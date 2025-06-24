package libclient

import (
	"compress/gzip"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
)

type LogRotate struct {
	sync.Mutex

	// called on shutdown to stop the background loop
	stopper chan struct{}

	// these two channels are used in testing. pokeCh awakens the background loop
	// early so it can recheck the clock and then go back to sleep. And waiters wait
	// for the next log rotation to happen.
	pokeCh  chan<- struct{}
	waiters []chan struct{}
}

func NewLogRotate() *LogRotate {
	return &LogRotate{}
}

func (g *LogRotate) timeUntilLogRotate(m MetaContext) (time.Duration, error) {
	// We want to rotate logs at 3 AM every day.
	now := m.G().Now()
	dayInc := 1
	if now.Hour() < 3 {
		dayInc = 0
	}
	nextRotate := time.Date(now.Year(), now.Month(), now.Day()+dayInc, 3, 0, 0, 0, now.Location())

	diff := nextRotate.Sub(now)
	if diff < time.Minute {
		diff += 24 * time.Hour
	}
	return diff, nil
}

func (g *LogRotate) WaitForNextRotate(ch chan struct{}) {
	g.Lock()
	defer g.Unlock()
	if ch == nil {
		return
	}
	g.waiters = append(g.waiters, ch)
}

func (g *LogRotate) unlockWaiters(m MetaContext) {
	g.Lock()
	defer g.Unlock()
	v := g.waiters
	g.waiters = nil
	for _, ch := range v {
		close(ch)
	}
}

func (g *LogRotate) doLogRotate(m MetaContext) (err error) {

	defer func() {
		if err != nil {
			m.Errorw("logrotate", "stage", "doLogRotate", "err", err)
		}
	}()

	nm, err := m.G().OutLogPath()
	if err != nil {
		return err
	}
	err = g.rename(m, nm)
	if err != nil {
		return err
	}
	err = g.ageOut(m, nm)
	if err != nil {
		return err
	}

	g.unlockWaiters(m)

	return nil
}

func (g *LogRotate) gzipFile(m MetaContext, nm core.Path) (err error) {
	dst := nm.AddSuffix(".gz")
	m.Infow("logrotate", "stage", "gzipFile", "from", nm, "to", dst)

	in, err := nm.Open()
	if err != nil {
		return err
	}
	defer func() {
		if in == nil {
			return
		}
		if cerr := in.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	out, err := dst.Create()
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	gz := gzip.NewWriter(out)
	_, err = io.Copy(gz, in)
	if err != nil {
		return err
	}
	err = in.Close()
	if err != nil {
		return err
	}
	in = nil

	err = gz.Close()
	if err != nil {
		return err
	}
	gz = nil

	m.Infow("logrotate", "stage", "gzipFile done")
	if err := nm.Remove(); err != nil {
		return err
	}
	return nil
}

func (g *LogRotate) rename(m MetaContext, nm core.Path) error {
	now := m.G().Now()
	// format time in YYYYMMDDHHMMSS format
	timestamp := now.Format("20060102150405")

	rotated := core.Path(nm.String() + "." + timestamp)

	m.Infow("logrotate", "stage", "rename", "from", nm, "to", rotated)
	err := nm.Rename(rotated)
	if err != nil {
		return err
	}

	err = g.gzipFile(m, rotated)
	if err != nil {
		m.Errorw("logrotate", "stage", "gzipFile", "err", err)
	}

	err = m.G().ConfigureLogging(m.Ctx())
	if err != nil {
		return err
	}
	m.Infow("logrotate", "stage", "done", "file", nm)
	return nil
}

type RotatedLog struct {
	Path      core.Path
	Timestamp time.Time
}

func (g *LogRotate) FindRotatedLogs(m MetaContext, nm core.Path) ([]RotatedLog, error) {
	parent := nm.Dir()
	files, err := parent.ReadDir()
	if err != nil {
		return nil, err
	}
	rxx := regexp.MustCompile("^" + nm.Base().String() + `\.(\d{14})\.gz$`)
	var ret []RotatedLog
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		matches := rxx.FindStringSubmatch(file.Name())
		if matches == nil {
			continue
		}
		timestamp := matches[1]
		t, err := time.Parse("20060102150405", timestamp)
		if err != nil {
			m.Warnw("logrotate", "stage", "FindRotatedLogs", "err", err, "file", file.Name())
			continue
		}
		ret = append(ret, RotatedLog{
			Path:      parent.JoinStrings(file.Name()),
			Timestamp: t,
		})
	}
	return ret, nil
}

func (g *LogRotate) ageOut(m MetaContext, nm core.Path) error {

	logs, err := g.FindRotatedLogs(m, nm)
	if err != nil {
		return err
	}
	now := m.G().Now()
	for _, log := range logs {
		if now.Sub(log.Timestamp) < 7*24*time.Hour {
			m.Debugw("logrotate", "stage", "ageOut", "file", log.Path, "action", "keep")
			continue
		}
		m.Debugw("logrotate", "stage", "ageOut", "file", log.Path, "action", "delete")
		err := log.Path.Remove()
		if err != nil {
			m.Errorw("logrotate", "stage", "ageOut", "err", err, "file", log.Path)
		}
	}
	return nil
}

func (g *LogRotate) Run(m MetaContext) error {
	m = m.WithLogTag("logrotate")
	ch := make(chan struct{})
	pokeCh := make(chan struct{})
	g.stopper = ch
	g.pokeCh = pokeCh
	go func() {
		g.bgLoop(m, ch, pokeCh)
	}()
	return nil
}

func (g *LogRotate) Poke() {
	if g.pokeCh != nil {
		g.pokeCh <- struct{}{}
	}
}

func (g *LogRotate) Stop() {
	if g.stopper != nil {
		tmp := g.stopper
		g.stopper = nil
		close(tmp)
	}
}

func (g *LogRotate) bgLoop(m MetaContext, stopCh chan struct{}, pokeCh <-chan struct{}) {
	m = m.Background()
	m = m.WithLogTag("logrotate")

	for {
		wait, err := g.timeUntilLogRotate(m)
		if err != nil {
			m.Errorw("logrotate", "stage", "timeUntilLogRotate", "err", err)
		}
		select {
		case <-stopCh:
			m.Debugw("logrotate", "stage", "stop")
			return
		case <-pokeCh:
			m.Debugw("logrotate", "stage", "poke")
		case <-m.Ctx().Done():
			m.Warnw("logrotate", "stage", "ctxDone", "err", m.Ctx().Err())
			return
		case <-m.G().After(wait):
			m.Debugw("logrotate", "stage", "start")
			err := g.doLogRotate(m)
			if err != nil {
				m.Errorw("logrotate", "stage", "doLogRotate", "err", err)
			}
		}
	}
}
