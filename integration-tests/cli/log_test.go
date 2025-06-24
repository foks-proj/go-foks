package cli

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/keybase/clockwork"
	"github.com/stretchr/testify/require"
)

func TestLogRotations(t *testing.T) {
	agent := newTestAgent(t)
	agent.runAgent(t)
	defer agent.stop(t)

	m := libclient.NewMetaContextBackground(agent.g)

	line := 1
	spew := func() {
		m.Infow("test log", "cmd", line)
		line++
	}
	cl := clockwork.NewFakeClock()
	orig := m.G().Clock()
	m.G().SetClock(cl)
	defer m.G().SetClock(orig)

	lr := m.G().LogRotate()

	// After setting the new clock, we need to poke the log rotate loop
	// to pick up the new clock.
	lr.Poke()

	for range 10 {
		spew()
	}

	countLines := func(b []byte) int {
		lines := 0
		for _, c := range b {
			if c == '\n' {
				lines++
			}
		}
		return lines
	}

	gunzip := func(p core.Path) []byte {
		file, err := p.ReadFile()
		require.NoError(t, err)
		var b bytes.Buffer
		_, err = b.Write(file)
		require.NoError(t, err)
		r, err := gzip.NewReader(&b)
		require.NoError(t, err)
		defer r.Close()
		data, err := io.ReadAll(r)
		require.NoError(t, err)
		return data
	}

	countRotatedLogs := func(expected int) {
		file, err := m.G().OutLogPath()
		require.NoError(t, err)
		logs, err := lr.FindRotatedLogs(m, file)
		require.NoError(t, err)
		require.Equal(t, expected, len(logs))
		for _, log := range logs {
			data := gunzip(log.Path)
			lines := countLines(data)
			require.Greater(t, lines, 1) // need at least two lines in each rotated log
		}
	}

	readLog := func(low int, high int) {
		_ = m.G().LogSync()
		file, err := m.G().OutLogPath()
		require.NoError(t, err)
		data, err := file.ReadFile()
		require.NoError(t, err)
		lines := countLines(data)
		require.GreaterOrEqual(t, lines, low)
		require.LessOrEqual(t, lines, high)
	}

	readLog(10, 20)
	countRotatedLogs(0)

	ch := make(chan struct{})
	lr.WaitForNextRotate(ch)

	cl.Advance(25 * time.Hour) // Advance the clock by 24 hours to trigger log rotation

	<-ch // Wait for the log rotation to complete
	for range 3 {
		spew()
	}

	// log rotation should add one line to the new log
	readLog(4, 6)
	countRotatedLogs(1)

}
