package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/briandowns/spinner"
	"github.com/compose-spec/compose-go/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/fatih/color"
	"github.com/foks-proj/go-foks/conf/srv"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
	"github.com/manifoldco/promptui"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"gopkg.in/yaml.v3"
)

const dbContainerNamePrefix = "foks-postgres"
const dbVolumeNamePrefix = "foks-postgres-data"
const hostConfDir = "conf-host"
const guestConfDir = "conf-guest"
const mountPrefix = "/foks/"
const mountedConfDir = mountPrefix + "conf"
const mountedKeysDir = mountPrefix + keysDir
const keysDir = "keys"
const dbImage = "postgres:17-alpine"
const envFile = ".env"
const statusFile = "standup.status.json"
const postgresDataDir = "/var/lib/postgresql/data"
const foksServer = "ghcr.io/foks-proj/foks-server:latest"
const foksTool = "ghcr.io/foks-proj/foks-tool:latest"
const postgresContainerName = "postgresql"
const defPostgresPort = 5432
const logfile = "standup.log"
const defLocalPostgresPort = 54321
const defHttpPort = 80

var promptTemplates = promptui.PromptTemplates{
	Prompt:  "- {{ . }} ",
	Valid:   "✔ {{ . | green }} ",
	Invalid: "- {{ . | red }} ",
	Success: "✔ {{ . | green }} ",
}

type StandupStatus struct {
	Sc    proto.StatusCode `json:"sc"`
	Stage StandupStage     `json:"stage"`
}

type StandupStage int

const (
	StandupStageNone             StandupStage = 0
	StandupStageWriteConfig      StandupStage = 1
	StandupStageCreateDBVolume   StandupStage = 2
	StandupStageCreateFoksUser   StandupStage = 3
	StandupStageInitDB           StandupStage = 4
	StandupStageGenCAs           StandupStage = 5
	StandupStageMakeHostChain    StandupStage = 6
	StandupStageMakeFrontendCert StandupStage = 7
	StandupStageMakeBackendCert  StandupStage = 8
	StandupStageIssueProbeCert   StandupStage = 9
	StandupStageInitMerkleTree   StandupStage = 10
	StandupStageWritePublicZone  StandupStage = 11
	StandupStageMakeInviteCode   StandupStage = 12
	StandupStageGenerateDBKeys   StandupStage = 13
	StandupStageWriteDockerYML   StandupStage = 14
	StandupStageSetViewership    StandupStage = 15
)

type StandupCmd struct {
	CLIAppBase
	hostname      string
	dbport        int
	httpLocalPort int
	force         bool
	interactive   bool
	viewershipStr string
	viewership    *proto.ViewershipMode
}

func (s *StandupCmd) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "standup",
		Short: "Standup a new stand-alone FOKS server",
		Long: `Standup a new stand-alone FOKS server from scratch. Will create and initialize 
databases, make keys, configurations etc. Subsequent restarts of the server can use simply
docker-compose up`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	ret.Flags().StringVarP(&s.hostname, "hostname", "H", "", "hostname of the FOKS server")
	ret.Flags().IntVar(&s.dbport, "db-port", defLocalPostgresPort, "port for the database")
	ret.Flags().BoolVarP(&s.force, "force", "f", false, "force overwrite even if files already exist")
	ret.Flags().IntVar(&s.httpLocalPort, "http-local-port", defHttpPort, "port to listen for HTTP requests on")
	ret.Flags().BoolVar(&s.interactive, "interactive", true, "run in interactive mode, prompting for user input")
	ret.Flags().StringVar(&s.viewershipStr, "viewership", "", "viewership mode for the server; one of: closed, open (default: open)")
	return ret
}

func parseViewershipMode(s string) (proto.ViewershipMode, error) {
	var tmp proto.ViewershipMode
	err := tmp.ImportFromDB(s)
	if err == nil && (tmp == proto.ViewershipMode_Open || tmp == proto.ViewershipMode_Closed) {
		return tmp, nil
	}
	var zed proto.ViewershipMode
	return zed, core.BadArgsError("invalid value for viewership; must be 'open' or 'closed'")
}

func (s *StandupCmd) setViewership() error {

	if s.viewershipStr == "" {
		s.viewershipStr = "open"
	}
	tmp, err := parseViewershipMode(s.viewershipStr)
	if err != nil {
		return err
	}
	s.viewership = &tmp
	return nil
}

func (s *StandupCmd) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if s.interactive {
		if s.dbport != defLocalPostgresPort ||
			s.httpLocalPort != defHttpPort ||
			s.hostname != "" ||
			s.viewershipStr != "" {
			return core.BadArgsError("in interactive mode, do not specify --db-port, --http-local-port, --viewership or --hostname; they will be prompted for")
		}
	} else {
		if s.hostname == "" {
			return core.BadArgsError("hostname is required")
		}
	}
	err := s.setViewership()
	if err != nil {
		return err
	}

	return nil
}

func (s *StandupCmd) getHostname(m shared.MetaContext) error {
	prompt := promptui.Prompt{
		Label: "🏠 Hostname:",
		Validate: func(input string) error {
			if input == "" {
				return errors.New("hostname cannot be empty")
			}
			// Basic hostname validation - alphanumeric, dots, and hyphens
			if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$`).MatchString(input) {
				return errors.New("hostname must be alphanumeric with optional dots and hyphens")
			}
			return nil
		},
		Templates: &promptTemplates,
	}
	res, err := prompt.Run()
	if err != nil {
		return err
	}
	s.hostname = res
	return nil
}

func (s *StandupCmd) getHttpLocalPort(m shared.MetaContext) error {
	prompt := promptui.Prompt{
		Label: fmt.Sprintf("🌐 HTTP Local Port (default: %d):", defHttpPort),
		Validate: func(input string) error {
			if input == "" {
				return nil
			}
			port, err := strconv.ParseInt(input, 10, 0)
			if err != nil {
				return errors.New("port must be an integer")
			}
			if port < 1 || port > 65535 {
				return errors.New("port must be between 1 and 65535")
			}
			return nil
		},
		Templates: &promptTemplates,
	}
	res, err := prompt.Run()
	if err != nil {
		return err
	}
	if res == "" {
		s.httpLocalPort = defHttpPort
		return nil
	}
	port, err := strconv.ParseInt(res, 10, 0)
	if err != nil {
		return err
	}
	s.httpLocalPort = int(port)
	return nil
}

func (s *StandupCmd) getDbPort(m shared.MetaContext) error {
	prompt := promptui.Prompt{
		Label: fmt.Sprintf("🗄️  Database Port (default: %d):", defLocalPostgresPort),
		Validate: func(input string) error {
			if input == "" {
				return nil
			}
			port, err := strconv.ParseInt(input, 10, 0)
			if err != nil {
				return errors.New("port must be an integer")
			}
			if port < 1 || port > 65535 {
				return errors.New("port must be between 1 and 65535")
			}
			return nil
		},
		Templates: &promptTemplates,
	}
	res, err := prompt.Run()
	if err != nil {
		return err
	}
	if res == "" {
		s.dbport = defLocalPostgresPort
		return nil
	}
	port, err := strconv.ParseInt(res, 10, 0)
	if err != nil {
		return err
	}
	s.dbport = int(port)
	return nil
}

func (s *StandupCmd) getViewshipMode(m shared.MetaContext) error {
	lbl := "👁️  Viewership Mode:"
	prompt := promptui.Select{
		Label: lbl,
		Items: []string{
			"open    (all users on this host can see each other; recommended)",
			"closed  (users must explicitly allow others to view them)",
		},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`✔ {{ "%s" | green }} {{ . | faint }}`, lbl),
		},
	}
	i, _, err := prompt.Run()
	if err != nil {
		return err
	}
	switch i {
	case 0:
		s.viewershipStr = "open"
		tmp := proto.ViewershipMode_Open
		s.viewership = &tmp
	case 1:
		s.viewershipStr = "closed"
		tmp := proto.ViewershipMode_Closed
		s.viewership = &tmp
	default:
		return core.BadArgsError("invalid viewership mode")
	}
	return nil
}

func (s *StandupCmd) runInteractive(m shared.MetaContext) error {
	err := s.getHostname(m)
	if err != nil {
		return err
	}
	err = s.getHttpLocalPort(m)
	if err != nil {
		return err
	}
	err = s.getDbPort(m)
	if err != nil {
		return err
	}
	err = s.getViewshipMode(m)
	if err != nil {
		return err
	}
	fmt.Printf("🔄 Starting standup with the following parameters:\n")
	fmt.Printf("  - 🏠 Hostname: %s\n", s.hostname)
	fmt.Printf("  - 🌐 HTTP Local Port: %d\n", s.httpLocalPort)
	fmt.Printf("  - 🗄️  Database Port: %d\n", s.dbport)
	fmt.Printf("  - 👁️  Viewership Mode: %s\n", s.viewership.String())
	return nil
}

func (s *StandupCmd) Run(m shared.MetaContext) error {
	_ = m.G().ShuntLogToFile(logfile)
	m.Infow("starting up", "pid", os.Getpid())

	if s.interactive {
		err := s.runInteractive(m)
		if err != nil {
			return err
		}
	}
	if s.viewership == nil {
		return core.InternalError("viewership mode is required")
	}

	eng := &StandupEng{
		hostname:      proto.Hostname(s.hostname),
		dbPort:        s.dbport,
		httpLocalPort: s.httpLocalPort,
		force:         s.force,
		viewership:    *s.viewership,
	}

	return eng.runAndCleanup(m)
}

func (s *StandupCmd) SetGlobalContext(g *shared.GlobalContext) {
}

type StandupEng struct {
	// params passed in
	hostname      proto.Hostname
	dbPort        int
	httpLocalPort int
	force         bool
	viewership    proto.ViewershipMode

	// generated secrets and keys
	iid        string // instance ID, generated at startup
	cksKey     proto.CKSEncKey
	dbpwRoot   string
	dbpw       string
	inviteCode string

	// internal state
	cwd             core.Path
	dockerCli       *client.Client
	dbVol           *volume.Volume
	dbContainerID   string
	dbRunning       bool
	status          *StandupStatus
	dbRoot          *pgx.Conn
	containerSuffix string // suffix for the database container name
}

func (c *StandupEng) checkpointedOperation(
	m shared.MetaContext,
	stage StandupStage,
	readOp func() (bool, error),
	writeOp func() error,
) error {
	if c.status != nil && c.status.Stage >= stage {
		done, err := readOp()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	err := writeOp()
	if err != nil {
		return err
	}
	err = c.writeStatus(m, StandupStatus{
		Sc:    proto.StatusCode_OK,
		Stage: stage,
	})
	if err != nil {
		return err
	}
	return nil
}

func (e *StandupEng) writeStatus(m shared.MetaContext, s StandupStatus) error {
	var buf []byte
	buf, err := json.Marshal(s)
	if err != nil {
		return err
	}
	err = e.writeConfig(
		m,
		statusFile,
		func(f *os.File) error {
			_, err := f.Write(buf)
			return err
		},
		writeConfigOpts{
			excl:      false,
			inConfDir: false,
		},
	)
	if err != nil {
		return err
	}
	e.status = &s
	return nil
}

func (e *StandupEng) readStatus(m shared.MetaContext) error {
	f, err := os.Open(statusFile)
	if err != nil && os.IsNotExist(err) {
		e.status = nil
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	var s StandupStatus
	dec := json.NewDecoder(f)
	err = dec.Decode(&s)
	if err != nil {
		return err
	}
	e.status = &s
	return nil
}

func (e *StandupEng) makeSecrets(m shared.MetaContext) error {
	err := core.RandomFill(e.cksKey[:])
	if err != nil {
		return err
	}
	e.dbpwRoot, err = core.RandomBase36String(13)
	if err != nil {
		return err
	}
	e.dbpw, err = core.RandomBase36String(13)
	if err != nil {
		return err
	}
	e.iid, err = core.RandomBase36String(6)
	if err != nil {
		return err
	}
	e.inviteCode, err = core.RandomBase36String(8)
	if err != nil {
		return err
	}
	return nil
}

func (e *StandupEng) makeDirs(m shared.MetaContext) error {
	dirs := []string{keysDir, hostConfDir, guestConfDir}
	for _, dir := range dirs {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *StandupEng) writeConfigs(m shared.MetaContext) error {

	return e.checkpointedOperation(
		m,
		StandupStageWriteConfig,
		func() (bool, error) {
			kvmap, err := e.readEnv(m)
			if err != nil {
				return false, err
			}
			if kvmap == nil {
				return false, nil
			}

			var rootpw, iid, userpw, hostname, inviteCode, httpPortStr string
			var foundSome bool
			var missedSome bool

			slots := []struct {
				slot *string
				key  string
			}{
				{&rootpw, "DB_PW_ROOT"},
				{&iid, "INSTANCE_ID"},
				{&userpw, "DB_PW"},
				{&hostname, "HOSTNAME"},
				{&inviteCode, "INVITE_CODE"},
				{&httpPortStr, "HTTP_LOCAL_PORT"},
			}
			var keys []string
			for _, slot := range slots {
				keys = append(keys, slot.key)
				if val, ok := kvmap[slot.key]; ok {
					*slot.slot = val
					foundSome = true
				} else {
					missedSome = true
				}
			}
			if !foundSome {
				return false, nil
			}
			if missedSome {
				return false, core.ConfigError("some fields missing in env file; need all of: " +
					strings.Join(keys, ", "))
			}

			if hostname != e.hostname.String() {
				return false, core.BadArgsError(
					"hostname in env file does not match command line hostname",
				)
			}
			port, err := strconv.ParseInt(httpPortStr, 10, 0)
			if err != nil {
				return false, core.BadArgsError(
					"HTTP_LOCAL_PORT in env file must be an integer",
				)
			}
			e.httpLocalPort = int(port)
			e.dbpwRoot = rootpw
			e.iid = iid
			e.dbpw = userpw
			e.inviteCode = inviteCode
			return true, nil
		},
		func() error {
			err := e.makeSecrets(m)
			if err != nil {
				return err
			}
			err = e.writeConfigPre(m, true)
			if err != nil {
				return err
			}
			err = e.writeConfigPre(m, false)
			if err != nil {
				return err
			}
			err = e.writeConfigMain(m, false)
			if err != nil {
				return err
			}
			err = e.writeConfigMain(m, true)
			if err != nil {
				return err
			}
			err = e.writeEnv(m)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

type writeConfigOpts struct {
	excl      bool
	inConfDir bool
	hostConf  bool
}

func (e *StandupEng) writeConfig(
	m shared.MetaContext,
	which string,
	doWrite func(*os.File) error,
	opts writeConfigOpts,
) (err error) {
	var targ core.Path

	var prfx core.Path

	if opts.inConfDir {
		if opts.hostConf {
			prfx = core.Path(hostConfDir)
		} else {
			prfx = core.Path(guestConfDir)
		}
	}
	base := core.Path(which)

	if !prfx.IsNil() {
		targ = prfx.Join(base)
	} else {
		targ = base
	}
	flags := os.O_CREATE | os.O_WRONLY
	if opts.excl {
		flags |= os.O_EXCL
	} else {
		flags |= os.O_TRUNC
	}
	f, err := targ.OpenFile(flags, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		tmp := f.Close()
		if tmp != nil && err == nil {
			err = tmp
		}
	}()
	err = doWrite(f)
	if err != nil {
		return err
	}
	return nil
}

func (e *StandupEng) writeConfigMain(m shared.MetaContext, inHost bool) (err error) {
	return e.writeConfig(
		m,
		"foks.jsonnet",
		func(f *os.File) error {
			_, err := f.WriteString(srv.FoksDockerComposeConfig)
			return err
		},
		writeConfigOpts{
			excl:      false,
			inConfDir: true,
			hostConf:  inHost,
		},
	)
}

func (e *StandupEng) writeConfigPre(m shared.MetaContext, isHost bool) (err error) {

	t, err := template.New("pre").Parse(`
local base(o) = o + {
    db +: {
        password : "{{.Dbpw}}",
		host : "{{.DbHostname}}",
		port : {{.DbPort}},
    },
	docker_compose : {{.DockerCompose}},
	external_addr : "{{.Hostname}}",
	top_dir : "{{.Topdir}}",
};
local final(o) = o + {
	cks : { enc_keys : ["{{.Key}}"] }
};
{ base : base, final : final }
	`)
	if err != nil {
		return err
	}

	data := struct {
		Dbpw          string
		DbPort        int
		DbHostname    proto.Hostname
		Hostname      proto.Hostname
		Key           string
		DockerCompose bool
		Topdir        string
	}{
		Dbpw:          e.dbpw,
		DbPort:        defPostgresPort,
		DbHostname:    postgresContainerName,
		Key:           e.cksKey.String(),
		DockerCompose: !isHost,
		Hostname:      e.hostname,
		Topdir:        mountPrefix,
	}

	if isHost {
		data.DbPort = e.dbPort
		data.DbHostname = "localhost"
		data.Topdir = "."
	}

	return e.writeConfig(
		m,
		"local.pre.libsonnet",
		func(f *os.File) error {
			return t.Execute(f, data)
		},
		writeConfigOpts{
			excl:      !e.force,
			inConfDir: true,
			hostConf:  isHost,
		},
	)
}

func (e *StandupEng) getcwd(m shared.MetaContext) error {
	pwd, err := os.Getwd()
	if err != nil {
		return err
	}
	path, err := filepath.Abs(pwd)
	if err != nil {
		return err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	e.cwd = core.Path(path)
	return nil
}

func (e *StandupEng) readEnv(m shared.MetaContext) (ret map[string]string, err error) {
	f, err := os.Open(envFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no env file, return empty map
		}
		return nil, err
	}
	defer func() {
		tmp := f.Close()
		if tmp != nil && err == nil {
			err = tmp
		}
	}()
	pairs := make(map[string]string)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue // skip empty lines and comments
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid env line: %s", line)
		}
		key := parts[0]
		value := parts[1]
		pairs[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading env file: %w", err)
	}
	ret = pairs
	return ret, nil
}

func writeKVPairs(f *os.File, pairs map[string]string) error {
	for key, value := range pairs {
		_, err := f.WriteString(
			key + "=" + value + "\n",
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *StandupEng) dbVolumeName() string {
	return dbVolumeNamePrefix + "-" + e.iid
}

func (e *StandupEng) dbContainerName() string {
	return dbContainerNamePrefix + "-" + e.iid + "-" + e.containerSuffix
}

func (e *StandupEng) writeEnv(m shared.MetaContext) error {

	pairs := map[string]string{
		"INSTANCE_ID":     e.iid,
		"HOSTNAME":        e.hostname.String(),
		"DB_PW_ROOT":      e.dbpwRoot,
		"DB_PW":           e.dbpw,
		"DB_IMAGE":        dbImage,
		"DB_VOLUME_NAME":  e.dbVolumeName(),
		"HTTP_LOCAL_PORT": fmt.Sprintf("%d", e.httpLocalPort),
		"INVITE_CODE":     e.inviteCode,
	}

	return e.writeConfig(
		m,
		envFile,
		func(f *os.File) error {
			// Write the environment variables to the file.
			_, err := f.WriteString("# FOKS server environment variables; Generated by foks-tool standup\n")
			if err != nil {
				return err
			}
			err = writeKVPairs(f, pairs)
			if err != nil {
				return err
			}
			return nil
		},
		writeConfigOpts{
			excl:      !e.force,
			inConfDir: false,
		},
	)
}

func (e *StandupEng) getDockerCli(m shared.MetaContext) (*client.Client, error) {
	if e.dockerCli != nil {
		return e.dockerCli, nil
	}
	cli, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}
	e.dockerCli = cli
	return cli, nil
}

var phaseCounter = 1

const totalPhases = 18

func (e *StandupEng) phase(which string, getErr func() error) func() {

	s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	lbl := fmt.Sprintf("[%2d/%d] %s", phaseCounter, totalPhases, which)
	phaseCounter++

	s.Suffix = "  " + lbl
	s.Start()

	return func() {
		s.Stop()
		if getErr() == nil {
			fmt.Printf("✅ %s ... ", lbl)
			color.Green("done\n")
		} else {
			fmt.Printf("❌ %s ... ", lbl)
			color.Red("failed")
		}
	}
}

func (e *StandupEng) setupFiles(m shared.MetaContext) (err error) {

	defer e.phase("setting up files", func() error { return err })()

	err = e.makeDirs(m)
	if err != nil {
		return err
	}
	err = e.getcwd(m)
	if err != nil {
		return err
	}
	err = e.writeConfigs(m)
	if err != nil {
		return err
	}
	return nil
}

func (e *StandupEng) databaseCreateVolume(m shared.MetaContext) error {
	cli, err := e.getDockerCli(m)
	if err != nil {
		return err
	}
	return e.checkpointedOperation(
		m,
		StandupStageCreateDBVolume,
		func() (bool, error) {
			vol, err := cli.VolumeInspect(m.Ctx(), e.dbVolumeName())
			if err != nil && client.IsErrNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			e.dbVol = &vol
			return true, nil
		},
		func() error {
			vol, err := cli.VolumeCreate(m.Ctx(), volume.CreateOptions{
				Name: e.dbVolumeName(),
			})
			if err != nil {
				return err
			}
			e.dbVol = &vol
			return nil
		},
	)
}

func (e *StandupEng) databaseCreateContainer(m shared.MetaContext) error {
	cli, err := e.getDockerCli(m)
	if err != nil {
		return err
	}

	e.containerSuffix, err = core.RandomBase36String(6)
	if err != nil {
		return err
	}

	dstPort := fmt.Sprintf("%d/tcp", defPostgresPort)
	dstPortNat := nat.Port(dstPort)

	resp, err := cli.ContainerCreate(m.Ctx(),
		&container.Config{
			Image: dbImage,
			Env: []string{
				fmt.Sprintf("POSTGRES_PASSWORD=%s", e.dbpwRoot),
			},
			ExposedPorts: nat.PortSet{
				dstPortNat: struct{}{},
			},
		},
		&container.HostConfig{
			PortBindings: nat.PortMap{
				dstPortNat: []nat.PortBinding{
					{HostIP: "0.0.0.0", HostPort: fmt.Sprintf("%d", e.dbPort)},
				},
			},
			Binds: []string{
				fmt.Sprintf("%s:%s", e.dbVol.Name, postgresDataDir),
			},
		},
		&network.NetworkingConfig{},
		&v1.Platform{},
		e.dbContainerName(),
	)
	if err != nil {
		return err
	}
	e.dbContainerID = resp.ID
	e.dbRunning = false
	return nil
}

func (e *StandupEng) databaseRunContainer(m shared.MetaContext) error {
	if e.dbRunning {
		return nil
	}
	cli, err := e.getDockerCli(m)
	if err != nil {
		return err
	}
	err = cli.ContainerStart(m.Ctx(), e.dbContainerID, container.StartOptions{})
	if err != nil {
		return err
	}
	e.dbRunning = true
	return nil
}

func (e *StandupEng) makeDatabase(m shared.MetaContext) (err error) {

	defer e.phase("setting up database", func() error { return err })()

	err = e.databaseImagePull(m)
	if err != nil {
		return err
	}
	err = e.databaseCreateVolume(m)
	if err != nil {
		return err
	}
	err = e.databaseCreateContainer(m)
	if err != nil {
		return err
	}
	err = e.databaseRunContainer(m)
	if err != nil {
		return err
	}
	return nil
}

func (e *StandupEng) getDBConnRoot(m shared.MetaContext) (*pgx.Conn, error) {
	if e.dbRoot != nil {
		return e.dbRoot, nil
	}
	conn, err := pgx.Connect(m.Ctx(), fmt.Sprintf(
		"postgres://postgres:%s@localhost:%d/postgres?sslmode=disable",
		e.dbpwRoot, e.dbPort,
	))
	if err != nil {
		return nil, err
	}
	e.dbRoot = conn
	return conn, nil
}

func (e *StandupEng) makeFoksUser(m shared.MetaContext) (err error) {

	defer e.phase("creating FOKS database user", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageCreateFoksUser,
		func() (bool, error) {
			conn, err := e.getDBConnRoot(m)
			if err != nil {
				return false, err
			}
			var exists bool
			err = conn.QueryRow(m.Ctx(), "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = 'foks')").Scan(&exists)
			if err != nil {
				return false, err
			}
			return exists, nil
		},
		func() error {
			conn, err := e.getDBConnRoot(m)
			if err != nil {
				return err
			}
			if strings.Contains(e.dbpw, "'") {
				return core.BadArgsError("database password cannot contain single quotes")
			}
			_, err = conn.Exec(
				m.Ctx(),
				"CREATE USER foks WITH CREATEDB PASSWORD '"+e.dbpw+"'",
			)
			if err != nil {
				return err
			}
			return nil
		},
	)

}

// ProgressMessage matches the essential fields sent by Docker during ImagePull.
// You could include more fields if you want, but ID and ProgressDetail are enough for a progress bar.
type ProgressMessage struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	ProgressDetail struct {
		Current int64 `json:"current"`
		Total   int64 `json:"total"`
	} `json:"progressDetail"`
}

const dbImageFull = "docker.io/library/" + dbImage

func (e *StandupEng) databaseImagePull(m shared.MetaContext) (err error) {

	cli, err := e.getDockerCli(m)
	if err != nil {
		return err
	}
	src := dbImageFull
	reader, err := cli.ImagePull(m.Ctx(), src, image.PullOptions{})
	if err != nil {
		return err
	}

	defer func() {
		tmp := reader.Close()
		if tmp != nil && err == nil {
			err = tmp
		}
	}()

	// 3) Create an mpb progress container with a reasonable width
	p := mpb.New(
		mpb.WithWidth(60),
		mpb.WithRefreshRate(180), // refresh every 180ms (≈5–6 FPS)
	)

	// 4) Keep a map of layer ID → *mpb.Bar so we only create one bar per layer
	bars := make(map[string]*mpb.Bar)

	// 5) Decode Docker's JSON stream
	dec := json.NewDecoder(reader)
	for {
		var msg ProgressMessage
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				break // done streaming
			}
			return err
		}

		// Docker sometimes emits messages without an "id" (e.g. "Pulling from …" or "Digest: …").
		// Skip those, since we only create bars for actual layers.
		if msg.ID == "" {
			continue
		}

		// If this layer has a non‐zero Total size, update (or create) its bar.
		total := msg.ProgressDetail.Total
		current := msg.ProgressDetail.Current
		if total == 0 {
			// If Total is zero, we don't know the size of this layer, so skip it.
			// This can happen for some layers that are already cached or have no size.
			continue
		}

		bar, exists := bars[msg.ID]
		if !exists {
			// First time seeing this layer ID: create a new bar with `total` as its width.
			// We prepend the layer ID (abbreviated) and show KiB counters + percentage.
			bar = p.AddBar(
				total,
				mpb.BarFillerClearOnComplete(), // clear on completion
				mpb.PrependDecorators(
					// Layer ID (first 12 chars) as the name
					decor.Name(fmt.Sprintf("%-12s", msg.ID[:12])),
					decor.CountersKibiByte("% .2f / % .2f"),
				),
				mpb.AppendDecorators(decor.Percentage()),
			)
			bars[msg.ID] = bar
		}
		// Compute how many bytes we need to increment:
		// Docker's ProgressDetail.Current is absolute, but bar.Current() is how many
		// we've already reported. So delta = newCurrent - oldCurrent.
		old := bar.Current()
		delta := int(current - old)
		if delta > 0 {
			bar.IncrBy(delta)
		}
	}

	// 6) Wait for all bars to complete
	p.Wait()

	return nil
}

func (e *StandupEng) findDockerSock(m shared.MetaContext) error {
	sock := os.Getenv("DOCKER_HOST")
	if sock != "" {
		m.Infow("Using DOCKER_HOST environment variable", "sock", sock)
		return nil
	}

	checkFile := func(path string) bool {
		_, err := os.Stat(path)
		return (err == nil)
	}

	def := "/var/run/docker.sock"
	if checkFile(def) {
		m.Infow("Using default Docker socket", "sock", def)
		return nil
	}

	if runtime.GOOS == "darwin" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		sock := filepath.Join(home, ".docker", "run", "docker.sock")
		if checkFile(sock) {
			m.Infow("Using Docker socket in home directory", "sock", sock)
			os.Setenv("DOCKER_HOST", "unix://"+sock)
			return nil
		}
	}
	return core.BadArgsError("could not find Docker socket; please set DOCKER_HOST environment variable")
}

func (e *StandupEng) pollDBRunning(m shared.MetaContext) (err error) {
	defer e.phase("waiting for database to start", func() error { return err })()

	for range 50 {
		var conn *pgx.Conn
		conn, err = e.getDBConnRoot(m)
		if err != nil {
			m.Infow("Waiting for database to start", "err", err)
		} else {
			err = conn.Ping(m.Ctx())
			if err == nil {
				e.dbRunning = true
				return nil // database is running
			}
		}
		m.Infow("Waiting for database to start", "err", err)
		time.Sleep(200 * time.Millisecond)
	}
	return core.DbError("Database did not start within the expected time frame; please check the logs for errors")
}

func (e *StandupEng) initDB(m shared.MetaContext) (err error) {
	defer e.phase("initializing databases", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageInitDB,
		func() (bool, error) { return true, nil },
		func() error {
			var err error
			var eng shared.InitDB
			eng.Dbs.Dbs = shared.AllDBs
			eng.Dbs.KVShards, err = shared.AllShards(m)
			if err != nil {
				return err
			}
			err = eng.CreateAll(m)
			if err != nil {
				return err
			}
			err = eng.RunMakeTablesAll(m)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func (e *StandupEng) config(m shared.MetaContext) (err error) {
	defer e.phase("configuring FOKS runtime", func() error { return err })()

	err = m.G().Configure(m.Ctx(), shared.GlobalCLIConfigOpts{
		ConfigPath: core.Path(hostConfDir).Join("foks.jsonnet"),
	})
	if err != nil {
		return err
	}
	// Redo this since logCfg replaced as a result of calling config
	_ = m.G().ShuntLogToFile(logfile)
	return nil
}

func (e *StandupEng) genCAs(m shared.MetaContext) (err error) {
	defer e.phase("generating CAs", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageGenCAs,
		func() (bool, error) { return true, nil },
		func() error {
			types := []proto.CKSAssetType{
				proto.CKSAssetType_InternalClientCA,
				proto.CKSAssetType_ExternalClientCA,
				proto.CKSAssetType_BackendCA,
			}
			for _, typ := range types {
				err := m.G().CertMgr().GenCA(m, typ)
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func (e *StandupEng) makeHostChain(m shared.MetaContext) (err error) {
	defer e.phase("making hostchain", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageMakeHostChain,
		func() (bool, error) {
			return true, nil
		},
		func() error {
			hc := shared.NewHostChain().
				WithHostname(proto.Hostname(e.hostname)).
				WithHostType(proto.HostType_Standalone)
			err := hc.Forge(m, core.Path(keysDir))
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func (e *StandupEng) makeFrontendCert(m shared.MetaContext) (err error) {
	defer e.phase("making frontend cert", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageMakeFrontendCert,
		func() (bool, error) { return true, nil },
		func() error {
			v := proto.CKSAssetType_HostchainFrontendX509Cert
			err := m.G().CertMgr().GenServerCert(m,
				[]proto.Hostname{e.hostname, "merkle_query", "probe"},
				nil,
				v.CAType(),
				v,
			)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func (e *StandupEng) makeBackendCert(m shared.MetaContext) (err error) {

	defer e.phase("making backend cert", func() error { return err })()

	tmp := []string{
		"localhost",
		"127.0.0.1",
		"::1",
	}

	for _, s := range proto.CoreServers {
		if !s.IsFrontFacing() {
			tmp = append(tmp, s.ToString())
		}
	}
	hostnames := append(
		core.Map(tmp, func(s string) proto.Hostname { return proto.Hostname(s) }),
		e.hostname,
	)

	return e.checkpointedOperation(
		m,
		StandupStageMakeBackendCert,
		func() (bool, error) { return true, nil },
		func() error {
			v := proto.CKSAssetType_BackendX509Cert
			err := m.G().CertMgr().GenServerCert(m,
				hostnames,
				nil,
				v.CAType(),
				v,
			)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func (e *StandupEng) issueProbeCert(m shared.MetaContext) (err error) {
	defer e.phase("requesting a TLS cert from LetsEncrypt", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageIssueProbeCert,
		func() (bool, error) { return true, nil },
		func() error {
			return doAutocert(m, proto.ServerType_Probe, proto.Port(e.httpLocalPort))
		},
	)
}

func (e *StandupEng) initMerkleTree(m shared.MetaContext) (err error) {
	defer e.phase("initializing Merkle tree", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageInitMerkleTree,
		func() (bool, error) { return true, nil },
		func() error {
			s := shared.NewSQLStorage(m)
			err := merkle.InitTree(m, s)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func (e *StandupEng) writePublicZone(m shared.MetaContext) (err error) {
	defer e.phase("writing public zone", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageWritePublicZone,
		func() (bool, error) { return true, nil },
		func() error {
			return doWritePublicZone(m, core.Path(keysDir).Join("metadata.host.key"))
		},
	)
}

func (e *StandupEng) makeInviteCode(m shared.MetaContext) (err error) {
	defer e.phase("making invite code", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageMakeInviteCode,
		func() (bool, error) { return true, nil },
		func() error {
			db, err := m.Db(shared.DbTypeUsers)
			if err != nil {
				return err
			}
			defer db.Release()
			_, err = db.Exec(
				m.Ctx(),
				`INSERT INTO multiuse_invite_codes(short_host_id, code, num_uses, valid)
				 VALUES($1, $2, 0, true) ON CONFLICT DO NOTHING`,
				m.ShortHostID(),
				e.inviteCode,
			)
			if err != nil {
				return err
			}
			return nil
		},
	)
}

func (e *StandupEng) generateDBKeys(m shared.MetaContext) (err error) {
	defer e.phase("generating database keys", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageGenerateDBKeys,
		func() (bool, error) { return true, nil },
		func() error { return shared.GenerateNewChallengeHMACKeys(m) },
	)
}

func (e *StandupEng) writeDockerComposeYMLinner(m shared.MetaContext) error {

	mkdur := func(t time.Duration) *types.Duration {
		d := types.Duration(t)
		return &d
	}
	mkuint64 := func(i uint64) *uint64 { return &i }
	mkstr := func(s string) *string { return &s }

	project := types.Project{
		Services: []types.ServiceConfig{
			{
				Name:    postgresContainerName,
				Image:   dbImageFull,
				Restart: "unless-stopped",
				Volumes: []types.ServiceVolumeConfig{
					{
						Source: e.dbVol.Name,
						Target: postgresDataDir,
						Type:   "volume",
					},
				},
				HealthCheck: &types.HealthCheckConfig{
					Test:        []string{"CMD-SHELL", "pg_isready -U postgres -d postgres"},
					StartPeriod: mkdur(time.Second * 20),
					Interval:    mkdur(time.Second * 1),
					Timeout:     mkdur(time.Second * 5),
					Retries:     mkuint64(10),
				},
				Environment: types.MappingWithEquals{
					"POSTGRES_PASSWORD": mkstr("${DB_PW_ROOT}"),
					"POSTGRES_USER":     mkstr("postgres"),
					"POSTGRES_DB":       mkstr("postgres"),
				},
				EnvFile: []string{envFile},
				Ports: []types.ServicePortConfig{
					{
						Target:    defPostgresPort,
						Published: fmt.Sprintf("%d", e.dbPort),
						Protocol:  "tcp",
						Mode:      "host",
					},
				},
			},
		},
		Volumes: types.Volumes{
			e.dbVol.Name: types.VolumeConfig{
				Name: e.dbVol.Name,
				External: types.External{
					External: true,
				},
			},
		},
	}
	configPath := mountedConfDir + "/foks.jsonnet"
	volumes := []types.ServiceVolumeConfig{
		{
			Source: guestConfDir,
			Target: mountedConfDir,
			Type:   "bind",
		}, {
			Source: keysDir,
			Target: mountedKeysDir,
			Type:   "bind",
		},
	}
	depends := types.DependsOnConfig{
		"postgresql": types.ServiceDependency{
			Condition: types.ServiceConditionHealthy,
		},
	}

	for _, svc := range proto.CoreServers {
		ba, _, _, err := m.G().Config().ListenParams(m.Ctx(), svc, 0)
		if err != nil {
			return err
		}
		port, err := ba.GetPort()
		if err != nil {
			return err
		}
		sc := types.ServiceConfig{
			Name:  svc.ToString(),
			Image: foksServer,
			Command: types.ShellCommand{
				svc.ToCommand(),
				"--config-path",
				configPath,
			},
			Volumes:   volumes,
			DependsOn: depends,
			Restart:   types.RestartPolicyUnlessStopped,
		}
		if svc.IsFrontFacing() {
			sc.Ports = []types.ServicePortConfig{
				{
					Target:    uint32(port),
					Published: fmt.Sprintf("%d", port),
					Protocol:  "tcp",
					Mode:      "host",
					HostIP:    "0.0.0.0",
				},
			}

		}
		project.Services = append(project.Services, sc)
	}

	project.Services = append(project.Services, types.ServiceConfig{
		Name:  "beacon_register",
		Image: foksTool,
		Command: types.ShellCommand{
			"beacon-register",
			"--config-path",
			configPath,
			"--delay", "5s",
			"--tries", "30",
			"--wait", "15s",
			"--hostname", e.hostname.String(),
		},
		Volumes:   volumes,
		Restart:   types.RestartPolicyOnFailure,
		DependsOn: depends,
	})

	out, err := yaml.Marshal(project)
	if err != nil {
		return err
	}
	err = e.writeConfig(
		m,
		"docker-compose.yml",
		func(f *os.File) error {
			_, err := f.Write(out)
			return err
		},
		writeConfigOpts{
			excl:      false,
			inConfDir: false,
		},
	)
	if err != nil {
		return err
	}
	return nil
}

func (e *StandupEng) writeDockerCompileYML(m shared.MetaContext) (err error) {

	defer e.phase("cooking up docker-compose.yml", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageWriteDockerYML,
		func() (bool, error) { return false, nil },
		func() error {
			return e.writeDockerComposeYMLinner(m)
		},
	)
}

func (e *StandupEng) teardownDockerDB(m shared.MetaContext) error {
	err := e.stopDockerDB(m)
	if err != nil {
		return err
	}
	err = e.removeDockerDB(m)
	if err != nil {
		return err
	}
	return nil
}

func (e *StandupEng) removeDockerDB(m shared.MetaContext) error {
	cli, err := e.getDockerCli(m)
	if err != nil {
		return err
	}

	if e.dbContainerID == "" {
		return nil // nothing to do
	}

	err = cli.ContainerRemove(m.Ctx(), e.dbContainerID, container.RemoveOptions{
		Force: true,
	})
	if err != nil {
		return err
	}
	e.dbContainerID = ""
	return nil
}

func (e *StandupEng) stopDockerDB(m shared.MetaContext) error {
	if !e.dbRunning {
		return nil
	}
	cli, err := e.getDockerCli(m)
	if err != nil {
		return err
	}

	err = cli.ContainerStop(m.Ctx(), e.dbContainerID, container.StopOptions{})
	if err != nil {
		return err
	}
	statusCh, errCh := cli.ContainerWait(m.Ctx(), e.dbContainerID, container.WaitConditionNotRunning)
	select {
	case <-statusCh:
	case err := <-errCh:
		return err
	case <-time.After(10 * time.Second):
		return core.TimeoutError{}
	}
	e.dbRunning = false
	return nil
}

func (e *StandupEng) errorOutput(format string, args ...interface{}) {
	color.Red(format, args...)
}

func (e *StandupEng) runAndCleanup(m shared.MetaContext) (err error) {

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	m, cancel := m.WithContextCancel()

	go func() {
		s := <-sigc
		m.Warnw("signal received", "sig", s.String())
		cancel()
	}()

	defer func() {
		// Our context might be canceled by now, so don't use it for cleanup.
		m = m.Background()
		cleanupErr := e.teardownDockerDB(m)
		if cleanupErr != nil {
			m.Infow("Error during cleanup", "cleanup_err", cleanupErr)
		}
		cancel()
	}()

	err = e.run(m)
	if err != nil {
		e.errorOutput("️❗ %s\n", err.Error())
		e.errorOutput("❗ Standup failed; see log file for more details: %s\n", logfile)
		return err
	}
	return nil
}

func (e *StandupEng) setViewership(m shared.MetaContext) (err error) {
	defer e.phase("setting host viewership", func() error { return err })()

	return e.checkpointedOperation(
		m,
		StandupStageSetViewership,
		func() (bool, error) { return true, nil },
		func() error { return shared.SetViewership(m, e.viewership, nil) },
	)
}

func (e *StandupEng) testHttp(m shared.MetaContext) (err error) {
	defer e.phase("testing HTTP connectivity", func() error { return err })()

	// Generate random test token
	token, err := core.RandomBase36String(16)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("0.0.0.0:%d", e.httpLocalPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	// Create test server
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/test" && r.Header.Get("X-Test-Token") == token {
				_, _ = w.Write([]byte("ok"))
			} else {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("not found"))
			}
		}),
	}

	// Start server in background
	go func() {
		err := server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			m.Errorw("test server error", "err", err)
		}
		listener.Close()
	}()

	// Make test request
	url := fmt.Sprintf("http://%s:%d/test", e.hostname, e.httpLocalPort)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}
	req.Header.Set("X-Test-Token", token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("test request failed with status %d", resp.StatusCode)
	}

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)

	return nil
}

func (e *StandupEng) run(m shared.MetaContext) (err error) {
	err = e.readStatus(m)
	if err != nil {
		return err
	}
	err = e.testHttp(m)
	if err != nil {
		return err
	}
	err = e.setupFiles(m)
	if err != nil {
		return err
	}
	err = e.findDockerSock(m)
	if err != nil {
		return err
	}
	err = e.makeDatabase(m)
	if err != nil {
		return err
	}
	err = e.pollDBRunning(m)
	if err != nil {
		return err
	}
	err = e.makeFoksUser(m)
	if err != nil {
		return err
	}
	err = e.config(m)
	if err != nil {
		return err
	}
	err = e.initDB(m)
	if err != nil {
		return err
	}
	err = e.genCAs(m)
	if err != nil {
		return err
	}
	err = e.makeHostChain(m)
	if err != nil {
		return err
	}
	err = shared.InitHostID(m)
	if err != nil {
		return err
	}
	err = e.makeFrontendCert(m)
	if err != nil {
		return err
	}
	err = e.makeBackendCert(m)
	if err != nil {
		return err
	}
	err = e.issueProbeCert(m)
	if err != nil {
		return err
	}
	err = e.initMerkleTree(m)
	if err != nil {
		return err
	}
	err = e.writePublicZone(m)
	if err != nil {
		return err
	}
	err = e.makeInviteCode(m)
	if err != nil {
		return err
	}
	err = e.generateDBKeys(m)
	if err != nil {
		return err
	}
	err = e.setViewership(m)
	if err != nil {
		return err
	}
	err = e.writeDockerCompileYML(m)
	if err != nil {
		return err
	}
	m.Infow("setup successful")
	fmt.Printf("✉️  Invite code: %s\n", e.inviteCode)
	fmt.Printf("🫡 Success! Run `docker-compose up` to start your FOKS server\n")
	return nil
}

func (b *StandupCmd) TweakOpts(opts *shared.GlobalCLIConfigOpts) {
	opts.SkipConfig = true
	opts.SkipNetwork = true
	opts.NoStartupMsg = true
}

var _ shared.CLIApp = (*StandupCmd)(nil)

func init() {
	AddCmd(&StandupCmd{})
}
