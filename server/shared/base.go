// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/go-chi/chi/v5"
	"github.com/spf13/cobra"
)

type ClientConn interface {
	RegisterProtocols(m MetaContext, srv *rpc.Server) error
	UserHost() UserHostContext
	G() *GlobalContext
	SetHostID(h *core.HostID)
}

type BaseClientConn struct {
	userHost UserHostContext
	g        *GlobalContext
}

func NewBaseClientConn(g *GlobalContext, uhc UserHostContext) BaseClientConn {
	return BaseClientConn{
		userHost: uhc,
		g:        g,
	}
}

func NewBaseClientConnWithUID(u proto.UID) BaseClientConn {
	return BaseClientConn{
		userHost: UserHostContext{
			Uid: u,
		},
	}
}

func NewMetaContextConn(ctx context.Context, c ClientConn) MetaContext {
	return NewMetaContextWithUserHost(ctx, c.G(), c.UserHost())
}

func (b BaseClientConn) UserHost() UserHostContext {
	return b.userHost
}

func (b BaseClientConn) G() *GlobalContext {
	return b.g
}

func (b BaseClientConn) UID() proto.UID {
	return b.userHost.Uid
}

func (b *BaseClientConn) UIDp() *proto.UID {
	return &b.userHost.Uid
}

func (b *BaseClientConn) MakeResHeader() proto.Header {
	return core.MakeProtoHeader()
}

func (b *BaseClientConn) CheckArgHeader(ctx context.Context, h proto.Header) error {
	return core.CheckProtoArgHeader(ctx, h, b.g)
}

type BaseRPCServer struct {
	BaseServer
}

func (b *BaseRPCServer) ToWebServer() WebServer { return nil }

type BaseWebServer struct {
	BaseServer
}

func (b *BaseWebServer) ToRPCServer() RPCServer { return nil }

type BaseServer struct {
	sync.RWMutex
	Listener net.Listener
	IsTLS    bool
	g        *GlobalContext
}

func (b *BaseServer) TweakOpts(*GlobalCLIConfigOpts) {}

func (b *BaseClientConn) SetHostID(h *core.HostID) {
	b.userHost.HostID = h
}

func (b *BaseServer) SetGlobalContext(g *GlobalContext) {
	b.g = g
}

func (b *BaseServer) GetHostID() core.HostID {
	return b.g.HostID()
}

func (b *BaseServer) Port() int {
	return port(b.Listener)
}

func (b *BaseServer) ListenerAddr() net.Addr {
	return b.Listener.Addr()
}

func port(l net.Listener) int {
	return l.Addr().(*net.TCPAddr).Port
}

func (b *BaseServer) G() *GlobalContext {
	return b.g
}

func (b *BaseServer) Mctx(ctx context.Context) MetaContext {
	return NewMetaContext(ctx, b.g)
}

func (b *BaseServer) InitHostID(m MetaContext) error {
	return InitHostID(m)
}

func InitHostID(m MetaContext) error {
	hostID, err := m.G().ConfigureHostID(m.Ctx())

	// Useful for debugging, etc
	m.Infow("HostID", "host_id", hostID.Id.Hex())
	m.Infow("HostID", "short_id", hostID.Short)
	return err
}

func (b *BaseServer) Setup(m MetaContext) error    { return nil }
func (b *BaseServer) Shutdown(m MetaContext) error { return nil }
func (b *BaseServer) IsInternal() bool             { return false }

type CobraConfigger interface {
	CobraConfig() *cobra.Command
}

type BaseProcess interface {
	SetGlobalContext(g *GlobalContext)
	TweakOpts(*GlobalCLIConfigOpts)
}

type CLIApp interface {
	BaseProcess
	CobraConfigger
	Run(m MetaContext) error
	CheckArgs(args []string) error
}

type ServerCommand interface {
	CobraConfigger
	Server // Can be either an RPCServer or a WebServer
}

type Server interface {
	BaseProcess

	SetListening(l net.Listener, isTLS bool)
	ListenerAddr() net.Addr
	ServerType() proto.ServerType
	Setup(MetaContext) error
	GetHostID() core.HostID

	InitHostID(MetaContext) error
	RunBackgroundLoops(MetaContext, chan<- error) error
	Shutdown(MetaContext) error
	IsInternal() bool
	ToWebServer() WebServer
	ToRPCServer() RPCServer
}

type AuthType int

const (
	AuthTypeNone     AuthType = 0
	AuthTypeInternal AuthType = 1
	AuthTypeExternal AuthType = 2
)

type RPCServer interface {
	Server
	RequireAuth() AuthType
	CheckDeviceKey(m MetaContext, uhc UserHostContext, k proto.EntityID) (*proto.Role, error)
	NewClientConn(xp rpc.Transporter, uhc UserHostContext) ClientConn
}

type WebServer interface {
	Server
	InitRouter(m MetaContext, mux *chi.Mux) error
}

func (b *BaseServer) SetListening(l net.Listener, isTLS bool) {
	b.Listener = l
	b.IsTLS = isTLS
}

func (b *BaseServer) RunBackgroundLoops(MetaContext, chan<- error) error { return nil }

func setupSignalsAndServe(m MetaContext, rc *RootCommand, s Server) error {
	m, cancel := m.WithContextCancel()
	defer cancel()

	err := s.Setup(m)
	if err != nil {
		return err
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	eofCh := make(chan struct{})

	if rc.Opts.ReforkChild {
		go func() {
			// Wait for EOF (or any error that kills reads) on stdin. That will mean that
			// the parent process wants us to exit.
			_, _ = io.ReadAll(os.Stdin)
			close(eofCh)
		}()
	}

	go func() {
		select {
		case <-eofCh:
			m.Warnw("EOF received on stdin")
		case s := <-sigc:
			m.Warnw("signal received", "sig", s.String())
		}
		cancel()
	}()

	return ServeWithSignals(m, s, nil)
}

func ServeWithSignals(m MetaContext, s Server, launchCh chan<- error) error {
	rpcSrv := s.ToRPCServer()
	webSrv := s.ToWebServer()

	switch {
	case rpcSrv != nil:
		return RPCServeWithSignals(m, rpcSrv, launchCh)
	case webSrv != nil:
		return WebServeWithSignals(m, webSrv, launchCh)
	default:
		return core.InternalError("unhandled server type")
	}
}

// runRefork reforks the given server process if argv[0] is a symlink. It does so
// with the resolved path as argv[0]. The goal here is that we can use ps or top
// to see which git version of the process is actually running, since Linux doesn't
// seem to expose that in `ps` or `top` --- though it's available via the `/proc`
// filesystem.
func runRefork(m MetaContext, rc *RootCommand) (bool, error) {
	if !rc.Opts.Refork || rc.Opts.ReforkChild {
		return false, nil
	}

	var argv []string
	argv = append(argv, os.Args...)

	stat, err := os.Lstat(argv[0])
	if err != nil {
		return false, err
	}

	if stat.Mode()&os.ModeSymlink == 0 {
		return false, nil
	}

	real, err := os.Readlink(argv[0])
	if err != nil {
		return false, err
	}

	// Handle relative symlinks by resolving them relative to the directory of argv[0]
	if !filepath.IsAbs(real) {
		dir := filepath.Dir(argv[0])
		real = filepath.Join(dir, real)
	}

	// If no change, no need to refork
	if real == argv[0] {
		return false, nil
	}

	argv[0] = real
	var newArgs = []string{real, "--refork-child"}
	newArgs = append(newArgs, argv[1:]...)

	m.Infow("refork", "new_args", newArgs)

	cmd := exec.Cmd{
		Path:   newArgs[0],
		Args:   newArgs,
		Stdin:  os.Stdin,
		Stderr: os.Stderr,
	}

	r, w, err := os.Pipe()
	if err != nil {
		return true, err
	}

	// Stdin in the child process is a pipe. When we close it, it's time for the child
	// to exit.
	cmd.Stdin = r

	err = cmd.Start()
	if err != nil {
		return true, err
	}

	m.Infow("refork", "stage", "started", "pid", cmd.Process.Pid)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		sig := <-sigCh
		m.Infow("signal received in parent process", "signal", sig.String())
		w.Close()
	}()

	err = cmd.Wait()
	m.Infow("refork", "stage", "finished", "pid", cmd.Process.Pid, "err", err)

	if err != nil {
		return true, err
	}

	return true, nil
}

func runServer(
	m MetaContext,
	rc *RootCommand,
	s ServerCommand,
	args []string,
) error {

	done, err := runRefork(m, rc)
	if err != nil || done {
		return err
	}

	err = runShared(m, rc, s)
	if err != nil {
		return err
	}
	err = s.InitHostID(m)
	if err != nil {
		return err
	}
	return setupSignalsAndServe(m, rc, s)
}

func runCLIApp(
	m MetaContext,
	rc *RootCommand,
	c CLIApp,
	args []string,
) error {
	err := runShared(m, rc, c)
	if err != nil {
		return err
	}
	err = c.CheckArgs(args)
	if err != nil {
		return err
	}
	return c.Run(m)
}

type RootCommand struct {
	Cmd  *cobra.Command
	Opts GlobalCLIConfigOpts
}

func (r *RootCommand) AddGlobalOptions() {
	f := r.Cmd.PersistentFlags()
	f.VarP(&r.Opts.ConfigPath, "config-path", "", "path to config file")
	f.StringVarP(&r.Opts.LogLevel, "log-level", "", "", "log level to set logger at")
	f.BoolVarP(&r.Opts.ForceJSONLog, "force-json-log", "", false, "force JSON log even if on console")
	f.BoolVar(&r.Opts.Refork, "refork", false, "refork the server after resolving argv[0]")
	f.BoolVar(&r.Opts.ReforkChild, "refork-child", false, "a child of a reforked process")
	f.UintVarP(&r.Opts.ShortHostID, "short-host-id", "", 0, "short host ID to run as")
	f.StringSliceVarP(&r.Opts.DNSAliases, "dns-aliases", "", nil, "DNS alias to use for this host")
}

func runShared(m MetaContext, rc *RootCommand, s BaseProcess) error {

	s.SetGlobalContext(m.G())

	s.TweakOpts(&rc.Opts)

	err := m.Configure(rc.Opts)
	if err != nil {
		return err
	}

	m.Infow(
		"starting up",
		"pid", os.Getpid(),
	)
	return nil
}

func MainWrapper(mainFn func(m MetaContext) error) {
	mctx := NewMetaContextMain(nil)
	err := mainFn(mctx)
	rc := 0
	if err != nil {
		mctx.Error(err.Error())
		rc = -2
	}
	mctx.Shutdown()
	os.Exit(rc)
}

func runWithAllCommands[T CobraConfigger](
	m MetaContext,
	rc *RootCommand,
	lst []T,
	runner func(m MetaContext, rc *RootCommand, c T, args []string) error,
) error {
	for _, c := range lst {
		cmd := c
		cfg := cmd.CobraConfig()
		if cfg.Long == "" {
			cfg.Long = cfg.Short
		}
		cfg.RunE = func(c *cobra.Command, args []string) error {
			return runner(m, rc, cmd, args)
		}
		rc.Cmd.AddCommand(cfg)
	}
	return rc.Cmd.ExecuteContext(m.Ctx())
}

func MainWrapperWithServer(rc *RootCommand, cmds []ServerCommand) {
	MainWrapper(func(m MetaContext) error {
		return runWithAllCommands(m, rc, cmds, runServer)
	})
}

func MainWrapperWithCLICmd(rc *RootCommand, cmds []CLIApp) {
	MainWrapper(func(m MetaContext) error {
		return runWithAllCommands(m, rc, cmds, runCLIApp)
	})
}
