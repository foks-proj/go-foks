package libkv

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type RESTArgs struct {
	ActingAs *proto.FQTeamParsed
	Path     proto.KVPath
	Roles    proto.RolePairOpt
}

type RESTer interface {
	Put(m libclient.MetaContext, args RESTArgs, rdr io.Reader) error
	Get(m libclient.MetaContext, args RESTArgs) (io.ReadCloser, error)
	Delete(m libclient.MetaContext, args RESTArgs) error
}

type MinderRESTWrapper struct {
	m   *Minder
	cfg lcl.KVConfig
}

type RESTServer struct {
	srv *http.Server
}

type httpError struct {
	code int
	msg  string
	err  error
}

func (e httpError) Error() string {
	return fmt.Sprintf("HTTP error %d: %s", e.code, e.msg)
}

type restReqV0 struct {
	path string
	srv  *RESTServer
	w    http.ResponseWriter
	req  *http.Request
	arg  lcl.ClientKVRestStartArg
	eng  RESTer
	ra   RESTArgs
}

func (r *restReqV0) auth(m libclient.MetaContext) error {
	if r.arg.AuthToken == nil {
		return nil
	}
	auth := r.req.Header.Get("Authorization")
	expected := "Basic " + r.arg.AuthToken.String()
	if auth != expected {
		return &httpError{
			code: http.StatusUnauthorized,
			msg:  "unauthorized",
		}
	}
	return nil
}

func (r *restReqV0) parsePath(m libclient.MetaContext) error {
	unversionedPath := r.path
	teamOrBlank, targetPath, found := strings.Cut(unversionedPath, "/")
	if !found {
		return httpError{
			code: http.StatusBadRequest,
			msg:  "invalid path; no target specified",
		}
	}
	var actingAs *proto.FQTeamParsed
	switch teamOrBlank {
	case "":
		return httpError{
			code: http.StatusBadRequest,
			msg:  "invalid path; no user or team specified",
		}
	case "-":
		// acting as the current user, noop
	default:
		// parse the team etc
		fqt, err := core.ParseFQTeam(proto.FQTeamString(teamOrBlank))
		if err != nil {
			return httpError{msg: "invalid team specified, failed to parse", code: http.StatusBadRequest}
		}
		actingAs = fqt
	}
	r.ra.ActingAs = actingAs
	r.ra.Path = proto.KVPath("/" + targetPath)

	parseRole := func(paramKey string) (*proto.Role, error) {
		raw := r.req.URL.Query().Get(paramKey)
		if len(raw) == 0 {
			return nil, nil // no role specified
		}
		p := proto.RoleString(raw)
		role, err := p.Parse()
		if err != nil {
			return nil, httpError{
				msg:  fmt.Sprintf("invalid role specified for %s", paramKey),
				code: http.StatusBadRequest,
			}
		}
		return role, nil
	}
	var err error
	r.ra.Roles.Read, err = parseRole("read")
	if err != nil {
		return err
	}
	r.ra.Roles.Write, err = parseRole("write")
	if err != nil {
		return err
	}

	return nil
}

func (r *restReqV0) dispatch(m libclient.MetaContext) error {

	switch r.req.Method {
	case "GET":
		rc, err := r.eng.Get(m, r.ra)
		if err != nil {
			return httpError{
				err:  err,
				code: http.StatusInternalServerError,
			}
		}
		defer rc.Close()
		io.Copy(r.w, rc)

	case "PUT":
		err := r.eng.Put(m, r.ra, r.req.Body)
		if err != nil {
			return httpError{
				err:  err,
				code: http.StatusInternalServerError,
			}
		}
		r.w.WriteHeader(http.StatusNoContent)
	case "DELETE":
		err := r.eng.Delete(m, r.ra)
		if err != nil {
			return httpError{
				err:  err,
				code: http.StatusInternalServerError,
			}
		}
		r.w.WriteHeader(http.StatusNoContent)
	default:
		return httpError{
			msg:  "method not allowed",
			code: http.StatusMethodNotAllowed,
		}
	}
	return nil
}

func (r *restReqV0) handleWithError(m libclient.MetaContext) error {
	err := r.auth(m)
	if err != nil {
		return err
	}

	err = r.parsePath(m)
	if err != nil {
		return err
	}

	err = r.dispatch(m)
	if err != nil {
		return err
	}

	return nil
}

func (r *restReqV0) handle(m libclient.MetaContext) {
	err := r.handleWithError(m)
	if err == nil {
		return
	}

	if httpErr, ok := err.(*httpError); ok {
		msg := httpErr.msg
		if httpErr.err != nil {
			msg = httpErr.err.Error()
		}
		if msg == "" {
			msg = "internal server error"
		}
		http.Error(r.w, msg, httpErr.code)
		return
	}

	m.Errorw("KV REST server error",
		"stage", "error",
		"error", err,
		"method", r.req.Method,
		"path", r.req.URL.Path,
	)
	http.Error(r.w, "internal server error", http.StatusInternalServerError)

}

func (r *RESTServer) Start(
	m libclient.MetaContext,
	arg lcl.ClientKVRestStartArg,
	eng RESTer,
) error {
	mux := http.NewServeMux()

	v0prefix := "/v0/"
	mux.HandleFunc(v0prefix, func(w http.ResponseWriter, req *http.Request) {
		(&restReqV0{
			path: req.URL.Path[len(v0prefix):],
			srv:  r,
			w:    w,
			req:  req,
			arg:  arg,
			eng:  eng,
		}).handle(m)
	})

	ip := "127.0.0.1"
	if arg.BindIP != nil {
		ip = arg.BindIP.String()
	}
	port := 8080
	if arg.Port != 0 {
		port = int(arg.Port)
	}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	r.srv = server
	m.Infow("KV REST server", "stage", "starting", "addr", addr)
	go server.Serve(ln)
	return nil
}

func (a *App) StartRESTServer(
	mc MetaContext,
	arg lcl.ClientKVRestStartArg,
) error {
	a.Lock()
	defer a.Unlock()

	if a.rest != nil {
		return core.KVRestAlreadyRunningError{}
	}
	srv := &RESTServer{}
	err := srv.Start(mc.MetaContext, arg, &MinderRESTWrapper{cfg: arg.Cfg})
	if err != nil {
		return err
	}
	a.rest = srv
	return nil
}

func (a *App) StopRESTServer(mc MetaContext) error {
	mc.Infow("KV REST server", "stage", "stopping")

	a.Lock()
	defer a.Unlock()

	if a.rest == nil {
		return core.KVRestNotRunningError{}
	}
	err := a.rest.srv.Close()
	if err != nil {
		mc.Errorw("KV REST server", "stage", "stopping", "err", err)
		return err
	}
	a.rest = nil
	return nil
}

func (m *MinderRESTWrapper) Put(
	mc libclient.MetaContext,
	args RESTArgs,
	rdr io.Reader,
) error {
	kvmc := NewMetaContext(mc).SetActiveUser(m.m.au)
	cfg := m.cfg
	cfg.MkdirP = true
	cfg.OverwriteOk = true
	cfg.ActingAs = args.ActingAs
	return PutFile(rdr,
		func(data []byte, isFinal bool) (proto.KVNodeID, error) {
			prf, err := m.m.PutFileFirst(kvmc, cfg, args.Path, data, isFinal)
			if err != nil {
				var zed proto.KVNodeID
				return zed, err
			}
			return prf.NodeID, nil
		},
		func(id proto.FileID, data []byte, offset proto.Offset, final bool) error {
			return m.m.PutFileChunk(kvmc, cfg, id, data, offset, final)
		},
		0,
	)
}

func (m *MinderRESTWrapper) Get(
	mc libclient.MetaContext,
	args RESTArgs,
) (io.ReadCloser, error) {
	return nil, core.NotImplementedError{}
}

func (m *MinderRESTWrapper) Delete(
	mc libclient.MetaContext,
	args RESTArgs,
) error {
	return core.NotImplementedError{}
}
