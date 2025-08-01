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

func (r *RESTServer) Start(
	m libclient.MetaContext,
	arg lcl.ClientKVRestStartArg,
	eng RESTer,
) error {
	mux := http.NewServeMux()

	versionPrefix := "/v0/"

	mux.HandleFunc(versionPrefix, func(w http.ResponseWriter, req *http.Request) {

		if arg.AuthToken != nil {
			auth := req.Header.Get("Authorization")
			expected := "Basic " + arg.AuthToken.String()
			if auth != expected {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		unversionedPath := req.URL.Path[len(versionPrefix):]
		teamOrBlank, targetPath, found := strings.Cut(unversionedPath, "/")
		if !found {
			http.Error(w, "invalid path; no user or team specified", http.StatusBadRequest)
			return
		}

		var actingAs *proto.FQTeamParsed
		switch teamOrBlank {
		case "":
			http.Error(w, "invalid path; no user or team specified", http.StatusBadRequest)
			return
		case "-":
			// acting as the current user, noop
		default:
			// parse the team etc
			fqt, err := core.ParseFQTeam(proto.FQTeamString(teamOrBlank))
			if err != nil {
				http.Error(w, "invalid team specified, failed to parse", http.StatusBadRequest)
				return
			}
			actingAs = fqt
		}

		path := proto.KVPath("/" + targetPath)
		restArgs := RESTArgs{
			ActingAs: actingAs,
			Path:     path,
		}
		switch req.Method {
		case "GET":
			rc, err := eng.Get(m, restArgs)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rc.Close()
			io.Copy(w, rc)
		case "PUT":
			err := eng.Put(m, restArgs, req.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "DELETE":
			err := eng.Delete(m, restArgs)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
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
	a.Lock()
	defer a.Unlock()

	if a.rest == nil {
		return core.KVRestNotRunningError{}
	}
	err := a.rest.srv.Close()
	if err != nil {
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
