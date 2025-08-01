package libkv

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type RESTer interface {
	Put(m libclient.MetaContext, path proto.KVPath, rdr io.Reader) error
	Get(m libclient.MetaContext, path proto.KVPath) (io.ReadCloser, error)
	Delete(m libclient.MetaContext, path proto.KVPath) error
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

	mux.HandleFunc("/v0/", func(w http.ResponseWriter, req *http.Request) {

		if arg.AuthToken != nil {
			auth := req.Header.Get("Authorization")
			expected := "Basic " + arg.AuthToken.String()
			if auth != expected {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		path := proto.KVPath(req.URL.Path[len("/v0/"):])
		switch req.Method {
		case "GET":
			rc, err := eng.Get(m, path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer rc.Close()
			io.Copy(w, rc)
		case "PUT":
			err := eng.Put(m, path, req.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "DELETE":
			err := eng.Delete(m, path)
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

func (m *Minder) StartRESTServer(
	mc MetaContext,
	arg lcl.ClientKVRestStartArg,
) error {
	m.Lock()
	defer m.Unlock()

	if m.rest != nil {
		return core.KVRestAlreadyRunningError{}
	}
	srv := &RESTServer{}
	err := srv.Start(mc.MetaContext, arg, &MinderRESTWrapper{m: m, cfg: arg.Cfg})
	if err != nil {
		return err
	}
	m.rest = srv
	return nil
}

func (m *Minder) StopRESTServer(mc MetaContext) error {
	m.Lock()
	defer m.Unlock()

	if m.rest == nil {
		return core.KVRestNotRunningError{}
	}
	err := m.rest.srv.Close()
	if err != nil {
		return err
	}
	m.rest = nil
	return nil
}

func (m *MinderRESTWrapper) Put(
	mc libclient.MetaContext,
	path proto.KVPath,
	rdr io.Reader,
) error {
	kvmc := NewMetaContext(mc).SetActiveUser(m.m.au)
	return PutFile(rdr,
		func(data []byte, isFinal bool) (proto.KVNodeID, error) {
			cfg := m.cfg
			cfg.MkdirP = true
			cfg.OverwriteOk = true
			prf, err := m.m.PutFileFirst(kvmc, cfg, path, data, isFinal)
			if err != nil {
				var zed proto.KVNodeID
				return zed, err
			}
			return prf.NodeID, nil
		},
		func(id proto.FileID, data []byte, offset proto.Offset, final bool) error {
			return m.m.PutFileChunk(kvmc, m.cfg, id, data, offset, final)
		},
		0,
	)
}

func (m *MinderRESTWrapper) Get(
	mc libclient.MetaContext,
	path proto.KVPath,
) (io.ReadCloser, error) {
	return nil, core.NotImplementedError{}
}

func (m *MinderRESTWrapper) Delete(
	mc libclient.MetaContext,
	path proto.KVPath,
) error {
	return core.NotImplementedError{}
}
