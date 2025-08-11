package libkv

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type RESTPagination struct {
	Num       int
	HMac      *proto.HMAC
	TimeMicro proto.TimeMicro
	DirID     *proto.DirID
}

type RESTArgs struct {
	ActingAs *proto.FQTeamParsed
	Path     proto.KVPath
	Roles    proto.RolePairOpt
	Page     *RESTPagination
}

type RESTer interface {
	Put(m libclient.MetaContext, args RESTArgs, rdr io.Reader) error
	Get(m libclient.MetaContext, args RESTArgs, targ http.ResponseWriter) error
	Delete(m libclient.MetaContext, args RESTArgs) error
}

type MinderRESTWrapper struct {
	cfg lcl.KVConfig
	app *App
	au  *libclient.UserContext
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
		err := r.eng.Get(m, r.ra, r.w)
		if err != nil {
			return httpError{
				err:  err,
				code: http.StatusInternalServerError,
			}
		}
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

func (r *restReqV0) parsePagination(m libclient.MetaContext) error {
	var ret RESTPagination
	var isSet bool

	if num := r.req.URL.Query().Get("page_entries"); num != "" {
		n, err := strconv.Atoi(num)
		if err == nil {
			isSet = true
			ret.Num = n
		}
	}

	if hmac := r.req.URL.Query().Get("page_hmac"); len(hmac) > 10 {
		h, err := core.B62Decode(hmac)
		if err == nil {
			isSet = true
			var targ proto.HMAC
			if len(targ) == len(h) {
				copy(targ[:], h)
				ret.HMac = &targ
			}
		}
	}

	if timeMicro := r.req.URL.Query().Get("page_time_micro"); timeMicro != "" {
		tm, err := strconv.ParseInt(timeMicro, 10, 64)
		if err == nil {
			isSet = true
			ret.TimeMicro = proto.TimeMicro(tm)
		}
	}
	if dirID := r.req.URL.Query().Get("dir_id"); len(dirID) > 0 {
		var kvnid proto.KVNodeID
		if err := kvnid.ImportFromString(dirID); err == nil && kvnid.IsDir() {
			isSet = true
			dirId, _ := kvnid.ToDirID()
			ret.DirID = dirId
		}
	}

	if isSet {
		r.ra.Page = &ret
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

	err = r.parsePagination(m)
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
) (
	*lcl.KVRestListenInfo,
	error,
) {
	mux := http.NewServeMux()

	v0prefix := "/v0/"
	mBg := m.Background()
	mux.HandleFunc(v0prefix, func(w http.ResponseWriter, req *http.Request) {
		(&restReqV0{
			path: req.URL.Path[len(v0prefix):],
			srv:  r,
			w:    w,
			req:  req,
			arg:  arg,
			eng:  eng,
		}).handle(mBg)
	})

	ip := "127.0.0.1"
	if arg.BindIP != nil {
		ip = arg.BindIP.String()
	}
	port := 8080
	if arg.Port != nil {
		port = int(*arg.Port)
	}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	retPort := ln.Addr().(*net.TCPAddr).Port
	r.srv = server
	m.Infow("KV REST server", "stage", "starting", "addr", addr)
	go func() {
		_ = server.Serve(ln)
	}()
	return &lcl.KVRestListenInfo{
		Port: proto.Port(retPort),
	}, nil
}

func (a *App) StartRESTServer(
	mc MetaContext,
	arg lcl.ClientKVRestStartArg,
) (
	*lcl.KVRestListenInfo,
	error,
) {
	a.Lock()
	defer a.Unlock()

	if a.rest != nil {
		return nil, core.KVRestAlreadyRunningError{}
	}
	au := mc.G().ActiveUser()
	if au == nil {
		return nil, core.NoActiveUserError{}
	}
	srv := &RESTServer{}
	wrap := MinderRESTWrapper{cfg: arg.Cfg, app: a, au: au}
	ret, err := srv.Start(mc.MetaContext, arg, &wrap)
	if err != nil {
		return nil, err
	}
	a.rest = srv
	return ret, nil
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
	kvmc := NewMetaContext(mc).SetActiveUser(m.au)
	cfg := lcl.KVConfig{
		MkdirP:      true,
		OverwriteOk: true,
		ActingAs:    args.ActingAs,
		Roles:       args.Roles,
	}
	minder, err := m.app.Minder(kvmc, args.ActingAs)
	if err != nil {
		return err
	}

	return PutFile(rdr,
		func(data []byte, isFinal bool) (proto.KVNodeID, error) {
			prf, err := minder.PutFileFirst(kvmc, cfg, args.Path, data, isFinal)
			if err != nil {
				var zed proto.KVNodeID
				return zed, err
			}
			return prf.NodeID, nil
		},
		func(id proto.FileID, data []byte, offset proto.Offset, final bool) error {
			return minder.PutFileChunk(kvmc, cfg, id, data, offset, final)
		},
		0,
	)
}

type ListEntryJSON struct {
	Name  string    `json:"name"`
	Write string    `json:"write"`
	Mtime time.Time `json:"mtime"`
	Ctime time.Time `json:"ctime"`
}

type PaginationJSON struct {
	Hmac *string    `json:"hmac,omitempty"`
	Time *time.Time `json:"time,omitempty"`
}

type ListNextJSON struct {
	DirID      string         `json:"dir_id"`
	Pagination PaginationJSON `json:"pagination"`
}

type ListPageJSON struct {
	Entries []ListEntryJSON `json:"entries"`
	Next    *ListNextJSON   `json:"next,omitempty"`
	Parent  string          `json:"parent,omitempty"`
}

func MarshalListToJSON(targ http.ResponseWriter, list *lcl.CliKVListRes) error {

	var ents []ListEntryJSON
	for _, e := range list.Ents {
		wr, err := e.Write.ShortStringErr()
		if err != nil {
			return err
		}
		kvle := ListEntryJSON{
			Name:  e.Name.ToPath().String(),
			Write: wr,
			Mtime: e.Mtime.Import(),
		}
		ents = append(ents, kvle)
	}
	var nxt *ListNextJSON
	if list.Nxt != nil {
		nxt = &ListNextJSON{}
		did, err := list.Nxt.Id.KVNodeID().StringErr()
		if err != nil {
			return err
		}
		nxt.DirID = did
		typ, err := list.Nxt.Nxt.GetT()
		if err != nil {
			return err
		}
		switch typ {
		case proto.KVListPaginationType_MAC:
			mac := core.B62Encode(list.Nxt.Nxt.Mac().Bytes())
			nxt.Pagination.Hmac = &mac
		case proto.KVListPaginationType_Time:
			tm := list.Nxt.Nxt.Time()
			t := tm.Import()
			nxt.Pagination.Time = &t
		}
	}
	targ.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(targ)
	return enc.Encode(ListPageJSON{
		Entries: ents,
		Next:    nxt,
		Parent:  list.Parent.String(),
	})
}

func (m *MinderRESTWrapper) list(
	mc libclient.MetaContext,
	args RESTArgs,
	targ http.ResponseWriter,
) error {
	kvmc := NewMetaContext(mc).SetActiveUser(mc.G().ActiveUser())
	cfg := lcl.KVConfig{
		ActingAs: args.ActingAs,
		Roles:    args.Roles,
	}
	minder, err := m.app.Minder(kvmc, args.ActingAs)
	if err != nil {
		return err
	}

	opts := rem.KVListOpts{}
	var dirId *proto.DirID
	if args.Page != nil {
		if args.Page.Num > 0 {
			opts.Num = uint64(args.Page.Num)
		}
		if args.Page.HMac != nil {
			opts.Start = proto.NewKVListPaginationWithMac(*args.Page.HMac)
		} else if args.Page.TimeMicro > 0 {
			opts.Start = proto.NewKVListPaginationWithTime(args.Page.TimeMicro)
		}
		dirId = args.Page.DirID
	}
	tmp, err := minder.List(kvmc, cfg, args.Path, dirId, opts)
	if err != nil {
		return err
	}

	err = MarshalListToJSON(targ, tmp)
	if err != nil {
		return err
	}
	return nil
}

func (m *MinderRESTWrapper) Get(
	mc libclient.MetaContext,
	args RESTArgs,
	targ http.ResponseWriter,
) error {
	if strings.HasSuffix(args.Path.String(), "/") {
		return m.list(mc, args, targ)
	}

	kvmc := NewMetaContext(mc).SetActiveUser(m.au)
	cfg := lcl.KVConfig{
		ActingAs: args.ActingAs,
	}
	minder, err := m.app.Minder(kvmc, args.ActingAs)
	if err != nil {
		return err
	}
	return GetFile(
		targ,
		func() (lcl.GetFileRes, error) {
			tmp, err := minder.GetFile(kvmc, cfg, args.Path)
			if err != nil {
				var zed lcl.GetFileRes
				return zed, err
			}
			return *tmp, nil
		},
		func(id proto.FileID, offset proto.Offset) (lcl.GetFileChunkRes, error) {
			tmp, err := minder.GetFileChunk(kvmc, cfg, id, offset)
			if err != nil {
				var zed lcl.GetFileChunkRes
				return zed, err
			}
			return *tmp, nil
		},
	)
}

func (m *MinderRESTWrapper) Delete(
	mc libclient.MetaContext,
	args RESTArgs,
) error {
	kvmc := NewMetaContext(mc).SetActiveUser(m.au)
	cfg := lcl.KVConfig{
		ActingAs: args.ActingAs,
		Roles:    args.Roles,
	}
	minder, err := m.app.Minder(kvmc, args.ActingAs)
	if err != nil {
		return err
	}
	return minder.Unlink(kvmc, cfg, args.Path)
}
