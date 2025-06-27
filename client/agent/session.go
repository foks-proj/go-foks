// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"
	"sync"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type SessionBase struct {
	homeServer       *chains.Probe
	regCli           *core.RpcClient
	skm              *libclient.SecretKeyMaterialManager
	selfTok          proto.PermissionToken
	hepks            *core.HEPKSet
	defaultServer    *chains.Probe
	ssoCfg           *proto.SSOConfig
	regServerType    lcl.RegServerType // = BigTop, VHostMgmt or Custom
	hostType         proto.HostType    // = BigTop, Mgmt or Vhost
	yubiDevices      []proto.YubiCardID
	activeYubiDevice *proto.YubiCardInfo
	doPinProtect     bool
	currPIN          *proto.YubiPIN
	icr              proto.InviteCodeRegime
}

type Sessioner interface {
	Base() *SessionBase
	Init(id proto.UISessionID)
	Cleanup()
}

func (s *SessionBase) Base() *SessionBase { return s }

func (s *SessionBase) Cleanup() {
	if s.regCli != nil {
		s.regCli.Shutdown()
		s.regCli = nil
	}
}

func (s *SessionBase) Init() {
	s.hepks = core.NewHEPKSet()
}

type Sessions struct {
	sync.Mutex
	m          map[proto.UISessionID]Sessioner
	nxtSession proto.UISessionCtr
}

func NewSessions() *Sessions {
	return &Sessions{
		m:          make(map[proto.UISessionID]Sessioner),
		nxtSession: 1, // start counting at 1, so 0 is unitialized
	}
}

func (s *Sessions) Base(id proto.UISessionID) (*SessionBase, error) {
	i := s.Get(id)
	if i == nil {
		return nil, core.SessionNotFoundError(id)
	}
	return i.Base(), nil
}

func (s *Sessions) Get(id proto.UISessionID) Sessioner {
	s.Lock()
	defer s.Unlock()
	ret := s.m[id]
	if ret == nil {
		return nil
	}
	return ret
}

func GenericSession[
	T Sessioner,
](
	s *Sessions,
	id proto.UISessionID,
) (
	T,
	error,
) {
	var zed T
	i := s.Get(id)
	if i == nil {
		return zed, core.SessionNotFoundError(id)
	}
	ret, ok := i.(T)
	if !ok {
		return zed, core.InternalError("session was of wrong type")
	}
	return ret, nil
}

func withGenericSession[
	T Sessioner,
](
	c *AgentConn,
	sid proto.UISessionID,
	fn func(sess T) error,
) error {
	sess, err := GenericSession[T](c.agent.sessions, sid)
	if err != nil {
		return err
	}
	return fn(sess)
}

func (c *AgentConn) withBaseSession(
	sid proto.UISessionID,
	fn func(sess *SessionBase) error,
) error {
	sess := c.agent.sessions.Get(sid)
	if sess == nil {
		return core.SessionNotFoundError(sid)
	}
	base := sess.Base()
	if base == nil {
		return core.InternalError("session was of wrong type")
	}
	return fn(base)
}

func (s *Sessions) Signup(id proto.UISessionID) (*SignupSession, error) {
	i := s.Get(id)
	if i == nil {
		return nil, core.SessionNotFoundError(id)
	}
	ret, ok := i.(*SignupSession)
	if !ok {
		return nil, core.InternalError("session was of wrong type")
	}
	return ret, nil
}

func (s *Sessions) LoadBackup(id proto.UISessionID) (*LoadBackupSession, error) {
	i := s.Get(id)
	if i == nil {
		return nil, core.SessionNotFoundError(id)
	}
	ret, ok := i.(*LoadBackupSession)
	if !ok {
		return nil, core.InternalError("session was of wrong type")
	}
	return ret, nil
}

func (s *Sessions) Assist(id proto.UISessionID) (*AssistSession, error) {
	i := s.Get(id)
	if i == nil {
		return nil, core.SessionNotFoundError(id)
	}
	ret, ok := i.(*AssistSession)
	if !ok {
		return nil, core.InternalError("session was of wrong type")
	}
	return ret, nil
}

func (s *Sessions) SSOLogin(id proto.UISessionID) (*SSOLoginSession, error) {
	i := s.Get(id)
	if i == nil {
		return nil, core.SessionNotFoundError(id)
	}
	ret, ok := i.(*SSOLoginSession)
	if !ok {
		return nil, core.InternalError("session was of wrong type")
	}
	return ret, nil
}

func (s *Sessions) makeSession(typ proto.UISessionType) (Sessioner, proto.UISessionID) {
	s.Lock()
	defer s.Unlock()
	ctr := s.nxtSession
	s.nxtSession++
	id := proto.UISessionID{Type: typ, Ctr: ctr}
	var ret Sessioner

	switch typ {
	case proto.UISessionType_Signup,
		proto.UISessionType_Provision,
		proto.UISessionType_YubiProvision,
		proto.UISessionType_YubiNew,
		proto.UISessionType_NewKeyWizard:
		ret = new(SignupSession)
	case proto.UISessionType_LoadBackup:
		ret = new(LoadBackupSession)
	case proto.UISessionType_Assist:
		ret = new(AssistSession)
	case proto.UISessionType_Switch:
		ret = new(SwitchSession)
	case proto.UISessionType_SSOLogin:
		ret = new(SSOLoginSession)
	case proto.UISessionType_YubiSPP:
		ret = new(YSPPSession)
	default:
	}
	ret.Init(id)
	s.m[id] = ret
	return ret, id
}

func (s *Sessions) completeSession(i proto.UISessionID) Sessioner {
	s.Lock()
	defer s.Unlock()
	ret := s.m[i]
	if ret == nil {
		return nil
	}
	delete(s.m, i)
	return ret
}

func (s *SessionBase) RegGCli(m libclient.MetaContext) (*core.RpcClient, error) {
	if s.regCli != nil {
		return s.regCli, nil
	}
	ret, err := s.homeServer.RegGCli(m)
	if err != nil {
		return nil, err
	}
	s.regCli = ret
	return ret, nil
}

func (s *SessionBase) RegCli(m libclient.MetaContext) (*rem.RegClient, error) {
	gcli, err := s.RegGCli(m)
	if err != nil {
		return nil, err
	}
	ret := core.NewRegClient(gcli, m)
	return &ret, nil
}

func (c *AgentConn) NewSession(ctx context.Context, typ proto.UISessionType) (proto.UISessionID, error) {
	ret, id := c.agent.sessions.makeSession(typ)
	if ret == nil {
		return id, core.BadArgsError("invalid session type")
	}
	return id, nil
}

func (c *AgentConn) FinishSession(ctx context.Context, arg proto.UISessionID) error {
	sess := c.agent.sessions.completeSession(arg)
	if sess == nil {
		return core.SessionNotFoundError(arg)
	}
	sess.Cleanup()
	return nil
}
