// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/user.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type LocalUserIndexParsed struct {
	Fqu      lib.FQUserParsed
	Role     lib.Role
	KeyGenus *lib.KeyGenus
	KeyID    lib.EntityID
}
type LocalUserIndexParsedInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu      *lib.FQUserParsedInternal__
	Role     *lib.RoleInternal__
	KeyGenus *lib.KeyGenusInternal__
	KeyID    *lib.EntityIDInternal__
}

func (l LocalUserIndexParsedInternal__) Import() LocalUserIndexParsed {
	return LocalUserIndexParsed{
		Fqu: (func(x *lib.FQUserParsedInternal__) (ret lib.FQUserParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Fqu),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Role),
		KeyGenus: (func(x *lib.KeyGenusInternal__) *lib.KeyGenus {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.KeyGenusInternal__) (ret lib.KeyGenus) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.KeyGenus),
		KeyID: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.KeyID),
	}
}
func (l LocalUserIndexParsed) Export() *LocalUserIndexParsedInternal__ {
	return &LocalUserIndexParsedInternal__{
		Fqu:  l.Fqu.Export(),
		Role: l.Role.Export(),
		KeyGenus: (func(x *lib.KeyGenus) *lib.KeyGenusInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(l.KeyGenus),
		KeyID: l.KeyID.Export(),
	}
}
func (l *LocalUserIndexParsed) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LocalUserIndexParsed) Decode(dec rpc.Decoder) error {
	var tmp LocalUserIndexParsedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LocalUserIndexParsed) Bytes() []byte { return nil }

type AgentStatus struct {
	Pid    int64
	Socket string
	Users  []lib.UserContext
}
type AgentStatusInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Pid     *int64
	Socket  *string
	Users   *[](*lib.UserContextInternal__)
}

func (a AgentStatusInternal__) Import() AgentStatus {
	return AgentStatus{
		Pid: (func(x *int64) (ret int64) {
			if x == nil {
				return ret
			}
			return *x
		})(a.Pid),
		Socket: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(a.Socket),
		Users: (func(x *[](*lib.UserContextInternal__)) (ret []lib.UserContext) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.UserContext, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.UserContextInternal__) (ret lib.UserContext) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(a.Users),
	}
}
func (a AgentStatus) Export() *AgentStatusInternal__ {
	return &AgentStatusInternal__{
		Pid:    &a.Pid,
		Socket: &a.Socket,
		Users: (func(x []lib.UserContext) *[](*lib.UserContextInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.UserContextInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(a.Users),
	}
}
func (a *AgentStatus) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AgentStatus) Decode(dec rpc.Decoder) error {
	var tmp AgentStatusInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AgentStatus) Bytes() []byte { return nil }

type ActiveUserCheckLockedRes struct {
	User       lib.UserContext
	LockStatus lib.Status
}
type ActiveUserCheckLockedResInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	User       *lib.UserContextInternal__
	LockStatus *lib.StatusInternal__
}

func (a ActiveUserCheckLockedResInternal__) Import() ActiveUserCheckLockedRes {
	return ActiveUserCheckLockedRes{
		User: (func(x *lib.UserContextInternal__) (ret lib.UserContext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.User),
		LockStatus: (func(x *lib.StatusInternal__) (ret lib.Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.LockStatus),
	}
}
func (a ActiveUserCheckLockedRes) Export() *ActiveUserCheckLockedResInternal__ {
	return &ActiveUserCheckLockedResInternal__{
		User:       a.User.Export(),
		LockStatus: a.LockStatus.Export(),
	}
}
func (a *ActiveUserCheckLockedRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *ActiveUserCheckLockedRes) Decode(dec rpc.Decoder) error {
	var tmp ActiveUserCheckLockedResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *ActiveUserCheckLockedRes) Bytes() []byte { return nil }

var UserProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xcc5e1b3e)

type ClearArg struct {
}
type ClearArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (c ClearArgInternal__) Import() ClearArg {
	return ClearArg{}
}
func (c ClearArg) Export() *ClearArgInternal__ {
	return &ClearArgInternal__{}
}
func (c *ClearArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClearArg) Decode(dec rpc.Decoder) error {
	var tmp ClearArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClearArg) Bytes() []byte { return nil }

type AgentStatusArg struct {
}
type AgentStatusArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (a AgentStatusArgInternal__) Import() AgentStatusArg {
	return AgentStatusArg{}
}
func (a AgentStatusArg) Export() *AgentStatusArgInternal__ {
	return &AgentStatusArgInternal__{}
}
func (a *AgentStatusArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AgentStatusArg) Decode(dec rpc.Decoder) error {
	var tmp AgentStatusArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AgentStatusArg) Bytes() []byte { return nil }

type ActiveUserArg struct {
}
type ActiveUserArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (a ActiveUserArgInternal__) Import() ActiveUserArg {
	return ActiveUserArg{}
}
func (a ActiveUserArg) Export() *ActiveUserArgInternal__ {
	return &ActiveUserArgInternal__{}
}
func (a *ActiveUserArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *ActiveUserArg) Decode(dec rpc.Decoder) error {
	var tmp ActiveUserArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *ActiveUserArg) Bytes() []byte { return nil }

type SwitchUserArg struct {
	Fqu LocalUserIndexParsed
}
type SwitchUserArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu     *LocalUserIndexParsedInternal__
}

func (s SwitchUserArgInternal__) Import() SwitchUserArg {
	return SwitchUserArg{
		Fqu: (func(x *LocalUserIndexParsedInternal__) (ret LocalUserIndexParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Fqu),
	}
}
func (s SwitchUserArg) Export() *SwitchUserArgInternal__ {
	return &SwitchUserArgInternal__{
		Fqu: s.Fqu.Export(),
	}
}
func (s *SwitchUserArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SwitchUserArg) Decode(dec rpc.Decoder) error {
	var tmp SwitchUserArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SwitchUserArg) Bytes() []byte { return nil }

type SwitchUserByInfoArg struct {
	I lib.UserInfo
}
type SwitchUserByInfoArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	I       *lib.UserInfoInternal__
}

func (s SwitchUserByInfoArgInternal__) Import() SwitchUserByInfoArg {
	return SwitchUserByInfoArg{
		I: (func(x *lib.UserInfoInternal__) (ret lib.UserInfo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.I),
	}
}
func (s SwitchUserByInfoArg) Export() *SwitchUserByInfoArgInternal__ {
	return &SwitchUserByInfoArgInternal__{
		I: s.I.Export(),
	}
}
func (s *SwitchUserByInfoArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SwitchUserByInfoArg) Decode(dec rpc.Decoder) error {
	var tmp SwitchUserByInfoArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SwitchUserByInfoArg) Bytes() []byte { return nil }

type GetExistingUsersArg struct {
}
type GetExistingUsersArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetExistingUsersArgInternal__) Import() GetExistingUsersArg {
	return GetExistingUsersArg{}
}
func (g GetExistingUsersArg) Export() *GetExistingUsersArgInternal__ {
	return &GetExistingUsersArgInternal__{}
}
func (g *GetExistingUsersArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetExistingUsersArg) Decode(dec rpc.Decoder) error {
	var tmp GetExistingUsersArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetExistingUsersArg) Bytes() []byte { return nil }

type ActiveUserCheckLockedArg struct {
}
type ActiveUserCheckLockedArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (a ActiveUserCheckLockedArgInternal__) Import() ActiveUserCheckLockedArg {
	return ActiveUserCheckLockedArg{}
}
func (a ActiveUserCheckLockedArg) Export() *ActiveUserCheckLockedArgInternal__ {
	return &ActiveUserCheckLockedArgInternal__{}
}
func (a *ActiveUserCheckLockedArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *ActiveUserCheckLockedArg) Decode(dec rpc.Decoder) error {
	var tmp ActiveUserCheckLockedArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *ActiveUserCheckLockedArg) Bytes() []byte { return nil }

type LoadMeArg struct {
}
type LoadMeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (l LoadMeArgInternal__) Import() LoadMeArg {
	return LoadMeArg{}
}
func (l LoadMeArg) Export() *LoadMeArgInternal__ {
	return &LoadMeArgInternal__{}
}
func (l *LoadMeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadMeArg) Decode(dec rpc.Decoder) error {
	var tmp LoadMeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadMeArg) Bytes() []byte { return nil }

type SkmInfoArg struct {
}
type SkmInfoArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (s SkmInfoArgInternal__) Import() SkmInfoArg {
	return SkmInfoArg{}
}
func (s SkmInfoArg) Export() *SkmInfoArgInternal__ {
	return &SkmInfoArgInternal__{}
}
func (s *SkmInfoArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SkmInfoArg) Decode(dec rpc.Decoder) error {
	var tmp SkmInfoArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SkmInfoArg) Bytes() []byte { return nil }

type SetSkmEncryptionArg struct {
	Mode lib.SecretKeyStorageType
}
type SetSkmEncryptionArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Mode    *lib.SecretKeyStorageTypeInternal__
}

func (s SetSkmEncryptionArgInternal__) Import() SetSkmEncryptionArg {
	return SetSkmEncryptionArg{
		Mode: (func(x *lib.SecretKeyStorageTypeInternal__) (ret lib.SecretKeyStorageType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Mode),
	}
}
func (s SetSkmEncryptionArg) Export() *SetSkmEncryptionArgInternal__ {
	return &SetSkmEncryptionArgInternal__{
		Mode: s.Mode.Export(),
	}
}
func (s *SetSkmEncryptionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetSkmEncryptionArg) Decode(dec rpc.Decoder) error {
	var tmp SetSkmEncryptionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetSkmEncryptionArg) Bytes() []byte { return nil }

type UserLockArg struct {
}
type UserLockArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (u UserLockArgInternal__) Import() UserLockArg {
	return UserLockArg{}
}
func (u UserLockArg) Export() *UserLockArgInternal__ {
	return &UserLockArgInternal__{}
}
func (u *UserLockArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserLockArg) Decode(dec rpc.Decoder) error {
	var tmp UserLockArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserLockArg) Bytes() []byte { return nil }

type ClientUserPingArg struct {
}
type ClientUserPingArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (c ClientUserPingArgInternal__) Import() ClientUserPingArg {
	return ClientUserPingArg{}
}
func (c ClientUserPingArg) Export() *ClientUserPingArgInternal__ {
	return &ClientUserPingArgInternal__{}
}
func (c *ClientUserPingArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientUserPingArg) Decode(dec rpc.Decoder) error {
	var tmp ClientUserPingArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientUserPingArg) Bytes() []byte { return nil }

type LoginStartSsoLoginFlowArg struct {
	SessionId lib.UISessionID
}
type LoginStartSsoLoginFlowArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (l LoginStartSsoLoginFlowArgInternal__) Import() LoginStartSsoLoginFlowArg {
	return LoginStartSsoLoginFlowArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SessionId),
	}
}
func (l LoginStartSsoLoginFlowArg) Export() *LoginStartSsoLoginFlowArgInternal__ {
	return &LoginStartSsoLoginFlowArgInternal__{
		SessionId: l.SessionId.Export(),
	}
}
func (l *LoginStartSsoLoginFlowArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoginStartSsoLoginFlowArg) Decode(dec rpc.Decoder) error {
	var tmp LoginStartSsoLoginFlowArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoginStartSsoLoginFlowArg) Bytes() []byte { return nil }

type LoginWaitForSsoLoginArg struct {
	SessionId lib.UISessionID
}
type LoginWaitForSsoLoginArgInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SessionId *lib.UISessionIDInternal__
}

func (l LoginWaitForSsoLoginArgInternal__) Import() LoginWaitForSsoLoginArg {
	return LoginWaitForSsoLoginArg{
		SessionId: (func(x *lib.UISessionIDInternal__) (ret lib.UISessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SessionId),
	}
}
func (l LoginWaitForSsoLoginArg) Export() *LoginWaitForSsoLoginArgInternal__ {
	return &LoginWaitForSsoLoginArgInternal__{
		SessionId: l.SessionId.Export(),
	}
}
func (l *LoginWaitForSsoLoginArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoginWaitForSsoLoginArg) Decode(dec rpc.Decoder) error {
	var tmp LoginWaitForSsoLoginArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoginWaitForSsoLoginArg) Bytes() []byte { return nil }

type UserInterface interface {
	Clear(context.Context) error
	AgentStatus(context.Context) (AgentStatus, error)
	ActiveUser(context.Context) (lib.UserContext, error)
	SwitchUser(context.Context, LocalUserIndexParsed) error
	SwitchUserByInfo(context.Context, lib.UserInfo) error
	GetExistingUsers(context.Context) ([]lib.UserInfo, error)
	ActiveUserCheckLocked(context.Context) (ActiveUserCheckLockedRes, error)
	LoadMe(context.Context) (UserMetadataAndSigchainState, error)
	SkmInfo(context.Context) (StoredSecretKeyBundle, error)
	SetSkmEncryption(context.Context, lib.SecretKeyStorageType) error
	UserLock(context.Context) error
	Ping(context.Context) (lib.FQUser, error)
	LoginStartSsoLoginFlow(context.Context, lib.UISessionID) (SsoLoginFlow, error)
	LoginWaitForSsoLogin(context.Context, lib.UISessionID) (lib.SSOLoginRes, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func UserMakeGenericErrorWrapper(f UserErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type UserErrorUnwrapper func(lib.Status) error
type UserErrorWrapper func(error) lib.Status

type userErrorUnwrapperAdapter struct {
	h UserErrorUnwrapper
}

func (u userErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (u userErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return u.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = userErrorUnwrapperAdapter{}

type UserClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper UserErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c UserClient) Clear(ctx context.Context) (err error) {
	var arg ClearArg
	warg := &rpc.DataWrap[Header, *ClearArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 0, "User.clear"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}
func (c UserClient) AgentStatus(ctx context.Context) (res AgentStatus, err error) {
	var arg AgentStatusArg
	warg := &rpc.DataWrap[Header, *AgentStatusArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, AgentStatusInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 1, "User.agentStatus"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}
func (c UserClient) ActiveUser(ctx context.Context) (res lib.UserContext, err error) {
	var arg ActiveUserArg
	warg := &rpc.DataWrap[Header, *ActiveUserArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.UserContextInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 2, "User.activeUser"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}
func (c UserClient) SwitchUser(ctx context.Context, fqu LocalUserIndexParsed) (err error) {
	arg := SwitchUserArg{
		Fqu: fqu,
	}
	warg := &rpc.DataWrap[Header, *SwitchUserArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 3, "User.switchUser"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}
func (c UserClient) SwitchUserByInfo(ctx context.Context, i lib.UserInfo) (err error) {
	arg := SwitchUserByInfoArg{
		I: i,
	}
	warg := &rpc.DataWrap[Header, *SwitchUserByInfoArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 4, "User.switchUserByInfo"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}
func (c UserClient) GetExistingUsers(ctx context.Context) (res []lib.UserInfo, err error) {
	var arg GetExistingUsersArg
	warg := &rpc.DataWrap[Header, *GetExistingUsersArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, [](*lib.UserInfoInternal__)]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 5, "User.getExistingUsers"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = (func(x *[](*lib.UserInfoInternal__)) (ret []lib.UserInfo) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]lib.UserInfo, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *lib.UserInfoInternal__) (ret lib.UserInfo) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(v)
		}
		return ret
	})(&tmp.Data)
	return
}
func (c UserClient) ActiveUserCheckLocked(ctx context.Context) (res ActiveUserCheckLockedRes, err error) {
	var arg ActiveUserCheckLockedArg
	warg := &rpc.DataWrap[Header, *ActiveUserCheckLockedArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, ActiveUserCheckLockedResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 6, "User.activeUserCheckLocked"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}
func (c UserClient) LoadMe(ctx context.Context) (res UserMetadataAndSigchainState, err error) {
	var arg LoadMeArg
	warg := &rpc.DataWrap[Header, *LoadMeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, UserMetadataAndSigchainStateInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 7, "User.loadMe"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}
func (c UserClient) SkmInfo(ctx context.Context) (res StoredSecretKeyBundle, err error) {
	var arg SkmInfoArg
	warg := &rpc.DataWrap[Header, *SkmInfoArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, StoredSecretKeyBundleInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 8, "User.skmInfo"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}
func (c UserClient) SetSkmEncryption(ctx context.Context, mode lib.SecretKeyStorageType) (err error) {
	arg := SetSkmEncryptionArg{
		Mode: mode,
	}
	warg := &rpc.DataWrap[Header, *SetSkmEncryptionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 9, "User.setSkmEncryption"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}
func (c UserClient) UserLock(ctx context.Context) (err error) {
	var arg UserLockArg
	warg := &rpc.DataWrap[Header, *UserLockArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 10, "User.userLock"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}
func (c UserClient) Ping(ctx context.Context) (res lib.FQUser, err error) {
	var arg ClientUserPingArg
	warg := &rpc.DataWrap[Header, *ClientUserPingArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.FQUserInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 11, "User.ping"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}
func (c UserClient) LoginStartSsoLoginFlow(ctx context.Context, sessionId lib.UISessionID) (res SsoLoginFlow, err error) {
	arg := LoginStartSsoLoginFlowArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *LoginStartSsoLoginFlowArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, SsoLoginFlowInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 12, "User.loginStartSsoLoginFlow"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}
func (c UserClient) LoginWaitForSsoLogin(ctx context.Context, sessionId lib.UISessionID) (res lib.SSOLoginRes, err error) {
	arg := LoginWaitForSsoLoginArg{
		SessionId: sessionId,
	}
	warg := &rpc.DataWrap[Header, *LoginWaitForSsoLoginArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.SSOLoginResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 13, "User.loginWaitForSsoLogin"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}
func UserProtocol(i UserInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "User",
		ID:   UserProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClearArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClearArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClearArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						err := i.Clear(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clear",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *AgentStatusArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *AgentStatusArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *AgentStatusArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.AgentStatus(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *AgentStatusInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "agentStatus",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ActiveUserArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ActiveUserArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ActiveUserArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.ActiveUser(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.UserContextInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "activeUser",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SwitchUserArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SwitchUserArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SwitchUserArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SwitchUser(ctx, (typedArg.Import()).Fqu)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "switchUser",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SwitchUserByInfoArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SwitchUserByInfoArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SwitchUserByInfoArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SwitchUserByInfo(ctx, (typedArg.Import()).I)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "switchUserByInfo",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GetExistingUsersArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GetExistingUsersArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GetExistingUsersArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetExistingUsers(ctx)
						if err != nil {
							return nil, err
						}
						lst := (func(x []lib.UserInfo) *[](*lib.UserInfoInternal__) {
							if len(x) == 0 {
								return nil
							}
							ret := make([](*lib.UserInfoInternal__), len(x))
							for k, v := range x {
								ret[k] = v.Export()
							}
							return &ret
						})(tmp)
						ret := rpc.DataWrap[Header, [](*lib.UserInfoInternal__)]{
							Header: i.MakeResHeader(),
						}
						if lst != nil {
							ret.Data = *lst
						}
						return &ret, nil
					},
				},
				Name: "getExistingUsers",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ActiveUserCheckLockedArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ActiveUserCheckLockedArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ActiveUserCheckLockedArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.ActiveUserCheckLocked(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *ActiveUserCheckLockedResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "activeUserCheckLocked",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *LoadMeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *LoadMeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *LoadMeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.LoadMe(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *UserMetadataAndSigchainStateInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loadMe",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SkmInfoArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SkmInfoArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SkmInfoArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.SkmInfo(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *StoredSecretKeyBundleInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "skmInfo",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *SetSkmEncryptionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *SetSkmEncryptionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *SetSkmEncryptionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SetSkmEncryption(ctx, (typedArg.Import()).Mode)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "setSkmEncryption",
			},
			10: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *UserLockArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *UserLockArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *UserLockArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						err := i.UserLock(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "userLock",
			},
			11: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientUserPingArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientUserPingArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientUserPingArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.Ping(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.FQUserInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "ping",
			},
			12: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *LoginStartSsoLoginFlowArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *LoginStartSsoLoginFlowArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *LoginStartSsoLoginFlowArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.LoginStartSsoLoginFlow(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *SsoLoginFlowInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loginStartSsoLoginFlow",
			},
			13: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *LoginWaitForSsoLoginArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *LoginWaitForSsoLoginArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *LoginWaitForSsoLoginArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.LoginWaitForSsoLogin(ctx, (typedArg.Import()).SessionId)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.SSOLoginResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loginWaitForSsoLogin",
			},
		},
		WrapError: UserMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(UserProtocolID)
}
