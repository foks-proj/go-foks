// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/user.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type UserInfo struct {
	Fqu       FQUser
	Username  NameBundle
	HostAddr  TCPAddr
	Active    bool
	YubiInfo  *YubiKeyInfoHybrid
	Role      Role
	KeyGenus  KeyGenus
	ViewToken *ViewToken
	Key       EntityID
	Devname   DeviceName
}
type UserInfoInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu       *FQUserInternal__
	Username  *NameBundleInternal__
	HostAddr  *TCPAddrInternal__
	Active    *bool
	YubiInfo  *YubiKeyInfoHybridInternal__
	Role      *RoleInternal__
	KeyGenus  *KeyGenusInternal__
	ViewToken *ViewTokenInternal__
	Key       *EntityIDInternal__
	Devname   *DeviceNameInternal__
}

func (u UserInfoInternal__) Import() UserInfo {
	return UserInfo{
		Fqu: (func(x *FQUserInternal__) (ret FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Fqu),
		Username: (func(x *NameBundleInternal__) (ret NameBundle) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Username),
		HostAddr: (func(x *TCPAddrInternal__) (ret TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.HostAddr),
		Active: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(u.Active),
		YubiInfo: (func(x *YubiKeyInfoHybridInternal__) *YubiKeyInfoHybrid {
			if x == nil {
				return nil
			}
			tmp := (func(x *YubiKeyInfoHybridInternal__) (ret YubiKeyInfoHybrid) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.YubiInfo),
		Role: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Role),
		KeyGenus: (func(x *KeyGenusInternal__) (ret KeyGenus) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.KeyGenus),
		ViewToken: (func(x *ViewTokenInternal__) *ViewToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *ViewTokenInternal__) (ret ViewToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.ViewToken),
		Key: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Key),
		Devname: (func(x *DeviceNameInternal__) (ret DeviceName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Devname),
	}
}
func (u UserInfo) Export() *UserInfoInternal__ {
	return &UserInfoInternal__{
		Fqu:      u.Fqu.Export(),
		Username: u.Username.Export(),
		HostAddr: u.HostAddr.Export(),
		Active:   &u.Active,
		YubiInfo: (func(x *YubiKeyInfoHybrid) *YubiKeyInfoHybridInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(u.YubiInfo),
		Role:     u.Role.Export(),
		KeyGenus: u.KeyGenus.Export(),
		ViewToken: (func(x *ViewToken) *ViewTokenInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(u.ViewToken),
		Key:     u.Key.Export(),
		Devname: u.Devname.Export(),
	}
}
func (u *UserInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserInfo) Decode(dec rpc.Decoder) error {
	var tmp UserInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

var UserInfoTypeUniqueID = rpc.TypeUniqueID(0xb9d0f7ccec149b5b)

func (u *UserInfo) GetTypeUniqueID() rpc.TypeUniqueID {
	return UserInfoTypeUniqueID
}
func (u *UserInfo) Bytes() []byte { return nil }

type UserContext struct {
	Info          UserInfo
	Key           EntityID
	Puks          []SharedKey
	Mtime         Time
	Devname       DeviceName
	LockStatus    Status
	NetworkStatus Status
}
type UserContextInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Info          *UserInfoInternal__
	Key           *EntityIDInternal__
	Puks          *[](*SharedKeyInternal__)
	Mtime         *TimeInternal__
	Devname       *DeviceNameInternal__
	LockStatus    *StatusInternal__
	NetworkStatus *StatusInternal__
}

func (u UserContextInternal__) Import() UserContext {
	return UserContext{
		Info: (func(x *UserInfoInternal__) (ret UserInfo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Info),
		Key: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Key),
		Puks: (func(x *[](*SharedKeyInternal__)) (ret []SharedKey) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SharedKey, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SharedKeyInternal__) (ret SharedKey) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.Puks),
		Mtime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Mtime),
		Devname: (func(x *DeviceNameInternal__) (ret DeviceName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Devname),
		LockStatus: (func(x *StatusInternal__) (ret Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.LockStatus),
		NetworkStatus: (func(x *StatusInternal__) (ret Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.NetworkStatus),
	}
}
func (u UserContext) Export() *UserContextInternal__ {
	return &UserContextInternal__{
		Info: u.Info.Export(),
		Key:  u.Key.Export(),
		Puks: (func(x []SharedKey) *[](*SharedKeyInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SharedKeyInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.Puks),
		Mtime:         u.Mtime.Export(),
		Devname:       u.Devname.Export(),
		LockStatus:    u.LockStatus.Export(),
		NetworkStatus: u.NetworkStatus.Export(),
	}
}
func (u *UserContext) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserContext) Decode(dec rpc.Decoder) error {
	var tmp UserContextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserContext) Bytes() []byte { return nil }

type RegServerConfig struct {
	Sso *SSOConfig
	Typ HostType
}
type RegServerConfigInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Sso     *SSOConfigInternal__
	Typ     *HostTypeInternal__
}

func (r RegServerConfigInternal__) Import() RegServerConfig {
	return RegServerConfig{
		Sso: (func(x *SSOConfigInternal__) *SSOConfig {
			if x == nil {
				return nil
			}
			tmp := (func(x *SSOConfigInternal__) (ret SSOConfig) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Sso),
		Typ: (func(x *HostTypeInternal__) (ret HostType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Typ),
	}
}
func (r RegServerConfig) Export() *RegServerConfigInternal__ {
	return &RegServerConfigInternal__{
		Sso: (func(x *SSOConfig) *SSOConfigInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Sso),
		Typ: r.Typ.Export(),
	}
}
func (r *RegServerConfig) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RegServerConfig) Decode(dec rpc.Decoder) error {
	var tmp RegServerConfigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RegServerConfig) Bytes() []byte { return nil }

type Email string
type EmailInternal__ string

func (e Email) Export() *EmailInternal__ {
	tmp := ((string)(e))
	return ((*EmailInternal__)(&tmp))
}
func (e EmailInternal__) Import() Email {
	tmp := (string)(e)
	return Email((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *Email) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *Email) Decode(dec rpc.Decoder) error {
	var tmp EmailInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e Email) Bytes() []byte {
	return nil
}

type LookupUserRes struct {
	Fqu          FQUser
	Username     Name
	UsernameUtf8 NameUtf8
	Role         Role
	YubiPQHint   *YubiSlotAndPQKeyID
}
type LookupUserResInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu          *FQUserInternal__
	Username     *NameInternal__
	UsernameUtf8 *NameUtf8Internal__
	Role         *RoleInternal__
	YubiPQHint   *YubiSlotAndPQKeyIDInternal__
}

func (l LookupUserResInternal__) Import() LookupUserRes {
	return LookupUserRes{
		Fqu: (func(x *FQUserInternal__) (ret FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Fqu),
		Username: (func(x *NameInternal__) (ret Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Username),
		UsernameUtf8: (func(x *NameUtf8Internal__) (ret NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.UsernameUtf8),
		Role: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Role),
		YubiPQHint: (func(x *YubiSlotAndPQKeyIDInternal__) *YubiSlotAndPQKeyID {
			if x == nil {
				return nil
			}
			tmp := (func(x *YubiSlotAndPQKeyIDInternal__) (ret YubiSlotAndPQKeyID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.YubiPQHint),
	}
}
func (l LookupUserRes) Export() *LookupUserResInternal__ {
	return &LookupUserResInternal__{
		Fqu:          l.Fqu.Export(),
		Username:     l.Username.Export(),
		UsernameUtf8: l.UsernameUtf8.Export(),
		Role:         l.Role.Export(),
		YubiPQHint: (func(x *YubiSlotAndPQKeyID) *YubiSlotAndPQKeyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(l.YubiPQHint),
	}
}
func (l *LookupUserRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LookupUserRes) Decode(dec rpc.Decoder) error {
	var tmp LookupUserResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LookupUserRes) Bytes() []byte { return nil }

type UserLockState int

const (
	UserLockState_Unset      UserLockState = 0
	UserLockState_Error      UserLockState = 1
	UserLockState_Unlocked   UserLockState = 2
	UserLockState_Passphrase UserLockState = 3
	UserLockState_Yubi       UserLockState = 4
	UserLockState_Keychain   UserLockState = 5
	UserLockState_SSO        UserLockState = 6
)

var UserLockStateMap = map[string]UserLockState{
	"Unset":      0,
	"Error":      1,
	"Unlocked":   2,
	"Passphrase": 3,
	"Yubi":       4,
	"Keychain":   5,
	"SSO":        6,
}
var UserLockStateRevMap = map[UserLockState]string{
	0: "Unset",
	1: "Error",
	2: "Unlocked",
	3: "Passphrase",
	4: "Yubi",
	5: "Keychain",
	6: "SSO",
}

type UserLockStateInternal__ UserLockState

func (u UserLockStateInternal__) Import() UserLockState {
	return UserLockState(u)
}
func (u UserLockState) Export() *UserLockStateInternal__ {
	return ((*UserLockStateInternal__)(&u))
}

type UserInfoAndStatus struct {
	Info          UserInfo
	LockStatus    Status
	NetworkStatus Status
}
type UserInfoAndStatusInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Info          *UserInfoInternal__
	LockStatus    *StatusInternal__
	NetworkStatus *StatusInternal__
}

func (u UserInfoAndStatusInternal__) Import() UserInfoAndStatus {
	return UserInfoAndStatus{
		Info: (func(x *UserInfoInternal__) (ret UserInfo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Info),
		LockStatus: (func(x *StatusInternal__) (ret Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.LockStatus),
		NetworkStatus: (func(x *StatusInternal__) (ret Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.NetworkStatus),
	}
}
func (u UserInfoAndStatus) Export() *UserInfoAndStatusInternal__ {
	return &UserInfoAndStatusInternal__{
		Info:          u.Info.Export(),
		LockStatus:    u.LockStatus.Export(),
		NetworkStatus: u.NetworkStatus.Export(),
	}
}
func (u *UserInfoAndStatus) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserInfoAndStatus) Decode(dec rpc.Decoder) error {
	var tmp UserInfoAndStatusInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserInfoAndStatus) Bytes() []byte { return nil }

type LocalUserIndexAtHost struct {
	Uid   UID
	Keyid EntityID
}
type LocalUserIndexAtHostInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid     *UIDInternal__
	Keyid   *EntityIDInternal__
}

func (l LocalUserIndexAtHostInternal__) Import() LocalUserIndexAtHost {
	return LocalUserIndexAtHost{
		Uid: (func(x *UIDInternal__) (ret UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Uid),
		Keyid: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Keyid),
	}
}
func (l LocalUserIndexAtHost) Export() *LocalUserIndexAtHostInternal__ {
	return &LocalUserIndexAtHostInternal__{
		Uid:   l.Uid.Export(),
		Keyid: l.Keyid.Export(),
	}
}
func (l *LocalUserIndexAtHost) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LocalUserIndexAtHost) Decode(dec rpc.Decoder) error {
	var tmp LocalUserIndexAtHostInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

var LocalUserIndexAtHostTypeUniqueID = rpc.TypeUniqueID(0xef52df3bdf52d9d1)

func (l *LocalUserIndexAtHost) GetTypeUniqueID() rpc.TypeUniqueID {
	return LocalUserIndexAtHostTypeUniqueID
}
func (l *LocalUserIndexAtHost) Bytes() []byte { return nil }

type LocalUserIndex struct {
	Host HostID
	Rest LocalUserIndexAtHost
}
type LocalUserIndexInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *HostIDInternal__
	Rest    *LocalUserIndexAtHostInternal__
}

func (l LocalUserIndexInternal__) Import() LocalUserIndex {
	return LocalUserIndex{
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Host),
		Rest: (func(x *LocalUserIndexAtHostInternal__) (ret LocalUserIndexAtHost) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Rest),
	}
}
func (l LocalUserIndex) Export() *LocalUserIndexInternal__ {
	return &LocalUserIndexInternal__{
		Host: l.Host.Export(),
		Rest: l.Rest.Export(),
	}
}
func (l *LocalUserIndex) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LocalUserIndex) Decode(dec rpc.Decoder) error {
	var tmp LocalUserIndexInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

var LocalUserIndexTypeUniqueID = rpc.TypeUniqueID(0xc2b545ad04c73d1b)

func (l *LocalUserIndex) GetTypeUniqueID() rpc.TypeUniqueID {
	return LocalUserIndexTypeUniqueID
}
func (l *LocalUserIndex) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(UserInfoTypeUniqueID)
	rpc.AddUnique(LocalUserIndexAtHostTypeUniqueID)
	rpc.AddUnique(LocalUserIndexTypeUniqueID)
}
