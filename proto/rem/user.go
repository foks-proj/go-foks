// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/rem/user.snowp

package rem

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type WebSession [20]byte
type WebSessionInternal__ [20]byte

func (w WebSession) Export() *WebSessionInternal__ {
	tmp := (([20]byte)(w))
	return ((*WebSessionInternal__)(&tmp))
}

func (w WebSessionInternal__) Import() WebSession {
	tmp := ([20]byte)(w)
	return WebSession((func(x *[20]byte) (ret [20]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (w *WebSession) Encode(enc rpc.Encoder) error {
	return enc.Encode(w.Export())
}

func (w *WebSession) Decode(dec rpc.Decoder) error {
	var tmp WebSessionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*w = tmp.Import()
	return nil
}

func (w WebSession) Bytes() []byte {
	return (w)[:]
}

type WebSessionString string
type WebSessionStringInternal__ string

func (w WebSessionString) Export() *WebSessionStringInternal__ {
	tmp := ((string)(w))
	return ((*WebSessionStringInternal__)(&tmp))
}

func (w WebSessionStringInternal__) Import() WebSessionString {
	tmp := (string)(w)
	return WebSessionString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (w *WebSessionString) Encode(enc rpc.Encoder) error {
	return enc.Encode(w.Export())
}

func (w *WebSessionString) Decode(dec rpc.Decoder) error {
	var tmp WebSessionStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*w = tmp.Import()
	return nil
}

func (w WebSessionString) Bytes() []byte {
	return nil
}

type DeviceLabelNameAndCommitmentKey struct {
	Dln           lib.DeviceLabelAndName
	CommitmentKey lib.RandomCommitmentKey
}

type DeviceLabelNameAndCommitmentKeyInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Dln           *lib.DeviceLabelAndNameInternal__
	CommitmentKey *lib.RandomCommitmentKeyInternal__
}

func (d DeviceLabelNameAndCommitmentKeyInternal__) Import() DeviceLabelNameAndCommitmentKey {
	return DeviceLabelNameAndCommitmentKey{
		Dln: (func(x *lib.DeviceLabelAndNameInternal__) (ret lib.DeviceLabelAndName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Dln),
		CommitmentKey: (func(x *lib.RandomCommitmentKeyInternal__) (ret lib.RandomCommitmentKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.CommitmentKey),
	}
}

func (d DeviceLabelNameAndCommitmentKey) Export() *DeviceLabelNameAndCommitmentKeyInternal__ {
	return &DeviceLabelNameAndCommitmentKeyInternal__{
		Dln:           d.Dln.Export(),
		CommitmentKey: d.CommitmentKey.Export(),
	}
}

func (d *DeviceLabelNameAndCommitmentKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceLabelNameAndCommitmentKey) Decode(dec rpc.Decoder) error {
	var tmp DeviceLabelNameAndCommitmentKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DeviceLabelNameAndCommitmentKey) Bytes() []byte { return nil }

type LoadUserChainAuthType int

const (
	LoadUserChainAuthType_AsLocalUser LoadUserChainAuthType = 0
	LoadUserChainAuthType_Token       LoadUserChainAuthType = 1
	LoadUserChainAuthType_SelfToken   LoadUserChainAuthType = 2
	LoadUserChainAuthType_AsLocalTeam LoadUserChainAuthType = 3
	LoadUserChainAuthType_OpenVHost   LoadUserChainAuthType = 4
)

var LoadUserChainAuthTypeMap = map[string]LoadUserChainAuthType{
	"AsLocalUser": 0,
	"Token":       1,
	"SelfToken":   2,
	"AsLocalTeam": 3,
	"OpenVHost":   4,
}

var LoadUserChainAuthTypeRevMap = map[LoadUserChainAuthType]string{
	0: "AsLocalUser",
	1: "Token",
	2: "SelfToken",
	3: "AsLocalTeam",
	4: "OpenVHost",
}

type LoadUserChainAuthTypeInternal__ LoadUserChainAuthType

func (l LoadUserChainAuthTypeInternal__) Import() LoadUserChainAuthType {
	return LoadUserChainAuthType(l)
}

func (l LoadUserChainAuthType) Export() *LoadUserChainAuthTypeInternal__ {
	return ((*LoadUserChainAuthTypeInternal__)(&l))
}

type LoadUserChainAuth struct {
	T     LoadUserChainAuthType
	F_1__ *lib.PermissionToken `json:"f1,omitempty"`
	F_2__ *lib.PermissionToken `json:"f2,omitempty"`
	F_3__ *TeamVOBearerToken   `json:"f3,omitempty"`
}

type LoadUserChainAuthInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        LoadUserChainAuthType
	Switch__ LoadUserChainAuthInternalSwitch__
}

type LoadUserChainAuthInternalSwitch__ struct {
	_struct struct{}                       `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *lib.PermissionTokenInternal__ `codec:"1"`
	F_2__   *lib.PermissionTokenInternal__ `codec:"2"`
	F_3__   *TeamVOBearerTokenInternal__   `codec:"3"`
}

func (l LoadUserChainAuth) GetT() (ret LoadUserChainAuthType, err error) {
	switch l.T {
	case LoadUserChainAuthType_AsLocalUser:
		break
	case LoadUserChainAuthType_Token:
		if l.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case LoadUserChainAuthType_SelfToken:
		if l.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case LoadUserChainAuthType_AsLocalTeam:
		if l.F_3__ == nil {
			return ret, errors.New("unexpected nil case for F_3__")
		}
	case LoadUserChainAuthType_OpenVHost:
		break
	}
	return l.T, nil
}

func (l LoadUserChainAuth) Token() lib.PermissionToken {
	if l.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if l.T != LoadUserChainAuthType_Token {
		panic(fmt.Sprintf("unexpected switch value (%v) when Token is called", l.T))
	}
	return *l.F_1__
}

func (l LoadUserChainAuth) Selftoken() lib.PermissionToken {
	if l.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if l.T != LoadUserChainAuthType_SelfToken {
		panic(fmt.Sprintf("unexpected switch value (%v) when Selftoken is called", l.T))
	}
	return *l.F_2__
}

func (l LoadUserChainAuth) Aslocalteam() TeamVOBearerToken {
	if l.F_3__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if l.T != LoadUserChainAuthType_AsLocalTeam {
		panic(fmt.Sprintf("unexpected switch value (%v) when Aslocalteam is called", l.T))
	}
	return *l.F_3__
}

func NewLoadUserChainAuthWithAslocaluser() LoadUserChainAuth {
	return LoadUserChainAuth{
		T: LoadUserChainAuthType_AsLocalUser,
	}
}

func NewLoadUserChainAuthWithToken(v lib.PermissionToken) LoadUserChainAuth {
	return LoadUserChainAuth{
		T:     LoadUserChainAuthType_Token,
		F_1__: &v,
	}
}

func NewLoadUserChainAuthWithSelftoken(v lib.PermissionToken) LoadUserChainAuth {
	return LoadUserChainAuth{
		T:     LoadUserChainAuthType_SelfToken,
		F_2__: &v,
	}
}

func NewLoadUserChainAuthWithAslocalteam(v TeamVOBearerToken) LoadUserChainAuth {
	return LoadUserChainAuth{
		T:     LoadUserChainAuthType_AsLocalTeam,
		F_3__: &v,
	}
}

func NewLoadUserChainAuthWithOpenvhost() LoadUserChainAuth {
	return LoadUserChainAuth{
		T: LoadUserChainAuthType_OpenVHost,
	}
}

func (l LoadUserChainAuthInternal__) Import() LoadUserChainAuth {
	return LoadUserChainAuth{
		T: l.T,
		F_1__: (func(x *lib.PermissionTokenInternal__) *lib.PermissionToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Switch__.F_1__),
		F_2__: (func(x *lib.PermissionTokenInternal__) *lib.PermissionToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Switch__.F_2__),
		F_3__: (func(x *TeamVOBearerTokenInternal__) *TeamVOBearerToken {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamVOBearerTokenInternal__) (ret TeamVOBearerToken) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Switch__.F_3__),
	}
}

func (l LoadUserChainAuth) Export() *LoadUserChainAuthInternal__ {
	return &LoadUserChainAuthInternal__{
		T: l.T,
		Switch__: LoadUserChainAuthInternalSwitch__{
			F_1__: (func(x *lib.PermissionToken) *lib.PermissionTokenInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(l.F_1__),
			F_2__: (func(x *lib.PermissionToken) *lib.PermissionTokenInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(l.F_2__),
			F_3__: (func(x *TeamVOBearerToken) *TeamVOBearerTokenInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(l.F_3__),
		},
	}
}

func (l *LoadUserChainAuth) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadUserChainAuth) Decode(dec rpc.Decoder) error {
	var tmp LoadUserChainAuthInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadUserChainAuth) Bytes() []byte { return nil }

type LoadUserChainArg struct {
	Uid      lib.UID
	Start    lib.Seqno
	Username *NameSeqnoPair
	Auth     LoadUserChainAuth
}

type LoadUserChainArgInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid      *lib.UIDInternal__
	Start    *lib.SeqnoInternal__
	Username *NameSeqnoPairInternal__
	Auth     *LoadUserChainAuthInternal__
}

func (l LoadUserChainArgInternal__) Import() LoadUserChainArg {
	return LoadUserChainArg{
		Uid: (func(x *lib.UIDInternal__) (ret lib.UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Uid),
		Start: (func(x *lib.SeqnoInternal__) (ret lib.Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Start),
		Username: (func(x *NameSeqnoPairInternal__) *NameSeqnoPair {
			if x == nil {
				return nil
			}
			tmp := (func(x *NameSeqnoPairInternal__) (ret NameSeqnoPair) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.Username),
		Auth: (func(x *LoadUserChainAuthInternal__) (ret LoadUserChainAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Auth),
	}
}

func (l LoadUserChainArg) Export() *LoadUserChainArgInternal__ {
	return &LoadUserChainArgInternal__{
		Uid:   l.Uid.Export(),
		Start: l.Start.Export(),
		Username: (func(x *NameSeqnoPair) *NameSeqnoPairInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(l.Username),
		Auth: l.Auth.Export(),
	}
}

func (l *LoadUserChainArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadUserChainArg) Decode(dec rpc.Decoder) error {
	var tmp LoadUserChainArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadUserChainArg) Bytes() []byte { return nil }

type NameSeqnoPair struct {
	N lib.Name
	S lib.NameSeqno
}

type NameSeqnoPairInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	N       *lib.NameInternal__
	S       *lib.NameSeqnoInternal__
}

func (n NameSeqnoPairInternal__) Import() NameSeqnoPair {
	return NameSeqnoPair{
		N: (func(x *lib.NameInternal__) (ret lib.Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.N),
		S: (func(x *lib.NameSeqnoInternal__) (ret lib.NameSeqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.S),
	}
}

func (n NameSeqnoPair) Export() *NameSeqnoPairInternal__ {
	return &NameSeqnoPairInternal__{
		N: n.N.Export(),
		S: n.S.Export(),
	}
}

func (n *NameSeqnoPair) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NameSeqnoPair) Decode(dec rpc.Decoder) error {
	var tmp NameSeqnoPairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NameSeqnoPair) Bytes() []byte { return nil }

type ResolveUsernameArg struct {
	N    lib.Name
	Auth LoadUserChainAuth
}

type ResolveUsernameArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	N       *lib.NameInternal__
	Auth    *LoadUserChainAuthInternal__
}

func (r ResolveUsernameArgInternal__) Import() ResolveUsernameArg {
	return ResolveUsernameArg{
		N: (func(x *lib.NameInternal__) (ret lib.Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.N),
		Auth: (func(x *LoadUserChainAuthInternal__) (ret LoadUserChainAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Auth),
	}
}

func (r ResolveUsernameArg) Export() *ResolveUsernameArgInternal__ {
	return &ResolveUsernameArgInternal__{
		N:    r.N.Export(),
		Auth: r.Auth.Export(),
	}
}

func (r *ResolveUsernameArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *ResolveUsernameArg) Decode(dec rpc.Decoder) error {
	var tmp ResolveUsernameArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *ResolveUsernameArg) Bytes() []byte { return nil }

type NameCommitmentAndKey struct {
	Unc NameCommitment
	Key lib.RandomCommitmentKey
}

type NameCommitmentAndKeyInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Unc     *NameCommitmentInternal__
	Key     *lib.RandomCommitmentKeyInternal__
}

func (n NameCommitmentAndKeyInternal__) Import() NameCommitmentAndKey {
	return NameCommitmentAndKey{
		Unc: (func(x *NameCommitmentInternal__) (ret NameCommitment) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Unc),
		Key: (func(x *lib.RandomCommitmentKeyInternal__) (ret lib.RandomCommitmentKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Key),
	}
}

func (n NameCommitmentAndKey) Export() *NameCommitmentAndKeyInternal__ {
	return &NameCommitmentAndKeyInternal__{
		Unc: n.Unc.Export(),
		Key: n.Key.Export(),
	}
}

func (n *NameCommitmentAndKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NameCommitmentAndKey) Decode(dec rpc.Decoder) error {
	var tmp NameCommitmentAndKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NameCommitmentAndKey) Bytes() []byte { return nil }

type UserChain struct {
	Links            []lib.LinkOuter
	Locations        []lib.TreeLocation
	Usernames        []NameCommitmentAndKey
	Merkle           lib.MerklePathsCompressed
	DeviceNames      []DeviceLabelNameAndCommitmentKey
	UsernameUtf8     lib.NameUtf8
	NumUsernameLinks uint64
	Hepks            lib.HEPKSet
}

type UserChainInternal__ struct {
	_struct          struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Links            *[](*lib.LinkOuterInternal__)
	Locations        *[](*lib.TreeLocationInternal__)
	Usernames        *[](*NameCommitmentAndKeyInternal__)
	Merkle           *lib.MerklePathsCompressedInternal__
	DeviceNames      *[](*DeviceLabelNameAndCommitmentKeyInternal__)
	UsernameUtf8     *lib.NameUtf8Internal__
	NumUsernameLinks *uint64
	Hepks            *lib.HEPKSetInternal__
}

func (u UserChainInternal__) Import() UserChain {
	return UserChain{
		Links: (func(x *[](*lib.LinkOuterInternal__)) (ret []lib.LinkOuter) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.LinkOuter, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.Links),
		Locations: (func(x *[](*lib.TreeLocationInternal__)) (ret []lib.TreeLocation) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.TreeLocation, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.Locations),
		Usernames: (func(x *[](*NameCommitmentAndKeyInternal__)) (ret []NameCommitmentAndKey) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]NameCommitmentAndKey, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *NameCommitmentAndKeyInternal__) (ret NameCommitmentAndKey) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.Usernames),
		Merkle: (func(x *lib.MerklePathsCompressedInternal__) (ret lib.MerklePathsCompressed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Merkle),
		DeviceNames: (func(x *[](*DeviceLabelNameAndCommitmentKeyInternal__)) (ret []DeviceLabelNameAndCommitmentKey) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]DeviceLabelNameAndCommitmentKey, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *DeviceLabelNameAndCommitmentKeyInternal__) (ret DeviceLabelNameAndCommitmentKey) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.DeviceNames),
		UsernameUtf8: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.UsernameUtf8),
		NumUsernameLinks: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(u.NumUsernameLinks),
		Hepks: (func(x *lib.HEPKSetInternal__) (ret lib.HEPKSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Hepks),
	}
}

func (u UserChain) Export() *UserChainInternal__ {
	return &UserChainInternal__{
		Links: (func(x []lib.LinkOuter) *[](*lib.LinkOuterInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.LinkOuterInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.Links),
		Locations: (func(x []lib.TreeLocation) *[](*lib.TreeLocationInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.TreeLocationInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.Locations),
		Usernames: (func(x []NameCommitmentAndKey) *[](*NameCommitmentAndKeyInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*NameCommitmentAndKeyInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.Usernames),
		Merkle: u.Merkle.Export(),
		DeviceNames: (func(x []DeviceLabelNameAndCommitmentKey) *[](*DeviceLabelNameAndCommitmentKeyInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*DeviceLabelNameAndCommitmentKeyInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.DeviceNames),
		UsernameUtf8:     u.UsernameUtf8.Export(),
		NumUsernameLinks: &u.NumUsernameLinks,
		Hepks:            u.Hepks.Export(),
	}
}

func (u *UserChain) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserChain) Decode(dec rpc.Decoder) error {
	var tmp UserChainInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserChain) Bytes() []byte { return nil }

type SetPassphraseAnnex struct {
	Arg  ChangePassphraseArg
	Link PostGenericLinkArg
}

type SetPassphraseAnnexInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Arg     *ChangePassphraseArgInternal__
	Link    *PostGenericLinkArgInternal__
}

func (s SetPassphraseAnnexInternal__) Import() SetPassphraseAnnex {
	return SetPassphraseAnnex{
		Arg: (func(x *ChangePassphraseArgInternal__) (ret ChangePassphraseArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Arg),
		Link: (func(x *PostGenericLinkArgInternal__) (ret PostGenericLinkArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Link),
	}
}

func (s SetPassphraseAnnex) Export() *SetPassphraseAnnexInternal__ {
	return &SetPassphraseAnnexInternal__{
		Arg:  s.Arg.Export(),
		Link: s.Link.Export(),
	}
}

func (s *SetPassphraseAnnex) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetPassphraseAnnex) Decode(dec rpc.Decoder) error {
	var tmp SetPassphraseAnnexInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetPassphraseAnnex) Bytes() []byte { return nil }

type GrantLocalViewPermissionPayload struct {
	Viewee lib.PartyID
	Viewer lib.PartyID
	Tm     lib.Time
}

type GrantLocalViewPermissionPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Viewee  *lib.PartyIDInternal__
	Viewer  *lib.PartyIDInternal__
	Tm      *lib.TimeInternal__
}

func (g GrantLocalViewPermissionPayloadInternal__) Import() GrantLocalViewPermissionPayload {
	return GrantLocalViewPermissionPayload{
		Viewee: (func(x *lib.PartyIDInternal__) (ret lib.PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Viewee),
		Viewer: (func(x *lib.PartyIDInternal__) (ret lib.PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Viewer),
		Tm: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Tm),
	}
}

func (g GrantLocalViewPermissionPayload) Export() *GrantLocalViewPermissionPayloadInternal__ {
	return &GrantLocalViewPermissionPayloadInternal__{
		Viewee: g.Viewee.Export(),
		Viewer: g.Viewer.Export(),
		Tm:     g.Tm.Export(),
	}
}

func (g *GrantLocalViewPermissionPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GrantLocalViewPermissionPayload) Decode(dec rpc.Decoder) error {
	var tmp GrantLocalViewPermissionPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

var GrantLocalViewPermissionPayloadTypeUniqueID = rpc.TypeUniqueID(0xf620e4a9845fa063)

func (g *GrantLocalViewPermissionPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return GrantLocalViewPermissionPayloadTypeUniqueID
}

func (g *GrantLocalViewPermissionPayload) Bytes() []byte { return nil }

type ChangedUsernameFullUpdateArg struct {
	Link                  lib.LinkOuter
	UsernameCommitmentKey lib.RandomCommitmentKey
	Rur                   ReserveNameRes
	NextTreeLocation      lib.TreeLocation
}

type ChangedUsernameFullUpdateArgInternal__ struct {
	_struct               struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Link                  *lib.LinkOuterInternal__
	UsernameCommitmentKey *lib.RandomCommitmentKeyInternal__
	Rur                   *ReserveNameResInternal__
	NextTreeLocation      *lib.TreeLocationInternal__
}

func (c ChangedUsernameFullUpdateArgInternal__) Import() ChangedUsernameFullUpdateArg {
	return ChangedUsernameFullUpdateArg{
		Link: (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Link),
		UsernameCommitmentKey: (func(x *lib.RandomCommitmentKeyInternal__) (ret lib.RandomCommitmentKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.UsernameCommitmentKey),
		Rur: (func(x *ReserveNameResInternal__) (ret ReserveNameRes) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Rur),
		NextTreeLocation: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.NextTreeLocation),
	}
}

func (c ChangedUsernameFullUpdateArg) Export() *ChangedUsernameFullUpdateArgInternal__ {
	return &ChangedUsernameFullUpdateArgInternal__{
		Link:                  c.Link.Export(),
		UsernameCommitmentKey: c.UsernameCommitmentKey.Export(),
		Rur:                   c.Rur.Export(),
		NextTreeLocation:      c.NextTreeLocation.Export(),
	}
}

func (c *ChangedUsernameFullUpdateArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChangedUsernameFullUpdateArg) Decode(dec rpc.Decoder) error {
	var tmp ChangedUsernameFullUpdateArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChangedUsernameFullUpdateArg) Bytes() []byte { return nil }

type GenericChain struct {
	Links        []lib.LinkOuter
	Locations    []lib.TreeLocation
	Merkle       lib.MerklePathsCompressed
	LocationSeed *lib.TreeLocation
}

type GenericChainInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Links        *[](*lib.LinkOuterInternal__)
	Locations    *[](*lib.TreeLocationInternal__)
	Merkle       *lib.MerklePathsCompressedInternal__
	LocationSeed *lib.TreeLocationInternal__
}

func (g GenericChainInternal__) Import() GenericChain {
	return GenericChain{
		Links: (func(x *[](*lib.LinkOuterInternal__)) (ret []lib.LinkOuter) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.LinkOuter, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Links),
		Locations: (func(x *[](*lib.TreeLocationInternal__)) (ret []lib.TreeLocation) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.TreeLocation, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Locations),
		Merkle: (func(x *lib.MerklePathsCompressedInternal__) (ret lib.MerklePathsCompressed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Merkle),
		LocationSeed: (func(x *lib.TreeLocationInternal__) *lib.TreeLocation {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.LocationSeed),
	}
}

func (g GenericChain) Export() *GenericChainInternal__ {
	return &GenericChainInternal__{
		Links: (func(x []lib.LinkOuter) *[](*lib.LinkOuterInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.LinkOuterInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Links),
		Locations: (func(x []lib.TreeLocation) *[](*lib.TreeLocationInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.TreeLocationInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Locations),
		Merkle: g.Merkle.Export(),
		LocationSeed: (func(x *lib.TreeLocation) *lib.TreeLocationInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.LocationSeed),
	}
}

func (g *GenericChain) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GenericChain) Decode(dec rpc.Decoder) error {
	var tmp GenericChainInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GenericChain) Bytes() []byte { return nil }

type GrantRemoteViewPermissionPayload struct {
	Viewee lib.PartyID
	Viewer lib.FQParty
	Tm     lib.Time
}

type GrantRemoteViewPermissionPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Viewee  *lib.PartyIDInternal__
	Viewer  *lib.FQPartyInternal__
	Tm      *lib.TimeInternal__
}

func (g GrantRemoteViewPermissionPayloadInternal__) Import() GrantRemoteViewPermissionPayload {
	return GrantRemoteViewPermissionPayload{
		Viewee: (func(x *lib.PartyIDInternal__) (ret lib.PartyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Viewee),
		Viewer: (func(x *lib.FQPartyInternal__) (ret lib.FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Viewer),
		Tm: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Tm),
	}
}

func (g GrantRemoteViewPermissionPayload) Export() *GrantRemoteViewPermissionPayloadInternal__ {
	return &GrantRemoteViewPermissionPayloadInternal__{
		Viewee: g.Viewee.Export(),
		Viewer: g.Viewer.Export(),
		Tm:     g.Tm.Export(),
	}
}

func (g *GrantRemoteViewPermissionPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GrantRemoteViewPermissionPayload) Decode(dec rpc.Decoder) error {
	var tmp GrantRemoteViewPermissionPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

var GrantRemoteViewPermissionPayloadTypeUniqueID = rpc.TypeUniqueID(0xc83da7560434c870)

func (g *GrantRemoteViewPermissionPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return GrantRemoteViewPermissionPayloadTypeUniqueID
}

func (g *GrantRemoteViewPermissionPayload) Bytes() []byte { return nil }

type LocalTeamListEntry struct {
	Id      lib.TeamID
	SrcRole lib.Role
	DstRole lib.Role
	Seqno   lib.Seqno
	KeyGen  lib.Generation
}

type LocalTeamListEntryInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.TeamIDInternal__
	SrcRole *lib.RoleInternal__
	DstRole *lib.RoleInternal__
	Seqno   *lib.SeqnoInternal__
	KeyGen  *lib.GenerationInternal__
}

func (l LocalTeamListEntryInternal__) Import() LocalTeamListEntry {
	return LocalTeamListEntry{
		Id: (func(x *lib.TeamIDInternal__) (ret lib.TeamID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Id),
		SrcRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SrcRole),
		DstRole: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.DstRole),
		Seqno: (func(x *lib.SeqnoInternal__) (ret lib.Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Seqno),
		KeyGen: (func(x *lib.GenerationInternal__) (ret lib.Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.KeyGen),
	}
}

func (l LocalTeamListEntry) Export() *LocalTeamListEntryInternal__ {
	return &LocalTeamListEntryInternal__{
		Id:      l.Id.Export(),
		SrcRole: l.SrcRole.Export(),
		DstRole: l.DstRole.Export(),
		Seqno:   l.Seqno.Export(),
		KeyGen:  l.KeyGen.Export(),
	}
}

func (l *LocalTeamListEntry) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LocalTeamListEntry) Decode(dec rpc.Decoder) error {
	var tmp LocalTeamListEntryInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LocalTeamListEntry) Bytes() []byte { return nil }

type NamedLocalTeamListEntry struct {
	Te          LocalTeamListEntry
	Name        lib.NameUtf8
	QuotaMaster *lib.UID
}

type NamedLocalTeamListEntryInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Te          *LocalTeamListEntryInternal__
	Name        *lib.NameUtf8Internal__
	QuotaMaster *lib.UIDInternal__
}

func (n NamedLocalTeamListEntryInternal__) Import() NamedLocalTeamListEntry {
	return NamedLocalTeamListEntry{
		Te: (func(x *LocalTeamListEntryInternal__) (ret LocalTeamListEntry) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Te),
		Name: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Name),
		QuotaMaster: (func(x *lib.UIDInternal__) *lib.UID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.UIDInternal__) (ret lib.UID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(n.QuotaMaster),
	}
}

func (n NamedLocalTeamListEntry) Export() *NamedLocalTeamListEntryInternal__ {
	return &NamedLocalTeamListEntryInternal__{
		Te:   n.Te.Export(),
		Name: n.Name.Export(),
		QuotaMaster: (func(x *lib.UID) *lib.UIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(n.QuotaMaster),
	}
}

func (n *NamedLocalTeamListEntry) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NamedLocalTeamListEntry) Decode(dec rpc.Decoder) error {
	var tmp NamedLocalTeamListEntryInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NamedLocalTeamListEntry) Bytes() []byte { return nil }

type NamedLocalTeamList []NamedLocalTeamListEntry
type NamedLocalTeamListInternal__ [](*NamedLocalTeamListEntryInternal__)

func (n NamedLocalTeamList) Export() *NamedLocalTeamListInternal__ {
	tmp := (([]NamedLocalTeamListEntry)(n))
	return ((*NamedLocalTeamListInternal__)((func(x []NamedLocalTeamListEntry) *[](*NamedLocalTeamListEntryInternal__) {
		if len(x) == 0 {
			return nil
		}
		ret := make([](*NamedLocalTeamListEntryInternal__), len(x))
		for k, v := range x {
			ret[k] = v.Export()
		}
		return &ret
	})(tmp)))
}

func (n NamedLocalTeamListInternal__) Import() NamedLocalTeamList {
	tmp := ([](*NamedLocalTeamListEntryInternal__))(n)
	return NamedLocalTeamList((func(x *[](*NamedLocalTeamListEntryInternal__)) (ret []NamedLocalTeamListEntry) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]NamedLocalTeamListEntry, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *NamedLocalTeamListEntryInternal__) (ret NamedLocalTeamListEntry) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(v)
		}
		return ret
	})(&tmp))
}

func (n *NamedLocalTeamList) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NamedLocalTeamList) Decode(dec rpc.Decoder) error {
	var tmp NamedLocalTeamListInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n NamedLocalTeamList) Bytes() []byte {
	return nil
}

type LocalTeamList []LocalTeamListEntry
type LocalTeamListInternal__ [](*LocalTeamListEntryInternal__)

func (l LocalTeamList) Export() *LocalTeamListInternal__ {
	tmp := (([]LocalTeamListEntry)(l))
	return ((*LocalTeamListInternal__)((func(x []LocalTeamListEntry) *[](*LocalTeamListEntryInternal__) {
		if len(x) == 0 {
			return nil
		}
		ret := make([](*LocalTeamListEntryInternal__), len(x))
		for k, v := range x {
			ret[k] = v.Export()
		}
		return &ret
	})(tmp)))
}

func (l LocalTeamListInternal__) Import() LocalTeamList {
	tmp := ([](*LocalTeamListEntryInternal__))(l)
	return LocalTeamList((func(x *[](*LocalTeamListEntryInternal__)) (ret []LocalTeamListEntry) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]LocalTeamListEntry, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *LocalTeamListEntryInternal__) (ret LocalTeamListEntry) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(v)
		}
		return ret
	})(&tmp))
}

func (l *LocalTeamList) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LocalTeamList) Decode(dec rpc.Decoder) error {
	var tmp LocalTeamListInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l LocalTeamList) Bytes() []byte {
	return nil
}

type EntityIDMerkleValueVersion int

const (
	EntityIDMerkleValueVersion_V1 EntityIDMerkleValueVersion = 1
)

var EntityIDMerkleValueVersionMap = map[string]EntityIDMerkleValueVersion{
	"V1": 1,
}

var EntityIDMerkleValueVersionRevMap = map[EntityIDMerkleValueVersion]string{
	1: "V1",
}

type EntityIDMerkleValueVersionInternal__ EntityIDMerkleValueVersion

func (e EntityIDMerkleValueVersionInternal__) Import() EntityIDMerkleValueVersion {
	return EntityIDMerkleValueVersion(e)
}

func (e EntityIDMerkleValueVersion) Export() *EntityIDMerkleValueVersionInternal__ {
	return ((*EntityIDMerkleValueVersionInternal__)(&e))
}

type EntityIDMerkleValue struct {
	V     EntityIDMerkleValueVersion
	F_1__ *lib.EntityID `json:"f1,omitempty"`
}

type EntityIDMerkleValueInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        EntityIDMerkleValueVersion
	Switch__ EntityIDMerkleValueInternalSwitch__
}

type EntityIDMerkleValueInternalSwitch__ struct {
	_struct struct{}                `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *lib.EntityIDInternal__ `codec:"1"`
}

func (e EntityIDMerkleValue) GetV() (ret EntityIDMerkleValueVersion, err error) {
	switch e.V {
	case EntityIDMerkleValueVersion_V1:
		if e.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return e.V, nil
}

func (e EntityIDMerkleValue) V1() lib.EntityID {
	if e.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if e.V != EntityIDMerkleValueVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", e.V))
	}
	return *e.F_1__
}

func NewEntityIDMerkleValueWithV1(v lib.EntityID) EntityIDMerkleValue {
	return EntityIDMerkleValue{
		V:     EntityIDMerkleValueVersion_V1,
		F_1__: &v,
	}
}

func (e EntityIDMerkleValueInternal__) Import() EntityIDMerkleValue {
	return EntityIDMerkleValue{
		V: e.V,
		F_1__: (func(x *lib.EntityIDInternal__) *lib.EntityID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(e.Switch__.F_1__),
	}
}

func (e EntityIDMerkleValue) Export() *EntityIDMerkleValueInternal__ {
	return &EntityIDMerkleValueInternal__{
		V: e.V,
		Switch__: EntityIDMerkleValueInternalSwitch__{
			F_1__: (func(x *lib.EntityID) *lib.EntityIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(e.F_1__),
		},
	}
}

func (e *EntityIDMerkleValue) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *EntityIDMerkleValue) Decode(dec rpc.Decoder) error {
	var tmp EntityIDMerkleValueInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

var EntityIDMerkleValueTypeUniqueID = rpc.TypeUniqueID(0xd3d21c7dc1d64ea1)

func (e *EntityIDMerkleValue) GetTypeUniqueID() rpc.TypeUniqueID {
	return EntityIDMerkleValueTypeUniqueID
}

func (e *EntityIDMerkleValue) Bytes() []byte { return nil }

type TreeLocationPair struct {
	Seqno lib.Seqno
	Loc   lib.TreeLocation
}

type TreeLocationPairInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seqno   *lib.SeqnoInternal__
	Loc     *lib.TreeLocationInternal__
}

func (t TreeLocationPairInternal__) Import() TreeLocationPair {
	return TreeLocationPair{
		Seqno: (func(x *lib.SeqnoInternal__) (ret lib.Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Seqno),
		Loc: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Loc),
	}
}

func (t TreeLocationPair) Export() *TreeLocationPairInternal__ {
	return &TreeLocationPairInternal__{
		Seqno: t.Seqno.Export(),
		Loc:   t.Loc.Export(),
	}
}

func (t *TreeLocationPair) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TreeLocationPair) Decode(dec rpc.Decoder) error {
	var tmp TreeLocationPairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TreeLocationPair) Bytes() []byte { return nil }

type YubiEncryptedManagementKey struct {
	Yk   lib.YubiID
	Box  lib.SecretBox
	Gen  lib.Generation
	Role lib.Role
}

type YubiEncryptedManagementKeyInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Yk      *lib.YubiIDInternal__
	Box     *lib.SecretBoxInternal__
	Gen     *lib.GenerationInternal__
	Role    *lib.RoleInternal__
}

func (y YubiEncryptedManagementKeyInternal__) Import() YubiEncryptedManagementKey {
	return YubiEncryptedManagementKey{
		Yk: (func(x *lib.YubiIDInternal__) (ret lib.YubiID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Yk),
		Box: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Box),
		Gen: (func(x *lib.GenerationInternal__) (ret lib.Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Gen),
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.Role),
	}
}

func (y YubiEncryptedManagementKey) Export() *YubiEncryptedManagementKeyInternal__ {
	return &YubiEncryptedManagementKeyInternal__{
		Yk:   y.Yk.Export(),
		Box:  y.Box.Export(),
		Gen:  y.Gen.Export(),
		Role: y.Role.Export(),
	}
}

func (y *YubiEncryptedManagementKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiEncryptedManagementKey) Decode(dec rpc.Decoder) error {
	var tmp YubiEncryptedManagementKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiEncryptedManagementKey) Bytes() []byte { return nil }

var UserProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x823f0899)

type PingArg struct {
}

type PingArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (p PingArgInternal__) Import() PingArg {
	return PingArg{}
}

func (p PingArg) Export() *PingArgInternal__ {
	return &PingArgInternal__{}
}

func (p *PingArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PingArg) Decode(dec rpc.Decoder) error {
	var tmp PingArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PingArg) Bytes() []byte { return nil }

type SetPassphraseArg struct {
	Key              lib.EntityID
	Salt             lib.PassphraseSalt
	SkwkBox          lib.SecretBox
	PassphraseBox    lib.PpePassphraseBox
	PukBox           *lib.PpePUKBox
	StretchVersion   lib.StretchVersion
	Link             lib.LinkOuter
	NextTreeLocation lib.TreeLocation
	UserSettingsLink *PostGenericLinkArg
}

type SetPassphraseArgInternal__ struct {
	_struct          struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Key              *lib.EntityIDInternal__
	Salt             *lib.PassphraseSaltInternal__
	SkwkBox          *lib.SecretBoxInternal__
	PassphraseBox    *lib.PpePassphraseBoxInternal__
	PukBox           *lib.PpePUKBoxInternal__
	StretchVersion   *lib.StretchVersionInternal__
	Link             *lib.LinkOuterInternal__
	NextTreeLocation *lib.TreeLocationInternal__
	UserSettingsLink *PostGenericLinkArgInternal__
}

func (s SetPassphraseArgInternal__) Import() SetPassphraseArg {
	return SetPassphraseArg{
		Key: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Key),
		Salt: (func(x *lib.PassphraseSaltInternal__) (ret lib.PassphraseSalt) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Salt),
		SkwkBox: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.SkwkBox),
		PassphraseBox: (func(x *lib.PpePassphraseBoxInternal__) (ret lib.PpePassphraseBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.PassphraseBox),
		PukBox: (func(x *lib.PpePUKBoxInternal__) *lib.PpePUKBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PpePUKBoxInternal__) (ret lib.PpePUKBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.PukBox),
		StretchVersion: (func(x *lib.StretchVersionInternal__) (ret lib.StretchVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.StretchVersion),
		Link: (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Link),
		NextTreeLocation: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.NextTreeLocation),
		UserSettingsLink: (func(x *PostGenericLinkArgInternal__) *PostGenericLinkArg {
			if x == nil {
				return nil
			}
			tmp := (func(x *PostGenericLinkArgInternal__) (ret PostGenericLinkArg) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.UserSettingsLink),
	}
}

func (s SetPassphraseArg) Export() *SetPassphraseArgInternal__ {
	return &SetPassphraseArgInternal__{
		Key:           s.Key.Export(),
		Salt:          s.Salt.Export(),
		SkwkBox:       s.SkwkBox.Export(),
		PassphraseBox: s.PassphraseBox.Export(),
		PukBox: (func(x *lib.PpePUKBox) *lib.PpePUKBoxInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.PukBox),
		StretchVersion:   s.StretchVersion.Export(),
		Link:             s.Link.Export(),
		NextTreeLocation: s.NextTreeLocation.Export(),
		UserSettingsLink: (func(x *PostGenericLinkArg) *PostGenericLinkArgInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.UserSettingsLink),
	}
}

func (s *SetPassphraseArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SetPassphraseArg) Decode(dec rpc.Decoder) error {
	var tmp SetPassphraseArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SetPassphraseArg) Bytes() []byte { return nil }

type ChangePassphraseArg struct {
	Key              lib.EntityID
	SkwkBox          lib.SecretBox
	PassphraseBox    lib.PpePassphraseBox
	PukBox           *lib.PpePUKBox
	StretchVersion   lib.StretchVersion
	PpGen            lib.PassphraseGeneration
	UserSettingsLink *PostGenericLinkArg
}

type ChangePassphraseArgInternal__ struct {
	_struct          struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Key              *lib.EntityIDInternal__
	SkwkBox          *lib.SecretBoxInternal__
	PassphraseBox    *lib.PpePassphraseBoxInternal__
	PukBox           *lib.PpePUKBoxInternal__
	StretchVersion   *lib.StretchVersionInternal__
	PpGen            *lib.PassphraseGenerationInternal__
	UserSettingsLink *PostGenericLinkArgInternal__
}

func (c ChangePassphraseArgInternal__) Import() ChangePassphraseArg {
	return ChangePassphraseArg{
		Key: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Key),
		SkwkBox: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.SkwkBox),
		PassphraseBox: (func(x *lib.PpePassphraseBoxInternal__) (ret lib.PpePassphraseBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.PassphraseBox),
		PukBox: (func(x *lib.PpePUKBoxInternal__) *lib.PpePUKBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PpePUKBoxInternal__) (ret lib.PpePUKBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.PukBox),
		StretchVersion: (func(x *lib.StretchVersionInternal__) (ret lib.StretchVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.StretchVersion),
		PpGen: (func(x *lib.PassphraseGenerationInternal__) (ret lib.PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.PpGen),
		UserSettingsLink: (func(x *PostGenericLinkArgInternal__) *PostGenericLinkArg {
			if x == nil {
				return nil
			}
			tmp := (func(x *PostGenericLinkArgInternal__) (ret PostGenericLinkArg) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.UserSettingsLink),
	}
}

func (c ChangePassphraseArg) Export() *ChangePassphraseArgInternal__ {
	return &ChangePassphraseArgInternal__{
		Key:           c.Key.Export(),
		SkwkBox:       c.SkwkBox.Export(),
		PassphraseBox: c.PassphraseBox.Export(),
		PukBox: (func(x *lib.PpePUKBox) *lib.PpePUKBoxInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.PukBox),
		StretchVersion: c.StretchVersion.Export(),
		PpGen:          c.PpGen.Export(),
		UserSettingsLink: (func(x *PostGenericLinkArg) *PostGenericLinkArgInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.UserSettingsLink),
	}
}

func (c *ChangePassphraseArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChangePassphraseArg) Decode(dec rpc.Decoder) error {
	var tmp ChangePassphraseArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChangePassphraseArg) Bytes() []byte { return nil }

type GetSaltArg struct {
}

type GetSaltArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetSaltArgInternal__) Import() GetSaltArg {
	return GetSaltArg{}
}

func (g GetSaltArg) Export() *GetSaltArgInternal__ {
	return &GetSaltArgInternal__{}
}

func (g *GetSaltArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetSaltArg) Decode(dec rpc.Decoder) error {
	var tmp GetSaltArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetSaltArg) Bytes() []byte { return nil }

type NextPassphraseGenerationArg struct {
}

type NextPassphraseGenerationArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (n NextPassphraseGenerationArgInternal__) Import() NextPassphraseGenerationArg {
	return NextPassphraseGenerationArg{}
}

func (n NextPassphraseGenerationArg) Export() *NextPassphraseGenerationArgInternal__ {
	return &NextPassphraseGenerationArgInternal__{}
}

func (n *NextPassphraseGenerationArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NextPassphraseGenerationArg) Decode(dec rpc.Decoder) error {
	var tmp NextPassphraseGenerationArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NextPassphraseGenerationArg) Bytes() []byte { return nil }

type StretchVersionArg struct {
}

type StretchVersionArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (s StretchVersionArgInternal__) Import() StretchVersionArg {
	return StretchVersionArg{}
}

func (s StretchVersionArg) Export() *StretchVersionArgInternal__ {
	return &StretchVersionArgInternal__{}
}

func (s *StretchVersionArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StretchVersionArg) Decode(dec rpc.Decoder) error {
	var tmp StretchVersionArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *StretchVersionArg) Bytes() []byte { return nil }

type ProvisionDeviceArg struct {
	Link             lib.LinkOuter
	PukBoxes         lib.SharedKeyBoxSet
	Dlnc             DeviceLabelNameAndCommitmentKey
	NextTreeLocation lib.TreeLocation
	SubkeyBox        *lib.Box
	SelfToken        lib.PermissionToken
	Hepks            lib.HEPKSet
	YubiPQhint       *lib.YubiSlotAndPQKeyID
}

type ProvisionDeviceArgInternal__ struct {
	_struct          struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Link             *lib.LinkOuterInternal__
	PukBoxes         *lib.SharedKeyBoxSetInternal__
	Dlnc             *DeviceLabelNameAndCommitmentKeyInternal__
	NextTreeLocation *lib.TreeLocationInternal__
	SubkeyBox        *lib.BoxInternal__
	SelfToken        *lib.PermissionTokenInternal__
	Hepks            *lib.HEPKSetInternal__
	Deprecated7      *struct{}
	Deprecated8      *struct{}
	Deprecated9      *struct{}
	Deprecated10     *struct{}
	Deprecated11     *struct{}
	Deprecated12     *struct{}
	Deprecated13     *struct{}
	YubiPQhint       *lib.YubiSlotAndPQKeyIDInternal__
}

func (p ProvisionDeviceArgInternal__) Import() ProvisionDeviceArg {
	return ProvisionDeviceArg{
		Link: (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Link),
		PukBoxes: (func(x *lib.SharedKeyBoxSetInternal__) (ret lib.SharedKeyBoxSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.PukBoxes),
		Dlnc: (func(x *DeviceLabelNameAndCommitmentKeyInternal__) (ret DeviceLabelNameAndCommitmentKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Dlnc),
		NextTreeLocation: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.NextTreeLocation),
		SubkeyBox: (func(x *lib.BoxInternal__) *lib.Box {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.BoxInternal__) (ret lib.Box) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.SubkeyBox),
		SelfToken: (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SelfToken),
		Hepks: (func(x *lib.HEPKSetInternal__) (ret lib.HEPKSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Hepks),
		YubiPQhint: (func(x *lib.YubiSlotAndPQKeyIDInternal__) *lib.YubiSlotAndPQKeyID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.YubiSlotAndPQKeyIDInternal__) (ret lib.YubiSlotAndPQKeyID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.YubiPQhint),
	}
}

func (p ProvisionDeviceArg) Export() *ProvisionDeviceArgInternal__ {
	return &ProvisionDeviceArgInternal__{
		Link:             p.Link.Export(),
		PukBoxes:         p.PukBoxes.Export(),
		Dlnc:             p.Dlnc.Export(),
		NextTreeLocation: p.NextTreeLocation.Export(),
		SubkeyBox: (func(x *lib.Box) *lib.BoxInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(p.SubkeyBox),
		SelfToken: p.SelfToken.Export(),
		Hepks:     p.Hepks.Export(),
		YubiPQhint: (func(x *lib.YubiSlotAndPQKeyID) *lib.YubiSlotAndPQKeyIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(p.YubiPQhint),
	}
}

func (p *ProvisionDeviceArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ProvisionDeviceArg) Decode(dec rpc.Decoder) error {
	var tmp ProvisionDeviceArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *ProvisionDeviceArg) Bytes() []byte { return nil }

type RevokeDeviceArg struct {
	Link             lib.LinkOuter
	PukBoxes         lib.SharedKeyBoxSet
	SeedChain        []lib.SeedChainBox
	NextTreeLocation lib.TreeLocation
	Ppa              *SetPassphraseAnnex
	Hepks            lib.HEPKSet
}

type RevokeDeviceArgInternal__ struct {
	_struct          struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Link             *lib.LinkOuterInternal__
	PukBoxes         *lib.SharedKeyBoxSetInternal__
	SeedChain        *[](*lib.SeedChainBoxInternal__)
	NextTreeLocation *lib.TreeLocationInternal__
	Ppa              *SetPassphraseAnnexInternal__
	Hepks            *lib.HEPKSetInternal__
}

func (r RevokeDeviceArgInternal__) Import() RevokeDeviceArg {
	return RevokeDeviceArg{
		Link: (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Link),
		PukBoxes: (func(x *lib.SharedKeyBoxSetInternal__) (ret lib.SharedKeyBoxSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.PukBoxes),
		SeedChain: (func(x *[](*lib.SeedChainBoxInternal__)) (ret []lib.SeedChainBox) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.SeedChainBox, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.SeedChainBoxInternal__) (ret lib.SeedChainBox) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(r.SeedChain),
		NextTreeLocation: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.NextTreeLocation),
		Ppa: (func(x *SetPassphraseAnnexInternal__) *SetPassphraseAnnex {
			if x == nil {
				return nil
			}
			tmp := (func(x *SetPassphraseAnnexInternal__) (ret SetPassphraseAnnex) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Ppa),
		Hepks: (func(x *lib.HEPKSetInternal__) (ret lib.HEPKSet) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Hepks),
	}
}

func (r RevokeDeviceArg) Export() *RevokeDeviceArgInternal__ {
	return &RevokeDeviceArgInternal__{
		Link:     r.Link.Export(),
		PukBoxes: r.PukBoxes.Export(),
		SeedChain: (func(x []lib.SeedChainBox) *[](*lib.SeedChainBoxInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.SeedChainBoxInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(r.SeedChain),
		NextTreeLocation: r.NextTreeLocation.Export(),
		Ppa: (func(x *SetPassphraseAnnex) *SetPassphraseAnnexInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Ppa),
		Hepks: r.Hepks.Export(),
	}
}

func (r *RevokeDeviceArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RevokeDeviceArg) Decode(dec rpc.Decoder) error {
	var tmp RevokeDeviceArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RevokeDeviceArg) Bytes() []byte { return nil }

type UserLoadUserChainArg struct {
	A LoadUserChainArg
}

type UserLoadUserChainArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	A       *LoadUserChainArgInternal__
}

func (u UserLoadUserChainArgInternal__) Import() UserLoadUserChainArg {
	return UserLoadUserChainArg{
		A: (func(x *LoadUserChainArgInternal__) (ret LoadUserChainArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.A),
	}
}

func (u UserLoadUserChainArg) Export() *UserLoadUserChainArgInternal__ {
	return &UserLoadUserChainArgInternal__{
		A: u.A.Export(),
	}
}

func (u *UserLoadUserChainArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserLoadUserChainArg) Decode(dec rpc.Decoder) error {
	var tmp UserLoadUserChainArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserLoadUserChainArg) Bytes() []byte { return nil }

type GrantLocalViewPermissionForUserArg struct {
	P GrantLocalViewPermissionPayload
}

type GrantLocalViewPermissionForUserArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	P       *GrantLocalViewPermissionPayloadInternal__
}

func (g GrantLocalViewPermissionForUserArgInternal__) Import() GrantLocalViewPermissionForUserArg {
	return GrantLocalViewPermissionForUserArg{
		P: (func(x *GrantLocalViewPermissionPayloadInternal__) (ret GrantLocalViewPermissionPayload) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.P),
	}
}

func (g GrantLocalViewPermissionForUserArg) Export() *GrantLocalViewPermissionForUserArgInternal__ {
	return &GrantLocalViewPermissionForUserArgInternal__{
		P: g.P.Export(),
	}
}

func (g *GrantLocalViewPermissionForUserArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GrantLocalViewPermissionForUserArg) Decode(dec rpc.Decoder) error {
	var tmp GrantLocalViewPermissionForUserArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GrantLocalViewPermissionForUserArg) Bytes() []byte { return nil }

type ChangeUsernameArg struct {
	UsernameUtf8 lib.NameUtf8
	Full         *ChangedUsernameFullUpdateArg
}

type ChangeUsernameArgInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	UsernameUtf8 *lib.NameUtf8Internal__
	Full         *ChangedUsernameFullUpdateArgInternal__
}

func (c ChangeUsernameArgInternal__) Import() ChangeUsernameArg {
	return ChangeUsernameArg{
		UsernameUtf8: (func(x *lib.NameUtf8Internal__) (ret lib.NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.UsernameUtf8),
		Full: (func(x *ChangedUsernameFullUpdateArgInternal__) *ChangedUsernameFullUpdateArg {
			if x == nil {
				return nil
			}
			tmp := (func(x *ChangedUsernameFullUpdateArgInternal__) (ret ChangedUsernameFullUpdateArg) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Full),
	}
}

func (c ChangeUsernameArg) Export() *ChangeUsernameArgInternal__ {
	return &ChangeUsernameArgInternal__{
		UsernameUtf8: c.UsernameUtf8.Export(),
		Full: (func(x *ChangedUsernameFullUpdateArg) *ChangedUsernameFullUpdateArgInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.Full),
	}
}

func (c *ChangeUsernameArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChangeUsernameArg) Decode(dec rpc.Decoder) error {
	var tmp ChangeUsernameArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ChangeUsernameArg) Bytes() []byte { return nil }

type ReserveUsernameForChangeArg struct {
	Un lib.Name
}

type ReserveUsernameForChangeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Un      *lib.NameInternal__
}

func (r ReserveUsernameForChangeArgInternal__) Import() ReserveUsernameForChangeArg {
	return ReserveUsernameForChangeArg{
		Un: (func(x *lib.NameInternal__) (ret lib.Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Un),
	}
}

func (r ReserveUsernameForChangeArg) Export() *ReserveUsernameForChangeArgInternal__ {
	return &ReserveUsernameForChangeArgInternal__{
		Un: r.Un.Export(),
	}
}

func (r *ReserveUsernameForChangeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *ReserveUsernameForChangeArg) Decode(dec rpc.Decoder) error {
	var tmp ReserveUsernameForChangeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *ReserveUsernameForChangeArg) Bytes() []byte { return nil }

type GetTreeLocationArg struct {
	Seqno lib.Seqno
}

type GetTreeLocationArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Seqno   *lib.SeqnoInternal__
}

func (g GetTreeLocationArgInternal__) Import() GetTreeLocationArg {
	return GetTreeLocationArg{
		Seqno: (func(x *lib.SeqnoInternal__) (ret lib.Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Seqno),
	}
}

func (g GetTreeLocationArg) Export() *GetTreeLocationArgInternal__ {
	return &GetTreeLocationArgInternal__{
		Seqno: g.Seqno.Export(),
	}
}

func (g *GetTreeLocationArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetTreeLocationArg) Decode(dec rpc.Decoder) error {
	var tmp GetTreeLocationArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetTreeLocationArg) Bytes() []byte { return nil }

type GetPUKForRoleArg struct {
	Role              lib.Role
	TargetPublicKeyId lib.EntityID
}

type GetPUKForRoleArgInternal__ struct {
	_struct           struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Role              *lib.RoleInternal__
	TargetPublicKeyId *lib.EntityIDInternal__
}

func (g GetPUKForRoleArgInternal__) Import() GetPUKForRoleArg {
	return GetPUKForRoleArg{
		Role: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Role),
		TargetPublicKeyId: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.TargetPublicKeyId),
	}
}

func (g GetPUKForRoleArg) Export() *GetPUKForRoleArgInternal__ {
	return &GetPUKForRoleArgInternal__{
		Role:              g.Role.Export(),
		TargetPublicKeyId: g.TargetPublicKeyId.Export(),
	}
}

func (g *GetPUKForRoleArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetPUKForRoleArg) Decode(dec rpc.Decoder) error {
	var tmp GetPUKForRoleArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetPUKForRoleArg) Bytes() []byte { return nil }

type GetPpeParcelArg struct {
}

type GetPpeParcelArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetPpeParcelArgInternal__) Import() GetPpeParcelArg {
	return GetPpeParcelArg{}
}

func (g GetPpeParcelArg) Export() *GetPpeParcelArgInternal__ {
	return &GetPpeParcelArgInternal__{}
}

func (g *GetPpeParcelArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetPpeParcelArg) Decode(dec rpc.Decoder) error {
	var tmp GetPpeParcelArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetPpeParcelArg) Bytes() []byte { return nil }

type PostGenericLinkArg struct {
	Link             lib.LinkOuter
	NextTreeLocation lib.TreeLocation
}

type PostGenericLinkArgInternal__ struct {
	_struct          struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Link             *lib.LinkOuterInternal__
	NextTreeLocation *lib.TreeLocationInternal__
}

func (p PostGenericLinkArgInternal__) Import() PostGenericLinkArg {
	return PostGenericLinkArg{
		Link: (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Link),
		NextTreeLocation: (func(x *lib.TreeLocationInternal__) (ret lib.TreeLocation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.NextTreeLocation),
	}
}

func (p PostGenericLinkArg) Export() *PostGenericLinkArgInternal__ {
	return &PostGenericLinkArgInternal__{
		Link:             p.Link.Export(),
		NextTreeLocation: p.NextTreeLocation.Export(),
	}
}

func (p *PostGenericLinkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PostGenericLinkArg) Decode(dec rpc.Decoder) error {
	var tmp PostGenericLinkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PostGenericLinkArg) Bytes() []byte { return nil }

type LoadGenericChainArg struct {
	Eid   lib.EntityID
	Typ   lib.ChainType
	Start lib.Seqno
}

type LoadGenericChainArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Eid     *lib.EntityIDInternal__
	Typ     *lib.ChainTypeInternal__
	Start   *lib.SeqnoInternal__
}

func (l LoadGenericChainArgInternal__) Import() LoadGenericChainArg {
	return LoadGenericChainArg{
		Eid: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Eid),
		Typ: (func(x *lib.ChainTypeInternal__) (ret lib.ChainType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Typ),
		Start: (func(x *lib.SeqnoInternal__) (ret lib.Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Start),
	}
}

func (l LoadGenericChainArg) Export() *LoadGenericChainArgInternal__ {
	return &LoadGenericChainArgInternal__{
		Eid:   l.Eid.Export(),
		Typ:   l.Typ.Export(),
		Start: l.Start.Export(),
	}
}

func (l *LoadGenericChainArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LoadGenericChainArg) Decode(dec rpc.Decoder) error {
	var tmp LoadGenericChainArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LoadGenericChainArg) Bytes() []byte { return nil }

type GrantRemoteViewPermissionForUserArg struct {
	P GrantRemoteViewPermissionPayload
}

type GrantRemoteViewPermissionForUserArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	P       *GrantRemoteViewPermissionPayloadInternal__
}

func (g GrantRemoteViewPermissionForUserArgInternal__) Import() GrantRemoteViewPermissionForUserArg {
	return GrantRemoteViewPermissionForUserArg{
		P: (func(x *GrantRemoteViewPermissionPayloadInternal__) (ret GrantRemoteViewPermissionPayload) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.P),
	}
}

func (g GrantRemoteViewPermissionForUserArg) Export() *GrantRemoteViewPermissionForUserArgInternal__ {
	return &GrantRemoteViewPermissionForUserArgInternal__{
		P: g.P.Export(),
	}
}

func (g *GrantRemoteViewPermissionForUserArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GrantRemoteViewPermissionForUserArg) Decode(dec rpc.Decoder) error {
	var tmp GrantRemoteViewPermissionForUserArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GrantRemoteViewPermissionForUserArg) Bytes() []byte { return nil }

type GetTeamListServerTrustArg struct {
}

type GetTeamListServerTrustArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetTeamListServerTrustArgInternal__) Import() GetTeamListServerTrustArg {
	return GetTeamListServerTrustArg{}
}

func (g GetTeamListServerTrustArg) Export() *GetTeamListServerTrustArgInternal__ {
	return &GetTeamListServerTrustArgInternal__{}
}

func (g *GetTeamListServerTrustArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetTeamListServerTrustArg) Decode(dec rpc.Decoder) error {
	var tmp GetTeamListServerTrustArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetTeamListServerTrustArg) Bytes() []byte { return nil }

type AssertPQKeyNotInUseArg struct {
	PqKey lib.YubiPQKeyID
}

type AssertPQKeyNotInUseArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	PqKey   *lib.YubiPQKeyIDInternal__
}

func (a AssertPQKeyNotInUseArgInternal__) Import() AssertPQKeyNotInUseArg {
	return AssertPQKeyNotInUseArg{
		PqKey: (func(x *lib.YubiPQKeyIDInternal__) (ret lib.YubiPQKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(a.PqKey),
	}
}

func (a AssertPQKeyNotInUseArg) Export() *AssertPQKeyNotInUseArgInternal__ {
	return &AssertPQKeyNotInUseArgInternal__{
		PqKey: a.PqKey.Export(),
	}
}

func (a *AssertPQKeyNotInUseArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AssertPQKeyNotInUseArg) Decode(dec rpc.Decoder) error {
	var tmp AssertPQKeyNotInUseArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a *AssertPQKeyNotInUseArg) Bytes() []byte { return nil }

type NewWebAdminPanelURLArg struct {
}

type NewWebAdminPanelURLArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (n NewWebAdminPanelURLArgInternal__) Import() NewWebAdminPanelURLArg {
	return NewWebAdminPanelURLArg{}
}

func (n NewWebAdminPanelURLArg) Export() *NewWebAdminPanelURLArgInternal__ {
	return &NewWebAdminPanelURLArgInternal__{}
}

func (n *NewWebAdminPanelURLArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NewWebAdminPanelURLArg) Decode(dec rpc.Decoder) error {
	var tmp NewWebAdminPanelURLArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NewWebAdminPanelURLArg) Bytes() []byte { return nil }

type CheckURLArg struct {
	Url lib.URLString
}

type CheckURLArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Url     *lib.URLStringInternal__
}

func (c CheckURLArgInternal__) Import() CheckURLArg {
	return CheckURLArg{
		Url: (func(x *lib.URLStringInternal__) (ret lib.URLString) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Url),
	}
}

func (c CheckURLArg) Export() *CheckURLArgInternal__ {
	return &CheckURLArgInternal__{
		Url: c.Url.Export(),
	}
}

func (c *CheckURLArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CheckURLArg) Decode(dec rpc.Decoder) error {
	var tmp CheckURLArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CheckURLArg) Bytes() []byte { return nil }

type UserResolveUsernameArg struct {
	A ResolveUsernameArg
}

type UserResolveUsernameArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	A       *ResolveUsernameArgInternal__
}

func (u UserResolveUsernameArgInternal__) Import() UserResolveUsernameArg {
	return UserResolveUsernameArg{
		A: (func(x *ResolveUsernameArgInternal__) (ret ResolveUsernameArg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.A),
	}
}

func (u UserResolveUsernameArg) Export() *UserResolveUsernameArgInternal__ {
	return &UserResolveUsernameArgInternal__{
		A: u.A.Export(),
	}
}

func (u *UserResolveUsernameArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserResolveUsernameArg) Decode(dec rpc.Decoder) error {
	var tmp UserResolveUsernameArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UserResolveUsernameArg) Bytes() []byte { return nil }

type GetHostConfigArg struct {
}

type GetHostConfigArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetHostConfigArgInternal__) Import() GetHostConfigArg {
	return GetHostConfigArg{}
}

func (g GetHostConfigArg) Export() *GetHostConfigArgInternal__ {
	return &GetHostConfigArgInternal__{}
}

func (g *GetHostConfigArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetHostConfigArg) Decode(dec rpc.Decoder) error {
	var tmp GetHostConfigArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetHostConfigArg) Bytes() []byte { return nil }

type GetDeviceNagArg struct {
}

type GetDeviceNagArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetDeviceNagArgInternal__) Import() GetDeviceNagArg {
	return GetDeviceNagArg{}
}

func (g GetDeviceNagArg) Export() *GetDeviceNagArgInternal__ {
	return &GetDeviceNagArgInternal__{}
}

func (g *GetDeviceNagArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetDeviceNagArg) Decode(dec rpc.Decoder) error {
	var tmp GetDeviceNagArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetDeviceNagArg) Bytes() []byte { return nil }

type ClearDeviceNagArg struct {
	Cleared bool
}

type ClearDeviceNagArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cleared *bool
}

func (c ClearDeviceNagArgInternal__) Import() ClearDeviceNagArg {
	return ClearDeviceNagArg{
		Cleared: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Cleared),
	}
}

func (c ClearDeviceNagArg) Export() *ClearDeviceNagArgInternal__ {
	return &ClearDeviceNagArgInternal__{
		Cleared: &c.Cleared,
	}
}

func (c *ClearDeviceNagArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClearDeviceNagArg) Decode(dec rpc.Decoder) error {
	var tmp ClearDeviceNagArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClearDeviceNagArg) Bytes() []byte { return nil }

type PutYubiManagementKeyArg struct {
	Ymk YubiEncryptedManagementKey
}

type PutYubiManagementKeyArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ymk     *YubiEncryptedManagementKeyInternal__
}

func (p PutYubiManagementKeyArgInternal__) Import() PutYubiManagementKeyArg {
	return PutYubiManagementKeyArg{
		Ymk: (func(x *YubiEncryptedManagementKeyInternal__) (ret YubiEncryptedManagementKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Ymk),
	}
}

func (p PutYubiManagementKeyArg) Export() *PutYubiManagementKeyArgInternal__ {
	return &PutYubiManagementKeyArgInternal__{
		Ymk: p.Ymk.Export(),
	}
}

func (p *PutYubiManagementKeyArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PutYubiManagementKeyArg) Decode(dec rpc.Decoder) error {
	var tmp PutYubiManagementKeyArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PutYubiManagementKeyArg) Bytes() []byte { return nil }

type GetYubiManagementKeyArg struct {
	Yk lib.YubiID
}

type GetYubiManagementKeyArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Yk      *lib.YubiIDInternal__
}

func (g GetYubiManagementKeyArgInternal__) Import() GetYubiManagementKeyArg {
	return GetYubiManagementKeyArg{
		Yk: (func(x *lib.YubiIDInternal__) (ret lib.YubiID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Yk),
	}
}

func (g GetYubiManagementKeyArg) Export() *GetYubiManagementKeyArgInternal__ {
	return &GetYubiManagementKeyArgInternal__{
		Yk: g.Yk.Export(),
	}
}

func (g *GetYubiManagementKeyArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetYubiManagementKeyArg) Decode(dec rpc.Decoder) error {
	var tmp GetYubiManagementKeyArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetYubiManagementKeyArg) Bytes() []byte { return nil }

type GetAllYubiManagementKeysArg struct {
}

type GetAllYubiManagementKeysArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
}

func (g GetAllYubiManagementKeysArgInternal__) Import() GetAllYubiManagementKeysArg {
	return GetAllYubiManagementKeysArg{}
}

func (g GetAllYubiManagementKeysArg) Export() *GetAllYubiManagementKeysArgInternal__ {
	return &GetAllYubiManagementKeysArgInternal__{}
}

func (g *GetAllYubiManagementKeysArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetAllYubiManagementKeysArg) Decode(dec rpc.Decoder) error {
	var tmp GetAllYubiManagementKeysArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetAllYubiManagementKeysArg) Bytes() []byte { return nil }

type UserInterface interface {
	Ping(context.Context) (lib.UID, error)
	SetPassphrase(context.Context, SetPassphraseArg) error
	ChangePassphrase(context.Context, ChangePassphraseArg) error
	GetSalt(context.Context) (lib.PassphraseSalt, error)
	NextPassphraseGeneration(context.Context) (lib.PassphraseGeneration, error)
	StretchVersion(context.Context) (lib.StretchVersion, error)
	ProvisionDevice(context.Context, ProvisionDeviceArg) error
	RevokeDevice(context.Context, RevokeDeviceArg) error
	LoadUserChain(context.Context, LoadUserChainArg) (UserChain, error)
	GrantLocalViewPermissionForUser(context.Context, GrantLocalViewPermissionPayload) (lib.PermissionToken, error)
	ChangeUsername(context.Context, ChangeUsernameArg) error
	ReserveUsernameForChange(context.Context, lib.Name) (ReserveNameRes, error)
	GetTreeLocation(context.Context, lib.Seqno) (lib.TreeLocation, error)
	GetPUKForRole(context.Context, GetPUKForRoleArg) (lib.SharedKeyParcel, error)
	GetPpeParcel(context.Context) (lib.PpeParcel, error)
	PostGenericLink(context.Context, PostGenericLinkArg) error
	LoadGenericChain(context.Context, LoadGenericChainArg) (GenericChain, error)
	GrantRemoteViewPermissionForUser(context.Context, GrantRemoteViewPermissionPayload) (lib.PermissionToken, error)
	GetTeamListServerTrust(context.Context) (LocalTeamList, error)
	AssertPQKeyNotInUse(context.Context, lib.YubiPQKeyID) error
	NewWebAdminPanelURL(context.Context) (lib.URLString, error)
	CheckURL(context.Context, lib.URLString) error
	ResolveUsername(context.Context, ResolveUsernameArg) (lib.UID, error)
	GetHostConfig(context.Context) (lib.HostConfig, error)
	GetDeviceNag(context.Context) (lib.DeviceNagInfo, error)
	ClearDeviceNag(context.Context, bool) error
	PutYubiManagementKey(context.Context, YubiEncryptedManagementKey) error
	GetYubiManagementKey(context.Context, lib.YubiID) (YubiEncryptedManagementKey, error)
	GetAllYubiManagementKeys(context.Context) ([]YubiEncryptedManagementKey, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error

	MakeResHeader() lib.Header
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
		return nil, errors.New("Error converting to internal type in UnwrapError")
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
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c UserClient) Ping(ctx context.Context) (res lib.UID, err error) {
	var arg PingArg
	warg := &rpc.DataWrap[lib.Header, *PingArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.UIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 0, "User.ping"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) SetPassphrase(ctx context.Context, arg SetPassphraseArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *SetPassphraseArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 1, "User.setPassphrase"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) ChangePassphrase(ctx context.Context, arg ChangePassphraseArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *ChangePassphraseArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 2, "User.changePassphrase"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GetSalt(ctx context.Context) (res lib.PassphraseSalt, err error) {
	var arg GetSaltArg
	warg := &rpc.DataWrap[lib.Header, *GetSaltArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.PassphraseSaltInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 3, "User.getSalt"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) NextPassphraseGeneration(ctx context.Context) (res lib.PassphraseGeneration, err error) {
	var arg NextPassphraseGenerationArg
	warg := &rpc.DataWrap[lib.Header, *NextPassphraseGenerationArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.PassphraseGenerationInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 4, "User.nextPassphraseGeneration"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) StretchVersion(ctx context.Context) (res lib.StretchVersion, err error) {
	var arg StretchVersionArg
	warg := &rpc.DataWrap[lib.Header, *StretchVersionArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.StretchVersionInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 5, "User.stretchVersion"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) ProvisionDevice(ctx context.Context, arg ProvisionDeviceArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *ProvisionDeviceArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 6, "User.provisionDevice"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) RevokeDevice(ctx context.Context, arg RevokeDeviceArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *RevokeDeviceArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 7, "User.revokeDevice"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) LoadUserChain(ctx context.Context, a LoadUserChainArg) (res UserChain, err error) {
	arg := UserLoadUserChainArg{
		A: a,
	}
	warg := &rpc.DataWrap[lib.Header, *UserLoadUserChainArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, UserChainInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 9, "User.loadUserChain"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GrantLocalViewPermissionForUser(ctx context.Context, p GrantLocalViewPermissionPayload) (res lib.PermissionToken, err error) {
	arg := GrantLocalViewPermissionForUserArg{
		P: p,
	}
	warg := &rpc.DataWrap[lib.Header, *GrantLocalViewPermissionForUserArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.PermissionTokenInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 10, "User.grantLocalViewPermissionForUser"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) ChangeUsername(ctx context.Context, arg ChangeUsernameArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *ChangeUsernameArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 11, "User.changeUsername"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) ReserveUsernameForChange(ctx context.Context, un lib.Name) (res ReserveNameRes, err error) {
	arg := ReserveUsernameForChangeArg{
		Un: un,
	}
	warg := &rpc.DataWrap[lib.Header, *ReserveUsernameForChangeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, ReserveNameResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 12, "User.reserveUsernameForChange"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GetTreeLocation(ctx context.Context, seqno lib.Seqno) (res lib.TreeLocation, err error) {
	arg := GetTreeLocationArg{
		Seqno: seqno,
	}
	warg := &rpc.DataWrap[lib.Header, *GetTreeLocationArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.TreeLocationInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 13, "User.getTreeLocation"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GetPUKForRole(ctx context.Context, arg GetPUKForRoleArg) (res lib.SharedKeyParcel, err error) {
	warg := &rpc.DataWrap[lib.Header, *GetPUKForRoleArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.SharedKeyParcelInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 14, "User.getPUKForRole"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GetPpeParcel(ctx context.Context) (res lib.PpeParcel, err error) {
	var arg GetPpeParcelArg
	warg := &rpc.DataWrap[lib.Header, *GetPpeParcelArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.PpeParcelInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 15, "User.getPpeParcel"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) PostGenericLink(ctx context.Context, arg PostGenericLinkArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *PostGenericLinkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 16, "User.postGenericLink"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) LoadGenericChain(ctx context.Context, arg LoadGenericChainArg) (res GenericChain, err error) {
	warg := &rpc.DataWrap[lib.Header, *LoadGenericChainArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, GenericChainInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 17, "User.loadGenericChain"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GrantRemoteViewPermissionForUser(ctx context.Context, p GrantRemoteViewPermissionPayload) (res lib.PermissionToken, err error) {
	arg := GrantRemoteViewPermissionForUserArg{
		P: p,
	}
	warg := &rpc.DataWrap[lib.Header, *GrantRemoteViewPermissionForUserArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.PermissionTokenInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 18, "User.grantRemoteViewPermissionForUser"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GetTeamListServerTrust(ctx context.Context) (res LocalTeamList, err error) {
	var arg GetTeamListServerTrustArg
	warg := &rpc.DataWrap[lib.Header, *GetTeamListServerTrustArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, LocalTeamListInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 19, "User.getTeamListServerTrust"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) AssertPQKeyNotInUse(ctx context.Context, pqKey lib.YubiPQKeyID) (err error) {
	arg := AssertPQKeyNotInUseArg{
		PqKey: pqKey,
	}
	warg := &rpc.DataWrap[lib.Header, *AssertPQKeyNotInUseArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 20, "User.assertPQKeyNotInUse"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) NewWebAdminPanelURL(ctx context.Context) (res lib.URLString, err error) {
	var arg NewWebAdminPanelURLArg
	warg := &rpc.DataWrap[lib.Header, *NewWebAdminPanelURLArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.URLStringInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 21, "User.newWebAdminPanelURL"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) CheckURL(ctx context.Context, url lib.URLString) (err error) {
	arg := CheckURLArg{
		Url: url,
	}
	warg := &rpc.DataWrap[lib.Header, *CheckURLArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 22, "User.checkURL"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) ResolveUsername(ctx context.Context, a ResolveUsernameArg) (res lib.UID, err error) {
	arg := UserResolveUsernameArg{
		A: a,
	}
	warg := &rpc.DataWrap[lib.Header, *UserResolveUsernameArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.UIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 23, "User.resolveUsername"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GetHostConfig(ctx context.Context) (res lib.HostConfig, err error) {
	var arg GetHostConfigArg
	warg := &rpc.DataWrap[lib.Header, *GetHostConfigArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.HostConfigInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 24, "User.getHostConfig"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GetDeviceNag(ctx context.Context) (res lib.DeviceNagInfo, err error) {
	var arg GetDeviceNagArg
	warg := &rpc.DataWrap[lib.Header, *GetDeviceNagArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.DeviceNagInfoInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 25, "User.getDeviceNag"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) ClearDeviceNag(ctx context.Context, cleared bool) (err error) {
	arg := ClearDeviceNagArg{
		Cleared: cleared,
	}
	warg := &rpc.DataWrap[lib.Header, *ClearDeviceNagArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 26, "User.clearDeviceNag"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) PutYubiManagementKey(ctx context.Context, ymk YubiEncryptedManagementKey) (err error) {
	arg := PutYubiManagementKeyArg{
		Ymk: ymk,
	}
	warg := &rpc.DataWrap[lib.Header, *PutYubiManagementKeyArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 27, "User.putYubiManagementKey"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GetYubiManagementKey(ctx context.Context, yk lib.YubiID) (res YubiEncryptedManagementKey, err error) {
	arg := GetYubiManagementKeyArg{
		Yk: yk,
	}
	warg := &rpc.DataWrap[lib.Header, *GetYubiManagementKeyArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, YubiEncryptedManagementKeyInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 28, "User.getYubiManagementKey"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c UserClient) GetAllYubiManagementKeys(ctx context.Context) (res []YubiEncryptedManagementKey, err error) {
	var arg GetAllYubiManagementKeysArg
	warg := &rpc.DataWrap[lib.Header, *GetAllYubiManagementKeysArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, [](*YubiEncryptedManagementKeyInternal__)]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(UserProtocolID, 29, "User.getAllYubiManagementKeys"), warg, &tmp, 0*time.Millisecond, userErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = (func(x *[](*YubiEncryptedManagementKeyInternal__)) (ret []YubiEncryptedManagementKey) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]YubiEncryptedManagementKey, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *YubiEncryptedManagementKeyInternal__) (ret YubiEncryptedManagementKey) {
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

func UserProtocol(i UserInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "User",
		ID:   UserProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *PingArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *PingArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *PingArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.Ping(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.UIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "ping",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *SetPassphraseArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *SetPassphraseArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *SetPassphraseArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SetPassphrase(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "setPassphrase",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChangePassphraseArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChangePassphraseArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChangePassphraseArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ChangePassphrase(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "changePassphrase",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetSaltArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetSaltArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetSaltArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetSalt(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.PassphraseSaltInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getSalt",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *NextPassphraseGenerationArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *NextPassphraseGenerationArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *NextPassphraseGenerationArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.NextPassphraseGeneration(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.PassphraseGenerationInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "nextPassphraseGeneration",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *StretchVersionArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *StretchVersionArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *StretchVersionArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.StretchVersion(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.StretchVersionInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "stretchVersion",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ProvisionDeviceArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ProvisionDeviceArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ProvisionDeviceArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ProvisionDevice(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "provisionDevice",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *RevokeDeviceArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *RevokeDeviceArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *RevokeDeviceArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.RevokeDevice(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "revokeDevice",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *UserLoadUserChainArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *UserLoadUserChainArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *UserLoadUserChainArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.LoadUserChain(ctx, (typedArg.Import()).A)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *UserChainInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loadUserChain",
			},
			10: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GrantLocalViewPermissionForUserArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GrantLocalViewPermissionForUserArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GrantLocalViewPermissionForUserArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GrantLocalViewPermissionForUser(ctx, (typedArg.Import()).P)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.PermissionTokenInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "grantLocalViewPermissionForUser",
			},
			11: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ChangeUsernameArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ChangeUsernameArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ChangeUsernameArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ChangeUsername(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "changeUsername",
			},
			12: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ReserveUsernameForChangeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ReserveUsernameForChangeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ReserveUsernameForChangeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ReserveUsernameForChange(ctx, (typedArg.Import()).Un)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *ReserveNameResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "reserveUsernameForChange",
			},
			13: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetTreeLocationArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetTreeLocationArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetTreeLocationArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetTreeLocation(ctx, (typedArg.Import()).Seqno)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.TreeLocationInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getTreeLocation",
			},
			14: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetPUKForRoleArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetPUKForRoleArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetPUKForRoleArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetPUKForRole(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.SharedKeyParcelInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getPUKForRole",
			},
			15: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetPpeParcelArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetPpeParcelArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetPpeParcelArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetPpeParcel(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.PpeParcelInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getPpeParcel",
			},
			16: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *PostGenericLinkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *PostGenericLinkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *PostGenericLinkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.PostGenericLink(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "postGenericLink",
			},
			17: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *LoadGenericChainArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *LoadGenericChainArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *LoadGenericChainArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.LoadGenericChain(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *GenericChainInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "loadGenericChain",
			},
			18: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GrantRemoteViewPermissionForUserArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GrantRemoteViewPermissionForUserArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GrantRemoteViewPermissionForUserArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GrantRemoteViewPermissionForUser(ctx, (typedArg.Import()).P)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.PermissionTokenInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "grantRemoteViewPermissionForUser",
			},
			19: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetTeamListServerTrustArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetTeamListServerTrustArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetTeamListServerTrustArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetTeamListServerTrust(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *LocalTeamListInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getTeamListServerTrust",
			},
			20: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *AssertPQKeyNotInUseArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *AssertPQKeyNotInUseArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *AssertPQKeyNotInUseArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.AssertPQKeyNotInUse(ctx, (typedArg.Import()).PqKey)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "assertPQKeyNotInUse",
			},
			21: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *NewWebAdminPanelURLArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *NewWebAdminPanelURLArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *NewWebAdminPanelURLArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.NewWebAdminPanelURL(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.URLStringInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "newWebAdminPanelURL",
			},
			22: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *CheckURLArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *CheckURLArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *CheckURLArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.CheckURL(ctx, (typedArg.Import()).Url)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "checkURL",
			},
			23: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *UserResolveUsernameArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *UserResolveUsernameArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *UserResolveUsernameArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ResolveUsername(ctx, (typedArg.Import()).A)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.UIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "resolveUsername",
			},
			24: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetHostConfigArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetHostConfigArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetHostConfigArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetHostConfig(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.HostConfigInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getHostConfig",
			},
			25: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetDeviceNagArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetDeviceNagArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetDeviceNagArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetDeviceNag(ctx)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.DeviceNagInfoInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getDeviceNag",
			},
			26: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ClearDeviceNagArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ClearDeviceNagArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ClearDeviceNagArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ClearDeviceNag(ctx, (typedArg.Import()).Cleared)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clearDeviceNag",
			},
			27: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *PutYubiManagementKeyArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *PutYubiManagementKeyArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *PutYubiManagementKeyArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.PutYubiManagementKey(ctx, (typedArg.Import()).Ymk)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "putYubiManagementKey",
			},
			28: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetYubiManagementKeyArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetYubiManagementKeyArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetYubiManagementKeyArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetYubiManagementKey(ctx, (typedArg.Import()).Yk)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *YubiEncryptedManagementKeyInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getYubiManagementKey",
			},
			29: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetAllYubiManagementKeysArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetAllYubiManagementKeysArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetAllYubiManagementKeysArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						tmp, err := i.GetAllYubiManagementKeys(ctx)
						if err != nil {
							return nil, err
						}
						lst := (func(x []YubiEncryptedManagementKey) *[](*YubiEncryptedManagementKeyInternal__) {
							if len(x) == 0 {
								return nil
							}
							ret := make([](*YubiEncryptedManagementKeyInternal__), len(x))
							for k, v := range x {
								ret[k] = v.Export()
							}
							return &ret
						})(tmp)
						ret := rpc.DataWrap[lib.Header, [](*YubiEncryptedManagementKeyInternal__)]{
							Header: i.MakeResHeader(),
						}
						if lst != nil {
							ret.Data = *lst
						}
						return &ret, nil
					},
				},
				Name: "getAllYubiManagementKeys",
			},
		},
		WrapError: UserMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(GrantLocalViewPermissionPayloadTypeUniqueID)
	rpc.AddUnique(GrantRemoteViewPermissionPayloadTypeUniqueID)
	rpc.AddUnique(EntityIDMerkleValueTypeUniqueID)
	rpc.AddUnique(UserProtocolID)
}
