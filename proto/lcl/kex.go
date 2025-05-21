// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/kex.snowp

package lcl

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type KexDerivationType int

const (
	KexDerivationType_SessionID    KexDerivationType = 0
	KexDerivationType_SecretBoxKey KexDerivationType = 1
)

var KexDerivationTypeMap = map[string]KexDerivationType{
	"SessionID":    0,
	"SecretBoxKey": 1,
}
var KexDerivationTypeRevMap = map[KexDerivationType]string{
	0: "SessionID",
	1: "SecretBoxKey",
}

type KexDerivationTypeInternal__ KexDerivationType

func (k KexDerivationTypeInternal__) Import() KexDerivationType {
	return KexDerivationType(k)
}
func (k KexDerivationType) Export() *KexDerivationTypeInternal__ {
	return ((*KexDerivationTypeInternal__)(&k))
}

type KexKeyDerivation struct {
	T KexDerivationType
}
type KexKeyDerivationInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        KexDerivationType
	Switch__ KexKeyDerivationInternalSwitch__
}
type KexKeyDerivationInternalSwitch__ struct {
	_struct struct{} `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
}

func (k KexKeyDerivation) GetT() (ret KexDerivationType, err error) {
	switch k.T {
	default:
		break
	}
	return k.T, nil
}
func NewKexKeyDerivationDefault(s KexDerivationType) KexKeyDerivation {
	return KexKeyDerivation{
		T: s,
	}
}
func (k KexKeyDerivationInternal__) Import() KexKeyDerivation {
	return KexKeyDerivation{
		T: k.T,
	}
}
func (k KexKeyDerivation) Export() *KexKeyDerivationInternal__ {
	return &KexKeyDerivationInternal__{
		T:        k.T,
		Switch__: KexKeyDerivationInternalSwitch__{},
	}
}
func (k *KexKeyDerivation) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexKeyDerivation) Decode(dec rpc.Decoder) error {
	var tmp KexKeyDerivationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KexKeyDerivationTypeUniqueID = rpc.TypeUniqueID(0x8d7bc7703f63ad64)

func (k *KexKeyDerivation) GetTypeUniqueID() rpc.TypeUniqueID {
	return KexKeyDerivationTypeUniqueID
}
func (k *KexKeyDerivation) Bytes() []byte { return nil }

type KexCleartext struct {
	SeesionID lib.KexSessionID
	Sender    lib.EntityID
	Seq       lib.KexSeqNo
	Msg       KexMsg
}
type KexCleartextInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SeesionID *lib.KexSessionIDInternal__
	Sender    *lib.EntityIDInternal__
	Seq       *lib.KexSeqNoInternal__
	Msg       *KexMsgInternal__
}

func (k KexCleartextInternal__) Import() KexCleartext {
	return KexCleartext{
		SeesionID: (func(x *lib.KexSessionIDInternal__) (ret lib.KexSessionID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.SeesionID),
		Sender: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Sender),
		Seq: (func(x *lib.KexSeqNoInternal__) (ret lib.KexSeqNo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Seq),
		Msg: (func(x *KexMsgInternal__) (ret KexMsg) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Msg),
	}
}
func (k KexCleartext) Export() *KexCleartextInternal__ {
	return &KexCleartextInternal__{
		SeesionID: k.SeesionID.Export(),
		Sender:    k.Sender.Export(),
		Seq:       k.Seq.Export(),
		Msg:       k.Msg.Export(),
	}
}
func (k *KexCleartext) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexCleartext) Decode(dec rpc.Decoder) error {
	var tmp KexCleartextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KexCleartextTypeUniqueID = rpc.TypeUniqueID(0xd2bce8263ea1dc0b)

func (k *KexCleartext) GetTypeUniqueID() rpc.TypeUniqueID {
	return KexCleartextTypeUniqueID
}
func (k *KexCleartext) Bytes() []byte { return nil }

type KexError struct {
	Status lib.Status
}
type KexErrorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Status  *lib.StatusInternal__
}

func (k KexErrorInternal__) Import() KexError {
	return KexError{
		Status: (func(x *lib.StatusInternal__) (ret lib.Status) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Status),
	}
}
func (k KexError) Export() *KexErrorInternal__ {
	return &KexErrorInternal__{
		Status: k.Status.Export(),
	}
}
func (k *KexError) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexError) Decode(dec rpc.Decoder) error {
	var tmp KexErrorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KexError) Bytes() []byte { return nil }

type KexMsgType int

const (
	KexMsgType_Error      KexMsgType = 0
	KexMsgType_Start      KexMsgType = 1
	KexMsgType_Hello      KexMsgType = 2
	KexMsgType_PleaseSign KexMsgType = 3
	KexMsgType_OkSigned   KexMsgType = 4
	KexMsgType_Done       KexMsgType = 5
)

var KexMsgTypeMap = map[string]KexMsgType{
	"Error":      0,
	"Start":      1,
	"Hello":      2,
	"PleaseSign": 3,
	"OkSigned":   4,
	"Done":       5,
}
var KexMsgTypeRevMap = map[KexMsgType]string{
	0: "Error",
	1: "Start",
	2: "Hello",
	3: "PleaseSign",
	4: "OkSigned",
	5: "Done",
}

type KexMsgTypeInternal__ KexMsgType

func (k KexMsgTypeInternal__) Import() KexMsgType {
	return KexMsgType(k)
}
func (k KexMsgType) Export() *KexMsgTypeInternal__ {
	return ((*KexMsgTypeInternal__)(&k))
}

type PleaseSign struct {
	Link lib.LinkOuter
	Ppe  *KexPPE
	Tok  lib.PermissionToken
}
type PleaseSignInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Link    *lib.LinkOuterInternal__
	Ppe     *KexPPEInternal__
	Tok     *lib.PermissionTokenInternal__
}

func (p PleaseSignInternal__) Import() PleaseSign {
	return PleaseSign{
		Link: (func(x *lib.LinkOuterInternal__) (ret lib.LinkOuter) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Link),
		Ppe: (func(x *KexPPEInternal__) *KexPPE {
			if x == nil {
				return nil
			}
			tmp := (func(x *KexPPEInternal__) (ret KexPPE) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Ppe),
		Tok: (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Tok),
	}
}
func (p PleaseSign) Export() *PleaseSignInternal__ {
	return &PleaseSignInternal__{
		Link: p.Link.Export(),
		Ppe: (func(x *KexPPE) *KexPPEInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(p.Ppe),
		Tok: p.Tok.Export(),
	}
}
func (p *PleaseSign) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PleaseSign) Decode(dec rpc.Decoder) error {
	var tmp PleaseSignInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PleaseSign) Bytes() []byte { return nil }

type OkSigned struct {
	Sig lib.Signature
}
type OkSignedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Sig     *lib.SignatureInternal__
}

func (o OkSignedInternal__) Import() OkSigned {
	return OkSigned{
		Sig: (func(x *lib.SignatureInternal__) (ret lib.Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(o.Sig),
	}
}
func (o OkSigned) Export() *OkSignedInternal__ {
	return &OkSignedInternal__{
		Sig: o.Sig.Export(),
	}
}
func (o *OkSigned) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OkSigned) Decode(dec rpc.Decoder) error {
	var tmp OkSignedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o *OkSigned) Bytes() []byte { return nil }

type HelloMsg struct {
	KeySuite lib.KeySuite
	Dln      lib.DeviceLabelAndName
}
type HelloMsgInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	KeySuite *lib.KeySuiteInternal__
	Dln      *lib.DeviceLabelAndNameInternal__
}

func (h HelloMsgInternal__) Import() HelloMsg {
	return HelloMsg{
		KeySuite: (func(x *lib.KeySuiteInternal__) (ret lib.KeySuite) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.KeySuite),
		Dln: (func(x *lib.DeviceLabelAndNameInternal__) (ret lib.DeviceLabelAndName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Dln),
	}
}
func (h HelloMsg) Export() *HelloMsgInternal__ {
	return &HelloMsgInternal__{
		KeySuite: h.KeySuite.Export(),
		Dln:      h.Dln.Export(),
	}
}
func (h *HelloMsg) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HelloMsg) Decode(dec rpc.Decoder) error {
	var tmp HelloMsgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HelloMsg) Bytes() []byte { return nil }

type KexMsg struct {
	T     KexMsgType
	F_0__ *KexError   `json:"f0,omitempty"`
	F_1__ *HelloMsg   `json:"f1,omitempty"`
	F_2__ *PleaseSign `json:"f2,omitempty"`
	F_3__ *OkSigned   `json:"f3,omitempty"`
}
type KexMsgInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        KexMsgType
	Switch__ KexMsgInternalSwitch__
}
type KexMsgInternalSwitch__ struct {
	_struct struct{}              `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *KexErrorInternal__   `codec:"0"`
	F_1__   *HelloMsgInternal__   `codec:"1"`
	F_2__   *PleaseSignInternal__ `codec:"2"`
	F_3__   *OkSignedInternal__   `codec:"3"`
}

func (k KexMsg) GetT() (ret KexMsgType, err error) {
	switch k.T {
	case KexMsgType_Error:
		if k.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case KexMsgType_Start, KexMsgType_Done:
		break
	case KexMsgType_Hello:
		if k.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case KexMsgType_PleaseSign:
		if k.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case KexMsgType_OkSigned:
		if k.F_3__ == nil {
			return ret, errors.New("unexpected nil case for F_3__")
		}
	}
	return k.T, nil
}
func (k KexMsg) Error() KexError {
	if k.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if k.T != KexMsgType_Error {
		panic(fmt.Sprintf("unexpected switch value (%v) when Error is called", k.T))
	}
	return *k.F_0__
}
func (k KexMsg) Hello() HelloMsg {
	if k.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if k.T != KexMsgType_Hello {
		panic(fmt.Sprintf("unexpected switch value (%v) when Hello is called", k.T))
	}
	return *k.F_1__
}
func (k KexMsg) Pleasesign() PleaseSign {
	if k.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if k.T != KexMsgType_PleaseSign {
		panic(fmt.Sprintf("unexpected switch value (%v) when Pleasesign is called", k.T))
	}
	return *k.F_2__
}
func (k KexMsg) Oksigned() OkSigned {
	if k.F_3__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if k.T != KexMsgType_OkSigned {
		panic(fmt.Sprintf("unexpected switch value (%v) when Oksigned is called", k.T))
	}
	return *k.F_3__
}
func NewKexMsgWithError(v KexError) KexMsg {
	return KexMsg{
		T:     KexMsgType_Error,
		F_0__: &v,
	}
}
func NewKexMsgWithStart() KexMsg {
	return KexMsg{
		T: KexMsgType_Start,
	}
}
func NewKexMsgWithDone() KexMsg {
	return KexMsg{
		T: KexMsgType_Done,
	}
}
func NewKexMsgWithHello(v HelloMsg) KexMsg {
	return KexMsg{
		T:     KexMsgType_Hello,
		F_1__: &v,
	}
}
func NewKexMsgWithPleasesign(v PleaseSign) KexMsg {
	return KexMsg{
		T:     KexMsgType_PleaseSign,
		F_2__: &v,
	}
}
func NewKexMsgWithOksigned(v OkSigned) KexMsg {
	return KexMsg{
		T:     KexMsgType_OkSigned,
		F_3__: &v,
	}
}
func (k KexMsgInternal__) Import() KexMsg {
	return KexMsg{
		T: k.T,
		F_0__: (func(x *KexErrorInternal__) *KexError {
			if x == nil {
				return nil
			}
			tmp := (func(x *KexErrorInternal__) (ret KexError) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_0__),
		F_1__: (func(x *HelloMsgInternal__) *HelloMsg {
			if x == nil {
				return nil
			}
			tmp := (func(x *HelloMsgInternal__) (ret HelloMsg) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_1__),
		F_2__: (func(x *PleaseSignInternal__) *PleaseSign {
			if x == nil {
				return nil
			}
			tmp := (func(x *PleaseSignInternal__) (ret PleaseSign) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_2__),
		F_3__: (func(x *OkSignedInternal__) *OkSigned {
			if x == nil {
				return nil
			}
			tmp := (func(x *OkSignedInternal__) (ret OkSigned) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_3__),
	}
}
func (k KexMsg) Export() *KexMsgInternal__ {
	return &KexMsgInternal__{
		T: k.T,
		Switch__: KexMsgInternalSwitch__{
			F_0__: (func(x *KexError) *KexErrorInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_0__),
			F_1__: (func(x *HelloMsg) *HelloMsgInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_1__),
			F_2__: (func(x *PleaseSign) *PleaseSignInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_2__),
			F_3__: (func(x *OkSigned) *OkSignedInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_3__),
		},
	}
}
func (k *KexMsg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexMsg) Decode(dec rpc.Decoder) error {
	var tmp KexMsgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KexMsgTypeUniqueID = rpc.TypeUniqueID(0x90ff590c87e01621)

func (k *KexMsg) GetTypeUniqueID() rpc.TypeUniqueID {
	return KexMsgTypeUniqueID
}
func (k *KexMsg) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(KexKeyDerivationTypeUniqueID)
	rpc.AddUnique(KexCleartextTypeUniqueID)
	rpc.AddUnique(KexMsgTypeUniqueID)
}
