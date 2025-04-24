// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/rem/invite.snowp

package rem

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type MultiUseInviteCode string
type MultiUseInviteCodeInternal__ string

func (m MultiUseInviteCode) Export() *MultiUseInviteCodeInternal__ {
	tmp := ((string)(m))
	return ((*MultiUseInviteCodeInternal__)(&tmp))
}

func (m MultiUseInviteCodeInternal__) Import() MultiUseInviteCode {
	tmp := (string)(m)
	return MultiUseInviteCode((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (m *MultiUseInviteCode) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MultiUseInviteCode) Decode(dec rpc.Decoder) error {
	var tmp MultiUseInviteCodeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MultiUseInviteCode) Bytes() []byte {
	return nil
}

type InviteCodeType int

const (
	InviteCodeType_None     InviteCodeType = 0
	InviteCodeType_Standard InviteCodeType = 1
	InviteCodeType_MultiUse InviteCodeType = 2
	InviteCodeType_SSO      InviteCodeType = 3
)

var InviteCodeTypeMap = map[string]InviteCodeType{
	"None":     0,
	"Standard": 1,
	"MultiUse": 2,
	"SSO":      3,
}

var InviteCodeTypeRevMap = map[InviteCodeType]string{
	0: "None",
	1: "Standard",
	2: "MultiUse",
	3: "SSO",
}

type InviteCodeTypeInternal__ InviteCodeType

func (i InviteCodeTypeInternal__) Import() InviteCodeType {
	return InviteCodeType(i)
}

func (i InviteCodeType) Export() *InviteCodeTypeInternal__ {
	return ((*InviteCodeTypeInternal__)(&i))
}

type InviteCode struct {
	T     InviteCodeType
	F_1__ *[]byte             `json:"f1,omitempty"`
	F_2__ *MultiUseInviteCode `json:"f2,omitempty"`
}

type InviteCodeInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        InviteCodeType
	Switch__ InviteCodeInternalSwitch__
}

type InviteCodeInternalSwitch__ struct {
	_struct struct{}                      `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *[]byte                       `codec:"1"`
	F_2__   *MultiUseInviteCodeInternal__ `codec:"2"`
}

func (i InviteCode) GetT() (ret InviteCodeType, err error) {
	switch i.T {
	default:
		break
	case InviteCodeType_Standard:
		if i.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case InviteCodeType_MultiUse:
		if i.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case InviteCodeType_SSO:
		break
	}
	return i.T, nil
}

func (i InviteCode) Standard() []byte {
	if i.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if i.T != InviteCodeType_Standard {
		panic(fmt.Sprintf("unexpected switch value (%v) when Standard is called", i.T))
	}
	return *i.F_1__
}

func (i InviteCode) Multiuse() MultiUseInviteCode {
	if i.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if i.T != InviteCodeType_MultiUse {
		panic(fmt.Sprintf("unexpected switch value (%v) when Multiuse is called", i.T))
	}
	return *i.F_2__
}

func NewInviteCodeDefault(s InviteCodeType) InviteCode {
	return InviteCode{
		T: s,
	}
}

func NewInviteCodeWithStandard(v []byte) InviteCode {
	return InviteCode{
		T:     InviteCodeType_Standard,
		F_1__: &v,
	}
}

func NewInviteCodeWithMultiuse(v MultiUseInviteCode) InviteCode {
	return InviteCode{
		T:     InviteCodeType_MultiUse,
		F_2__: &v,
	}
}

func NewInviteCodeWithSso() InviteCode {
	return InviteCode{
		T: InviteCodeType_SSO,
	}
}

func (i InviteCodeInternal__) Import() InviteCode {
	return InviteCode{
		T:     i.T,
		F_1__: i.Switch__.F_1__,
		F_2__: (func(x *MultiUseInviteCodeInternal__) *MultiUseInviteCode {
			if x == nil {
				return nil
			}
			tmp := (func(x *MultiUseInviteCodeInternal__) (ret MultiUseInviteCode) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(i.Switch__.F_2__),
	}
}

func (i InviteCode) Export() *InviteCodeInternal__ {
	return &InviteCodeInternal__{
		T: i.T,
		Switch__: InviteCodeInternalSwitch__{
			F_1__: i.F_1__,
			F_2__: (func(x *MultiUseInviteCode) *MultiUseInviteCodeInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(i.F_2__),
		},
	}
}

func (i *InviteCode) Encode(enc rpc.Encoder) error {
	return enc.Encode(i.Export())
}

func (i *InviteCode) Decode(dec rpc.Decoder) error {
	var tmp InviteCodeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*i = tmp.Import()
	return nil
}

func (i *InviteCode) Bytes() []byte { return nil }
