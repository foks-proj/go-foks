// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/ui.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type UISessionCtr uint64
type UISessionCtrInternal__ uint64

func (u UISessionCtr) Export() *UISessionCtrInternal__ {
	tmp := ((uint64)(u))
	return ((*UISessionCtrInternal__)(&tmp))
}
func (u UISessionCtrInternal__) Import() UISessionCtr {
	tmp := (uint64)(u)
	return UISessionCtr((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (u *UISessionCtr) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UISessionCtr) Decode(dec rpc.Decoder) error {
	var tmp UISessionCtrInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u UISessionCtr) Bytes() []byte {
	return nil
}

type UISessionID struct {
	Type UISessionType
	Ctr  UISessionCtr
}
type UISessionIDInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Type    *UISessionTypeInternal__
	Ctr     *UISessionCtrInternal__
}

func (u UISessionIDInternal__) Import() UISessionID {
	return UISessionID{
		Type: (func(x *UISessionTypeInternal__) (ret UISessionType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Type),
		Ctr: (func(x *UISessionCtrInternal__) (ret UISessionCtr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Ctr),
	}
}
func (u UISessionID) Export() *UISessionIDInternal__ {
	return &UISessionIDInternal__{
		Type: u.Type.Export(),
		Ctr:  u.Ctr.Export(),
	}
}
func (u *UISessionID) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UISessionID) Decode(dec rpc.Decoder) error {
	var tmp UISessionIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UISessionID) Bytes() []byte { return nil }

type UISessionType int

const (
	UISessionType_Signup        UISessionType = 1
	UISessionType_Provision     UISessionType = 2
	UISessionType_YubiProvision UISessionType = 3
	UISessionType_Assist        UISessionType = 4
	UISessionType_Switch        UISessionType = 5
	UISessionType_LoadBackup    UISessionType = 6
	UISessionType_YubiNew       UISessionType = 7
	UISessionType_SSOLogin      UISessionType = 8
	UISessionType_NewKeyWizard  UISessionType = 9
	UISessionType_YubiSPP       UISessionType = 10
)

var UISessionTypeMap = map[string]UISessionType{
	"Signup":        1,
	"Provision":     2,
	"YubiProvision": 3,
	"Assist":        4,
	"Switch":        5,
	"LoadBackup":    6,
	"YubiNew":       7,
	"SSOLogin":      8,
	"NewKeyWizard":  9,
	"YubiSPP":       10,
}
var UISessionTypeRevMap = map[UISessionType]string{
	1:  "Signup",
	2:  "Provision",
	3:  "YubiProvision",
	4:  "Assist",
	5:  "Switch",
	6:  "LoadBackup",
	7:  "YubiNew",
	8:  "SSOLogin",
	9:  "NewKeyWizard",
	10: "YubiSPP",
}

type UISessionTypeInternal__ UISessionType

func (u UISessionTypeInternal__) Import() UISessionType {
	return UISessionType(u)
}
func (u UISessionType) Export() *UISessionTypeInternal__ {
	return ((*UISessionTypeInternal__)(&u))
}
