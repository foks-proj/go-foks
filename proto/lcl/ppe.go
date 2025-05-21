// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/ppe.snowp

package lcl

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type SKMWK lib.SecretBoxKey
type SKMWKInternal__ lib.SecretBoxKeyInternal__

func (s SKMWK) Export() *SKMWKInternal__ {
	tmp := ((lib.SecretBoxKey)(s))
	return ((*SKMWKInternal__)(tmp.Export()))
}
func (s SKMWKInternal__) Import() SKMWK {
	tmp := (lib.SecretBoxKeyInternal__)(s)
	return SKMWK((func(x *lib.SecretBoxKeyInternal__) (ret lib.SecretBoxKey) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (s *SKMWK) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SKMWK) Decode(dec rpc.Decoder) error {
	var tmp SKMWKInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SKMWK) Bytes() []byte {
	return ((lib.SecretBoxKey)(s)).Bytes()
}

type SKMWKList struct {
	Fqu  lib.FQUser
	Keys []SKMWK
}
type SKMWKListInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu     *lib.FQUserInternal__
	Keys    *[](*SKMWKInternal__)
}

func (s SKMWKListInternal__) Import() SKMWKList {
	return SKMWKList{
		Fqu: (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Fqu),
		Keys: (func(x *[](*SKMWKInternal__)) (ret []SKMWK) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SKMWK, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SKMWKInternal__) (ret SKMWK) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(s.Keys),
	}
}
func (s SKMWKList) Export() *SKMWKListInternal__ {
	return &SKMWKListInternal__{
		Fqu: s.Fqu.Export(),
		Keys: (func(x []SKMWK) *[](*SKMWKInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SKMWKInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(s.Keys),
	}
}
func (s *SKMWKList) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SKMWKList) Decode(dec rpc.Decoder) error {
	var tmp SKMWKListInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

var SKMWKListTypeUniqueID = rpc.TypeUniqueID(0x813191a3c2c88094)

func (s *SKMWKList) GetTypeUniqueID() rpc.TypeUniqueID {
	return SKMWKListTypeUniqueID
}
func (s *SKMWKList) Bytes() []byte { return nil }

type PpeSessionKey [32]byte
type PpeSessionKeyInternal__ [32]byte

func (p PpeSessionKey) Export() *PpeSessionKeyInternal__ {
	tmp := (([32]byte)(p))
	return ((*PpeSessionKeyInternal__)(&tmp))
}
func (p PpeSessionKeyInternal__) Import() PpeSessionKey {
	tmp := ([32]byte)(p)
	return PpeSessionKey((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *PpeSessionKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PpeSessionKey) Decode(dec rpc.Decoder) error {
	var tmp PpeSessionKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PpeSessionKey) Bytes() []byte {
	return (p)[:]
}

type PpePUKBoxPayload struct {
	Gen        lib.PassphraseGeneration
	Sesskey    PpeSessionKey
	Passphrase lib.HEPK
}
type PpePUKBoxPayloadInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Gen        *lib.PassphraseGenerationInternal__
	Sesskey    *PpeSessionKeyInternal__
	Passphrase *lib.HEPKInternal__
}

func (p PpePUKBoxPayloadInternal__) Import() PpePUKBoxPayload {
	return PpePUKBoxPayload{
		Gen: (func(x *lib.PassphraseGenerationInternal__) (ret lib.PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Gen),
		Sesskey: (func(x *PpeSessionKeyInternal__) (ret PpeSessionKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Sesskey),
		Passphrase: (func(x *lib.HEPKInternal__) (ret lib.HEPK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Passphrase),
	}
}
func (p PpePUKBoxPayload) Export() *PpePUKBoxPayloadInternal__ {
	return &PpePUKBoxPayloadInternal__{
		Gen:        p.Gen.Export(),
		Sesskey:    p.Sesskey.Export(),
		Passphrase: p.Passphrase.Export(),
	}
}
func (p *PpePUKBoxPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PpePUKBoxPayload) Decode(dec rpc.Decoder) error {
	var tmp PpePUKBoxPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

var PpePUKBoxPayloadTypeUniqueID = rpc.TypeUniqueID(0x82a769eb072624cd)

func (p *PpePUKBoxPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return PpePUKBoxPayloadTypeUniqueID
}
func (p *PpePUKBoxPayload) Bytes() []byte { return nil }

type PpePassphraseBoxPayload struct {
	Gen     lib.PassphraseGeneration
	Sesskey PpeSessionKey
}
type PpePassphraseBoxPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Gen     *lib.PassphraseGenerationInternal__
	Sesskey *PpeSessionKeyInternal__
}

func (p PpePassphraseBoxPayloadInternal__) Import() PpePassphraseBoxPayload {
	return PpePassphraseBoxPayload{
		Gen: (func(x *lib.PassphraseGenerationInternal__) (ret lib.PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Gen),
		Sesskey: (func(x *PpeSessionKeyInternal__) (ret PpeSessionKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Sesskey),
	}
}
func (p PpePassphraseBoxPayload) Export() *PpePassphraseBoxPayloadInternal__ {
	return &PpePassphraseBoxPayloadInternal__{
		Gen:     p.Gen.Export(),
		Sesskey: p.Sesskey.Export(),
	}
}
func (p *PpePassphraseBoxPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PpePassphraseBoxPayload) Decode(dec rpc.Decoder) error {
	var tmp PpePassphraseBoxPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

var PpePassphraseBoxPayloadTypeUniqueID = rpc.TypeUniqueID(0x978c22a7627d777b)

func (p *PpePassphraseBoxPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return PpePassphraseBoxPayloadTypeUniqueID
}
func (p *PpePassphraseBoxPayload) Bytes() []byte { return nil }

type RotatePPEWithPUK struct {
	PpGen         lib.PassphraseGeneration
	SkwkBox       lib.SecretBox
	PassphraseBox lib.PpePassphraseBox
	PukBox        lib.PpePUKBox
}
type RotatePPEWithPUKInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	PpGen         *lib.PassphraseGenerationInternal__
	SkwkBox       *lib.SecretBoxInternal__
	PassphraseBox *lib.PpePassphraseBoxInternal__
	PukBox        *lib.PpePUKBoxInternal__
}

func (r RotatePPEWithPUKInternal__) Import() RotatePPEWithPUK {
	return RotatePPEWithPUK{
		PpGen: (func(x *lib.PassphraseGenerationInternal__) (ret lib.PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.PpGen),
		SkwkBox: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.SkwkBox),
		PassphraseBox: (func(x *lib.PpePassphraseBoxInternal__) (ret lib.PpePassphraseBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.PassphraseBox),
		PukBox: (func(x *lib.PpePUKBoxInternal__) (ret lib.PpePUKBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.PukBox),
	}
}
func (r RotatePPEWithPUK) Export() *RotatePPEWithPUKInternal__ {
	return &RotatePPEWithPUKInternal__{
		PpGen:         r.PpGen.Export(),
		SkwkBox:       r.SkwkBox.Export(),
		PassphraseBox: r.PassphraseBox.Export(),
		PukBox:        r.PukBox.Export(),
	}
}
func (r *RotatePPEWithPUK) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RotatePPEWithPUK) Decode(dec rpc.Decoder) error {
	var tmp RotatePPEWithPUKInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RotatePPEWithPUK) Bytes() []byte { return nil }

type KexPPE struct {
	Skwk  SKMWK
	PpGen lib.PassphraseGeneration
	Salt  lib.PassphraseSalt
	Sv    lib.StretchVersion
}
type KexPPEInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Skwk    *SKMWKInternal__
	PpGen   *lib.PassphraseGenerationInternal__
	Salt    *lib.PassphraseSaltInternal__
	Sv      *lib.StretchVersionInternal__
}

func (k KexPPEInternal__) Import() KexPPE {
	return KexPPE{
		Skwk: (func(x *SKMWKInternal__) (ret SKMWK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Skwk),
		PpGen: (func(x *lib.PassphraseGenerationInternal__) (ret lib.PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.PpGen),
		Salt: (func(x *lib.PassphraseSaltInternal__) (ret lib.PassphraseSalt) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Salt),
		Sv: (func(x *lib.StretchVersionInternal__) (ret lib.StretchVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Sv),
	}
}
func (k KexPPE) Export() *KexPPEInternal__ {
	return &KexPPEInternal__{
		Skwk:  k.Skwk.Export(),
		PpGen: k.PpGen.Export(),
		Salt:  k.Salt.Export(),
		Sv:    k.Sv.Export(),
	}
}
func (k *KexPPE) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexPPE) Decode(dec rpc.Decoder) error {
	var tmp KexPPEInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KexPPE) Bytes() []byte { return nil }

type UnlockedSKMWK struct {
	Lst         []SKMWK
	Salt        lib.PassphraseSalt
	ExpectedGen lib.PassphraseGeneration
	Ppk         lib.HEPK
	Sv          lib.StretchVersion
	VerifyKey   lib.EntityID
}
type UnlockedSKMWKInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Lst         *[](*SKMWKInternal__)
	Salt        *lib.PassphraseSaltInternal__
	ExpectedGen *lib.PassphraseGenerationInternal__
	Ppk         *lib.HEPKInternal__
	Sv          *lib.StretchVersionInternal__
	VerifyKey   *lib.EntityIDInternal__
}

func (u UnlockedSKMWKInternal__) Import() UnlockedSKMWK {
	return UnlockedSKMWK{
		Lst: (func(x *[](*SKMWKInternal__)) (ret []SKMWK) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]SKMWK, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SKMWKInternal__) (ret SKMWK) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(u.Lst),
		Salt: (func(x *lib.PassphraseSaltInternal__) (ret lib.PassphraseSalt) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Salt),
		ExpectedGen: (func(x *lib.PassphraseGenerationInternal__) (ret lib.PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.ExpectedGen),
		Ppk: (func(x *lib.HEPKInternal__) (ret lib.HEPK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Ppk),
		Sv: (func(x *lib.StretchVersionInternal__) (ret lib.StretchVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Sv),
		VerifyKey: (func(x *lib.EntityIDInternal__) (ret lib.EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.VerifyKey),
	}
}
func (u UnlockedSKMWK) Export() *UnlockedSKMWKInternal__ {
	return &UnlockedSKMWKInternal__{
		Lst: (func(x []SKMWK) *[](*SKMWKInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SKMWKInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(u.Lst),
		Salt:        u.Salt.Export(),
		ExpectedGen: u.ExpectedGen.Export(),
		Ppk:         u.Ppk.Export(),
		Sv:          u.Sv.Export(),
		VerifyKey:   u.VerifyKey.Export(),
	}
}
func (u *UnlockedSKMWK) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UnlockedSKMWK) Decode(dec rpc.Decoder) error {
	var tmp UnlockedSKMWKInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UnlockedSKMWK) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(SKMWKListTypeUniqueID)
	rpc.AddUnique(PpePUKBoxPayloadTypeUniqueID)
	rpc.AddUnique(PpePassphraseBoxPayloadTypeUniqueID)
}
