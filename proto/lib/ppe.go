// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/ppe.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type PpePassphraseBox struct {
	Box Box
}
type PpePassphraseBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Box     *BoxInternal__
}

func (p PpePassphraseBoxInternal__) Import() PpePassphraseBox {
	return PpePassphraseBox{
		Box: (func(x *BoxInternal__) (ret Box) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Box),
	}
}
func (p PpePassphraseBox) Export() *PpePassphraseBoxInternal__ {
	return &PpePassphraseBoxInternal__{
		Box: p.Box.Export(),
	}
}
func (p *PpePassphraseBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PpePassphraseBox) Decode(dec rpc.Decoder) error {
	var tmp PpePassphraseBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PpePassphraseBox) Bytes() []byte { return nil }

type PpePUKBox struct {
	Box     SecretBox
	PukGen  Generation
	PukRole Role
}
type PpePUKBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Box     *SecretBoxInternal__
	PukGen  *GenerationInternal__
	PukRole *RoleInternal__
}

func (p PpePUKBoxInternal__) Import() PpePUKBox {
	return PpePUKBox{
		Box: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Box),
		PukGen: (func(x *GenerationInternal__) (ret Generation) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.PukGen),
		PukRole: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.PukRole),
	}
}
func (p PpePUKBox) Export() *PpePUKBoxInternal__ {
	return &PpePUKBoxInternal__{
		Box:     p.Box.Export(),
		PukGen:  p.PukGen.Export(),
		PukRole: p.PukRole.Export(),
	}
}
func (p *PpePUKBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PpePUKBox) Decode(dec rpc.Decoder) error {
	var tmp PpePUKBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PpePUKBox) Bytes() []byte { return nil }

type PpeParcel struct {
	SkwkBox       SecretBox
	PpGen         PassphraseGeneration
	PassphraseBox PpePassphraseBox
	PukBox        *PpePUKBox
	Salt          PassphraseSalt
	Sv            StretchVersion
	VerifyKey     EntityID
}
type PpeParcelInternal__ struct {
	_struct       struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	SkwkBox       *SecretBoxInternal__
	PpGen         *PassphraseGenerationInternal__
	PassphraseBox *PpePassphraseBoxInternal__
	PukBox        *PpePUKBoxInternal__
	Salt          *PassphraseSaltInternal__
	Sv            *StretchVersionInternal__
	VerifyKey     *EntityIDInternal__
}

func (p PpeParcelInternal__) Import() PpeParcel {
	return PpeParcel{
		SkwkBox: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SkwkBox),
		PpGen: (func(x *PassphraseGenerationInternal__) (ret PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.PpGen),
		PassphraseBox: (func(x *PpePassphraseBoxInternal__) (ret PpePassphraseBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.PassphraseBox),
		PukBox: (func(x *PpePUKBoxInternal__) *PpePUKBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *PpePUKBoxInternal__) (ret PpePUKBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.PukBox),
		Salt: (func(x *PassphraseSaltInternal__) (ret PassphraseSalt) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Salt),
		Sv: (func(x *StretchVersionInternal__) (ret StretchVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Sv),
		VerifyKey: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.VerifyKey),
	}
}
func (p PpeParcel) Export() *PpeParcelInternal__ {
	return &PpeParcelInternal__{
		SkwkBox:       p.SkwkBox.Export(),
		PpGen:         p.PpGen.Export(),
		PassphraseBox: p.PassphraseBox.Export(),
		PukBox: (func(x *PpePUKBox) *PpePUKBoxInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(p.PukBox),
		Salt:      p.Salt.Export(),
		Sv:        p.Sv.Export(),
		VerifyKey: p.VerifyKey.Export(),
	}
}
func (p *PpeParcel) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PpeParcel) Decode(dec rpc.Decoder) error {
	var tmp PpeParcelInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PpeParcel) Bytes() []byte { return nil }
