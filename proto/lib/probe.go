// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/probe.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type PublicServices struct {
	Probe       TCPAddr
	Reg         TCPAddr
	User        TCPAddr
	MerkleQuery TCPAddr
	KvStore     TCPAddr
}

type PublicServicesInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Probe       *TCPAddrInternal__
	Reg         *TCPAddrInternal__
	User        *TCPAddrInternal__
	MerkleQuery *TCPAddrInternal__
	KvStore     *TCPAddrInternal__
}

func (p PublicServicesInternal__) Import() PublicServices {
	return PublicServices{
		Probe: (func(x *TCPAddrInternal__) (ret TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Probe),
		Reg: (func(x *TCPAddrInternal__) (ret TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Reg),
		User: (func(x *TCPAddrInternal__) (ret TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.User),
		MerkleQuery: (func(x *TCPAddrInternal__) (ret TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.MerkleQuery),
		KvStore: (func(x *TCPAddrInternal__) (ret TCPAddr) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.KvStore),
	}
}

func (p PublicServices) Export() *PublicServicesInternal__ {
	return &PublicServicesInternal__{
		Probe:       p.Probe.Export(),
		Reg:         p.Reg.Export(),
		User:        p.User.Export(),
		MerkleQuery: p.MerkleQuery.Export(),
		KvStore:     p.KvStore.Export(),
	}
}

func (p *PublicServices) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PublicServices) Decode(dec rpc.Decoder) error {
	var tmp PublicServicesInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PublicServices) Bytes() []byte { return nil }

type PublicZone struct {
	Ttl      DurationSecs
	Services PublicServices
}

type PublicZoneInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ttl      *DurationSecsInternal__
	Services *PublicServicesInternal__
}

func (p PublicZoneInternal__) Import() PublicZone {
	return PublicZone{
		Ttl: (func(x *DurationSecsInternal__) (ret DurationSecs) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Ttl),
		Services: (func(x *PublicServicesInternal__) (ret PublicServices) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Services),
	}
}

func (p PublicZone) Export() *PublicZoneInternal__ {
	return &PublicZoneInternal__{
		Ttl:      p.Ttl.Export(),
		Services: p.Services.Export(),
	}
}

func (p *PublicZone) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PublicZone) Decode(dec rpc.Decoder) error {
	var tmp PublicZoneInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PublicZone) Bytes() []byte { return nil }

type PublicZoneBlob []byte
type PublicZoneBlobInternal__ []byte

func (p PublicZoneBlob) Export() *PublicZoneBlobInternal__ {
	tmp := (([]byte)(p))
	return ((*PublicZoneBlobInternal__)(&tmp))
}

func (p PublicZoneBlobInternal__) Import() PublicZoneBlob {
	tmp := ([]byte)(p)
	return PublicZoneBlob((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *PublicZoneBlob) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PublicZoneBlob) Decode(dec rpc.Decoder) error {
	var tmp PublicZoneBlobInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

var PublicZoneBlobTypeUniqueID = rpc.TypeUniqueID(0xd4f1ec4f90eb2c6d)

func (p *PublicZoneBlob) GetTypeUniqueID() rpc.TypeUniqueID {
	return PublicZoneBlobTypeUniqueID
}

func (p PublicZoneBlob) Bytes() []byte {
	return (p)[:]
}

func (p *PublicZoneBlob) AllocAndDecode(f rpc.DecoderFactory) (*PublicZone, error) {
	var ret PublicZone
	src := f.NewDecoderBytes(&ret, p.Bytes())
	err := ret.Decode(src)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (p *PublicZoneBlob) AssertNormalized() error { return nil }

func (p *PublicZone) EncodeTyped(f rpc.EncoderFactory) (*PublicZoneBlob, error) {
	var tmp []byte
	enc := f.NewEncoderBytes(&tmp)
	err := p.Encode(enc)
	if err != nil {
		return nil, err
	}
	ret := PublicZoneBlob(tmp)
	return &ret, nil
}

func (p *PublicZone) ChildBlob(_b []byte) PublicZoneBlob {
	return PublicZoneBlob(_b)
}

type SignedPublicZone struct {
	Inner PublicZoneBlob
	Sig   Signature
}

type SignedPublicZoneInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Inner   *PublicZoneBlobInternal__
	Sig     *SignatureInternal__
}

func (s SignedPublicZoneInternal__) Import() SignedPublicZone {
	return SignedPublicZone{
		Inner: (func(x *PublicZoneBlobInternal__) (ret PublicZoneBlob) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Inner),
		Sig: (func(x *SignatureInternal__) (ret Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Sig),
	}
}

func (s SignedPublicZone) Export() *SignedPublicZoneInternal__ {
	return &SignedPublicZoneInternal__{
		Inner: s.Inner.Export(),
		Sig:   s.Sig.Export(),
	}
}

func (s *SignedPublicZone) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SignedPublicZone) Decode(dec rpc.Decoder) error {
	var tmp SignedPublicZoneInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SignedPublicZone) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(PublicZoneBlobTypeUniqueID)
}
