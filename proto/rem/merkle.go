// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/rem/merkle.snowp

package rem

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type GetHistoricalRootsRes struct {
	Roots  []lib.MerkleRoot
	Hashes []lib.MerkleRootHash
}

type GetHistoricalRootsResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Roots   *[](*lib.MerkleRootInternal__)
	Hashes  *[](*lib.MerkleRootHashInternal__)
}

func (g GetHistoricalRootsResInternal__) Import() GetHistoricalRootsRes {
	return GetHistoricalRootsRes{
		Roots: (func(x *[](*lib.MerkleRootInternal__)) (ret []lib.MerkleRoot) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.MerkleRoot, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.MerkleRootInternal__) (ret lib.MerkleRoot) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Roots),
		Hashes: (func(x *[](*lib.MerkleRootHashInternal__)) (ret []lib.MerkleRootHash) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.MerkleRootHash, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.MerkleRootHashInternal__) (ret lib.MerkleRootHash) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Hashes),
	}
}

func (g GetHistoricalRootsRes) Export() *GetHistoricalRootsResInternal__ {
	return &GetHistoricalRootsResInternal__{
		Roots: (func(x []lib.MerkleRoot) *[](*lib.MerkleRootInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.MerkleRootInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Roots),
		Hashes: (func(x []lib.MerkleRootHash) *[](*lib.MerkleRootHashInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.MerkleRootHashInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Hashes),
	}
}

func (g *GetHistoricalRootsRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetHistoricalRootsRes) Decode(dec rpc.Decoder) error {
	var tmp GetHistoricalRootsResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetHistoricalRootsRes) Bytes() []byte { return nil }

type MerkleExistsRes struct {
	Epno   lib.MerkleEpno
	Signed bool
}

type MerkleExistsResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Epno    *lib.MerkleEpnoInternal__
	Signed  *bool
}

func (m MerkleExistsResInternal__) Import() MerkleExistsRes {
	return MerkleExistsRes{
		Epno: (func(x *lib.MerkleEpnoInternal__) (ret lib.MerkleEpno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Epno),
		Signed: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Signed),
	}
}

func (m MerkleExistsRes) Export() *MerkleExistsResInternal__ {
	return &MerkleExistsResInternal__{
		Epno:   m.Epno.Export(),
		Signed: &m.Signed,
	}
}

func (m *MerkleExistsRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleExistsRes) Decode(dec rpc.Decoder) error {
	var tmp MerkleExistsResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleExistsRes) Bytes() []byte { return nil }

var MerkleQueryProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xc0412aa6)

type MerkleLookupArg struct {
	HostID *lib.HostID
	Key    lib.MerkleTreeRFOutput
	Signed bool
	Root   *lib.MerkleEpno
}

type MerkleLookupArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
	Key     *lib.MerkleTreeRFOutputInternal__
	Signed  *bool
	Root    *lib.MerkleEpnoInternal__
}

func (m MerkleLookupArgInternal__) Import() MerkleLookupArg {
	return MerkleLookupArg{
		HostID: (func(x *lib.HostIDInternal__) *lib.HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.HostIDInternal__) (ret lib.HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.HostID),
		Key: (func(x *lib.MerkleTreeRFOutputInternal__) (ret lib.MerkleTreeRFOutput) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Key),
		Signed: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Signed),
		Root: (func(x *lib.MerkleEpnoInternal__) *lib.MerkleEpno {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.MerkleEpnoInternal__) (ret lib.MerkleEpno) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Root),
	}
}

func (m MerkleLookupArg) Export() *MerkleLookupArgInternal__ {
	return &MerkleLookupArgInternal__{
		HostID: (func(x *lib.HostID) *lib.HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(m.HostID),
		Key:    m.Key.Export(),
		Signed: &m.Signed,
		Root: (func(x *lib.MerkleEpno) *lib.MerkleEpnoInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(m.Root),
	}
}

func (m *MerkleLookupArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleLookupArg) Decode(dec rpc.Decoder) error {
	var tmp MerkleLookupArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleLookupArg) Bytes() []byte { return nil }

type GetHistoricalRootsArg struct {
	HostID *lib.HostID
	Full   []lib.MerkleEpno
	Hashes []lib.MerkleEpno
}

type GetHistoricalRootsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
	Full    *[](*lib.MerkleEpnoInternal__)
	Hashes  *[](*lib.MerkleEpnoInternal__)
}

func (g GetHistoricalRootsArgInternal__) Import() GetHistoricalRootsArg {
	return GetHistoricalRootsArg{
		HostID: (func(x *lib.HostIDInternal__) *lib.HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.HostIDInternal__) (ret lib.HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.HostID),
		Full: (func(x *[](*lib.MerkleEpnoInternal__)) (ret []lib.MerkleEpno) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.MerkleEpno, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.MerkleEpnoInternal__) (ret lib.MerkleEpno) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Full),
		Hashes: (func(x *[](*lib.MerkleEpnoInternal__)) (ret []lib.MerkleEpno) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.MerkleEpno, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.MerkleEpnoInternal__) (ret lib.MerkleEpno) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Hashes),
	}
}

func (g GetHistoricalRootsArg) Export() *GetHistoricalRootsArgInternal__ {
	return &GetHistoricalRootsArgInternal__{
		HostID: (func(x *lib.HostID) *lib.HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.HostID),
		Full: (func(x []lib.MerkleEpno) *[](*lib.MerkleEpnoInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.MerkleEpnoInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Full),
		Hashes: (func(x []lib.MerkleEpno) *[](*lib.MerkleEpnoInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.MerkleEpnoInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Hashes),
	}
}

func (g *GetHistoricalRootsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetHistoricalRootsArg) Decode(dec rpc.Decoder) error {
	var tmp GetHistoricalRootsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetHistoricalRootsArg) Bytes() []byte { return nil }

type GetCurrentRootArg struct {
	HostID *lib.HostID
}

type GetCurrentRootArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
}

func (g GetCurrentRootArgInternal__) Import() GetCurrentRootArg {
	return GetCurrentRootArg{
		HostID: (func(x *lib.HostIDInternal__) *lib.HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.HostIDInternal__) (ret lib.HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.HostID),
	}
}

func (g GetCurrentRootArg) Export() *GetCurrentRootArgInternal__ {
	return &GetCurrentRootArgInternal__{
		HostID: (func(x *lib.HostID) *lib.HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.HostID),
	}
}

func (g *GetCurrentRootArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetCurrentRootArg) Decode(dec rpc.Decoder) error {
	var tmp GetCurrentRootArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetCurrentRootArg) Bytes() []byte { return nil }

type GetCurrentRootHashArg struct {
	HostID *lib.HostID
}

type GetCurrentRootHashArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
}

func (g GetCurrentRootHashArgInternal__) Import() GetCurrentRootHashArg {
	return GetCurrentRootHashArg{
		HostID: (func(x *lib.HostIDInternal__) *lib.HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.HostIDInternal__) (ret lib.HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.HostID),
	}
}

func (g GetCurrentRootHashArg) Export() *GetCurrentRootHashArgInternal__ {
	return &GetCurrentRootHashArgInternal__{
		HostID: (func(x *lib.HostID) *lib.HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.HostID),
	}
}

func (g *GetCurrentRootHashArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetCurrentRootHashArg) Decode(dec rpc.Decoder) error {
	var tmp GetCurrentRootHashArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetCurrentRootHashArg) Bytes() []byte { return nil }

type CheckKeyExistsArg struct {
	HostID *lib.HostID
	Key    lib.MerkleTreeRFOutput
}

type CheckKeyExistsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
	Key     *lib.MerkleTreeRFOutputInternal__
}

func (c CheckKeyExistsArgInternal__) Import() CheckKeyExistsArg {
	return CheckKeyExistsArg{
		HostID: (func(x *lib.HostIDInternal__) *lib.HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.HostIDInternal__) (ret lib.HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.HostID),
		Key: (func(x *lib.MerkleTreeRFOutputInternal__) (ret lib.MerkleTreeRFOutput) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Key),
	}
}

func (c CheckKeyExistsArg) Export() *CheckKeyExistsArgInternal__ {
	return &CheckKeyExistsArgInternal__{
		HostID: (func(x *lib.HostID) *lib.HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.HostID),
		Key: c.Key.Export(),
	}
}

func (c *CheckKeyExistsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CheckKeyExistsArg) Decode(dec rpc.Decoder) error {
	var tmp CheckKeyExistsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CheckKeyExistsArg) Bytes() []byte { return nil }

type GetCurrentRootSignedArg struct {
	HostID *lib.HostID
}

type GetCurrentRootSignedArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
}

func (g GetCurrentRootSignedArgInternal__) Import() GetCurrentRootSignedArg {
	return GetCurrentRootSignedArg{
		HostID: (func(x *lib.HostIDInternal__) *lib.HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.HostIDInternal__) (ret lib.HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.HostID),
	}
}

func (g GetCurrentRootSignedArg) Export() *GetCurrentRootSignedArgInternal__ {
	return &GetCurrentRootSignedArgInternal__{
		HostID: (func(x *lib.HostID) *lib.HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.HostID),
	}
}

func (g *GetCurrentRootSignedArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetCurrentRootSignedArg) Decode(dec rpc.Decoder) error {
	var tmp GetCurrentRootSignedArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetCurrentRootSignedArg) Bytes() []byte { return nil }

type MerkleMLookupArg struct {
	HostID *lib.HostID
	Keys   []lib.MerkleTreeRFOutput
	Signed bool
	Root   *lib.MerkleEpno
}

type MerkleMLookupArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
	Keys    *[](*lib.MerkleTreeRFOutputInternal__)
	Signed  *bool
	Root    *lib.MerkleEpnoInternal__
}

func (m MerkleMLookupArgInternal__) Import() MerkleMLookupArg {
	return MerkleMLookupArg{
		HostID: (func(x *lib.HostIDInternal__) *lib.HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.HostIDInternal__) (ret lib.HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.HostID),
		Keys: (func(x *[](*lib.MerkleTreeRFOutputInternal__)) (ret []lib.MerkleTreeRFOutput) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.MerkleTreeRFOutput, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.MerkleTreeRFOutputInternal__) (ret lib.MerkleTreeRFOutput) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(m.Keys),
		Signed: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Signed),
		Root: (func(x *lib.MerkleEpnoInternal__) *lib.MerkleEpno {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.MerkleEpnoInternal__) (ret lib.MerkleEpno) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(m.Root),
	}
}

func (m MerkleMLookupArg) Export() *MerkleMLookupArgInternal__ {
	return &MerkleMLookupArgInternal__{
		HostID: (func(x *lib.HostID) *lib.HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(m.HostID),
		Keys: (func(x []lib.MerkleTreeRFOutput) *[](*lib.MerkleTreeRFOutputInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.MerkleTreeRFOutputInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(m.Keys),
		Signed: &m.Signed,
		Root: (func(x *lib.MerkleEpno) *lib.MerkleEpnoInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(m.Root),
	}
}

func (m *MerkleMLookupArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleMLookupArg) Decode(dec rpc.Decoder) error {
	var tmp MerkleMLookupArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleMLookupArg) Bytes() []byte { return nil }

type GetCurrentRootSignedEpnoArg struct {
	HostID *lib.HostID
}

type GetCurrentRootSignedEpnoArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
}

func (g GetCurrentRootSignedEpnoArgInternal__) Import() GetCurrentRootSignedEpnoArg {
	return GetCurrentRootSignedEpnoArg{
		HostID: (func(x *lib.HostIDInternal__) *lib.HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.HostIDInternal__) (ret lib.HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.HostID),
	}
}

func (g GetCurrentRootSignedEpnoArg) Export() *GetCurrentRootSignedEpnoArgInternal__ {
	return &GetCurrentRootSignedEpnoArgInternal__{
		HostID: (func(x *lib.HostID) *lib.HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.HostID),
	}
}

func (g *GetCurrentRootSignedEpnoArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetCurrentRootSignedEpnoArg) Decode(dec rpc.Decoder) error {
	var tmp GetCurrentRootSignedEpnoArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetCurrentRootSignedEpnoArg) Bytes() []byte { return nil }

type MerkleSelectVHostArg struct {
	Host lib.HostID
}

type MerkleSelectVHostArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *lib.HostIDInternal__
}

func (m MerkleSelectVHostArgInternal__) Import() MerkleSelectVHostArg {
	return MerkleSelectVHostArg{
		Host: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.Host),
	}
}

func (m MerkleSelectVHostArg) Export() *MerkleSelectVHostArgInternal__ {
	return &MerkleSelectVHostArgInternal__{
		Host: m.Host.Export(),
	}
}

func (m *MerkleSelectVHostArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MerkleSelectVHostArg) Decode(dec rpc.Decoder) error {
	var tmp MerkleSelectVHostArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MerkleSelectVHostArg) Bytes() []byte { return nil }

type ConfirmRootArg struct {
	HostID lib.HostID
	Root   lib.TreeRoot
}

type ConfirmRootArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	HostID  *lib.HostIDInternal__
	Root    *lib.TreeRootInternal__
}

func (c ConfirmRootArgInternal__) Import() ConfirmRootArg {
	return ConfirmRootArg{
		HostID: (func(x *lib.HostIDInternal__) (ret lib.HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.HostID),
		Root: (func(x *lib.TreeRootInternal__) (ret lib.TreeRoot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Root),
	}
}

func (c ConfirmRootArg) Export() *ConfirmRootArgInternal__ {
	return &ConfirmRootArgInternal__{
		HostID: c.HostID.Export(),
		Root:   c.Root.Export(),
	}
}

func (c *ConfirmRootArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ConfirmRootArg) Decode(dec rpc.Decoder) error {
	var tmp ConfirmRootArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ConfirmRootArg) Bytes() []byte { return nil }

type MerkleQueryInterface interface {
	Lookup(context.Context, MerkleLookupArg) (lib.MerklePathCompressed, error)
	GetHistoricalRoots(context.Context, GetHistoricalRootsArg) (GetHistoricalRootsRes, error)
	GetCurrentRoot(context.Context, *lib.HostID) (lib.MerkleRoot, error)
	GetCurrentRootHash(context.Context, *lib.HostID) (lib.TreeRoot, error)
	CheckKeyExists(context.Context, CheckKeyExistsArg) (MerkleExistsRes, error)
	GetCurrentRootSigned(context.Context, *lib.HostID) (lib.SignedMerkleRoot, error)
	MLookup(context.Context, MerkleMLookupArg) (lib.MerklePathsCompressed, error)
	GetCurrentRootSignedEpno(context.Context, *lib.HostID) (lib.MerkleEpno, error)
	SelectVHost(context.Context, lib.HostID) error
	ConfirmRoot(context.Context, ConfirmRootArg) error
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error

	MakeResHeader() lib.Header
}

func MerkleQueryMakeGenericErrorWrapper(f MerkleQueryErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type MerkleQueryErrorUnwrapper func(lib.Status) error
type MerkleQueryErrorWrapper func(error) lib.Status

type merkleQueryErrorUnwrapperAdapter struct {
	h MerkleQueryErrorUnwrapper
}

func (m merkleQueryErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (m merkleQueryErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return m.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = merkleQueryErrorUnwrapperAdapter{}

type MerkleQueryClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper MerkleQueryErrorUnwrapper
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c MerkleQueryClient) Lookup(ctx context.Context, arg MerkleLookupArg) (res lib.MerklePathCompressed, err error) {
	warg := &rpc.DataWrap[lib.Header, *MerkleLookupArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.MerklePathCompressedInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 0, "MerkleQuery.lookup"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c MerkleQueryClient) GetHistoricalRoots(ctx context.Context, arg GetHistoricalRootsArg) (res GetHistoricalRootsRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *GetHistoricalRootsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, GetHistoricalRootsResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 1, "MerkleQuery.getHistoricalRoots"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c MerkleQueryClient) GetCurrentRoot(ctx context.Context, hostID *lib.HostID) (res lib.MerkleRoot, err error) {
	arg := GetCurrentRootArg{
		HostID: hostID,
	}
	warg := &rpc.DataWrap[lib.Header, *GetCurrentRootArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.MerkleRootInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 2, "MerkleQuery.getCurrentRoot"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c MerkleQueryClient) GetCurrentRootHash(ctx context.Context, hostID *lib.HostID) (res lib.TreeRoot, err error) {
	arg := GetCurrentRootHashArg{
		HostID: hostID,
	}
	warg := &rpc.DataWrap[lib.Header, *GetCurrentRootHashArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.TreeRootInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 3, "MerkleQuery.getCurrentRootHash"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c MerkleQueryClient) CheckKeyExists(ctx context.Context, arg CheckKeyExistsArg) (res MerkleExistsRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *CheckKeyExistsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, MerkleExistsResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 4, "MerkleQuery.checkKeyExists"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c MerkleQueryClient) GetCurrentRootSigned(ctx context.Context, hostID *lib.HostID) (res lib.SignedMerkleRoot, err error) {
	arg := GetCurrentRootSignedArg{
		HostID: hostID,
	}
	warg := &rpc.DataWrap[lib.Header, *GetCurrentRootSignedArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.SignedMerkleRootInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 5, "MerkleQuery.getCurrentRootSigned"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c MerkleQueryClient) MLookup(ctx context.Context, arg MerkleMLookupArg) (res lib.MerklePathsCompressed, err error) {
	warg := &rpc.DataWrap[lib.Header, *MerkleMLookupArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.MerklePathsCompressedInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 6, "MerkleQuery.mLookup"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c MerkleQueryClient) GetCurrentRootSignedEpno(ctx context.Context, hostID *lib.HostID) (res lib.MerkleEpno, err error) {
	arg := GetCurrentRootSignedEpnoArg{
		HostID: hostID,
	}
	warg := &rpc.DataWrap[lib.Header, *GetCurrentRootSignedEpnoArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.MerkleEpnoInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 7, "MerkleQuery.getCurrentRootSignedEpno"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c MerkleQueryClient) SelectVHost(ctx context.Context, host lib.HostID) (err error) {
	arg := MerkleSelectVHostArg{
		Host: host,
	}
	warg := &rpc.DataWrap[lib.Header, *MerkleSelectVHostArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 8, "MerkleQuery.selectVHost"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c MerkleQueryClient) ConfirmRoot(ctx context.Context, arg ConfirmRootArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *ConfirmRootArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(MerkleQueryProtocolID, 9, "MerkleQuery.confirmRoot"), warg, &tmp, 0*time.Millisecond, merkleQueryErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func MerkleQueryProtocol(i MerkleQueryInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "MerkleQuery",
		ID:   MerkleQueryProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *MerkleLookupArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *MerkleLookupArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *MerkleLookupArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.Lookup(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.MerklePathCompressedInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "lookup",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetHistoricalRootsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetHistoricalRootsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetHistoricalRootsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetHistoricalRoots(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *GetHistoricalRootsResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getHistoricalRoots",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetCurrentRootArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetCurrentRootArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetCurrentRootArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetCurrentRoot(ctx, (typedArg.Import()).HostID)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.MerkleRootInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getCurrentRoot",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetCurrentRootHashArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetCurrentRootHashArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetCurrentRootHashArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetCurrentRootHash(ctx, (typedArg.Import()).HostID)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.TreeRootInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getCurrentRootHash",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *CheckKeyExistsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *CheckKeyExistsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *CheckKeyExistsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.CheckKeyExists(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *MerkleExistsResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "checkKeyExists",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetCurrentRootSignedArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetCurrentRootSignedArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetCurrentRootSignedArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetCurrentRootSigned(ctx, (typedArg.Import()).HostID)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.SignedMerkleRootInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getCurrentRootSigned",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *MerkleMLookupArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *MerkleMLookupArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *MerkleMLookupArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.MLookup(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.MerklePathsCompressedInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "mLookup",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *GetCurrentRootSignedEpnoArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *GetCurrentRootSignedEpnoArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *GetCurrentRootSignedEpnoArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GetCurrentRootSignedEpno(ctx, (typedArg.Import()).HostID)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.MerkleEpnoInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "getCurrentRootSignedEpno",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *MerkleSelectVHostArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *MerkleSelectVHostArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *MerkleSelectVHostArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.SelectVHost(ctx, (typedArg.Import()).Host)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "selectVHost",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ConfirmRootArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ConfirmRootArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ConfirmRootArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ConfirmRoot(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "confirmRoot",
			},
		},
		WrapError: MerkleQueryMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(MerkleQueryProtocolID)
}
