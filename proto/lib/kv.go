// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/kv.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type KVShardID uint64
type KVShardIDInternal__ uint64

func (k KVShardID) Export() *KVShardIDInternal__ {
	tmp := ((uint64)(k))
	return ((*KVShardIDInternal__)(&tmp))
}

func (k KVShardIDInternal__) Import() KVShardID {
	tmp := (uint64)(k)
	return KVShardID((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KVShardID) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVShardID) Decode(dec rpc.Decoder) error {
	var tmp KVShardIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KVShardID) Bytes() []byte {
	return nil
}

type FileKeySeed SecretSeed32
type FileKeySeedInternal__ SecretSeed32Internal__

func (f FileKeySeed) Export() *FileKeySeedInternal__ {
	tmp := ((SecretSeed32)(f))
	return ((*FileKeySeedInternal__)(tmp.Export()))
}

func (f FileKeySeedInternal__) Import() FileKeySeed {
	tmp := (SecretSeed32Internal__)(f)
	return FileKeySeed((func(x *SecretSeed32Internal__) (ret SecretSeed32) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (f *FileKeySeed) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FileKeySeed) Decode(dec rpc.Decoder) error {
	var tmp FileKeySeedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

var FileKeySeedTypeUniqueID = rpc.TypeUniqueID(0xb6487f843b10cfce)

func (f *FileKeySeed) GetTypeUniqueID() rpc.TypeUniqueID {
	return FileKeySeedTypeUniqueID
}

func (f FileKeySeed) Bytes() []byte {
	return ((SecretSeed32)(f)).Bytes()
}

type DirKeySeed SecretSeed32
type DirKeySeedInternal__ SecretSeed32Internal__

func (d DirKeySeed) Export() *DirKeySeedInternal__ {
	tmp := ((SecretSeed32)(d))
	return ((*DirKeySeedInternal__)(tmp.Export()))
}

func (d DirKeySeedInternal__) Import() DirKeySeed {
	tmp := (SecretSeed32Internal__)(d)
	return DirKeySeed((func(x *SecretSeed32Internal__) (ret SecretSeed32) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (d *DirKeySeed) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DirKeySeed) Decode(dec rpc.Decoder) error {
	var tmp DirKeySeedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

var DirKeySeedTypeUniqueID = rpc.TypeUniqueID(0x8aece6566b244356)

func (d *DirKeySeed) GetTypeUniqueID() rpc.TypeUniqueID {
	return DirKeySeedTypeUniqueID
}

func (d DirKeySeed) Bytes() []byte {
	return ((SecretSeed32)(d)).Bytes()
}

type ShortPartyID [17]byte
type ShortPartyIDInternal__ [17]byte

func (s ShortPartyID) Export() *ShortPartyIDInternal__ {
	tmp := (([17]byte)(s))
	return ((*ShortPartyIDInternal__)(&tmp))
}

func (s ShortPartyIDInternal__) Import() ShortPartyID {
	tmp := ([17]byte)(s)
	return ShortPartyID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *ShortPartyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *ShortPartyID) Decode(dec rpc.Decoder) error {
	var tmp ShortPartyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s ShortPartyID) Bytes() []byte {
	return (s)[:]
}

type KVMacKey HMACKey
type KVMacKeyInternal__ HMACKeyInternal__

func (k KVMacKey) Export() *KVMacKeyInternal__ {
	tmp := ((HMACKey)(k))
	return ((*KVMacKeyInternal__)(tmp.Export()))
}

func (k KVMacKeyInternal__) Import() KVMacKey {
	tmp := (HMACKeyInternal__)(k)
	return KVMacKey((func(x *HMACKeyInternal__) (ret HMACKey) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (k *KVMacKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVMacKey) Decode(dec rpc.Decoder) error {
	var tmp KVMacKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KVMacKey) Bytes() []byte {
	return ((HMACKey)(k)).Bytes()
}

type KVBoxKey SecretBoxKey
type KVBoxKeyInternal__ SecretBoxKeyInternal__

func (k KVBoxKey) Export() *KVBoxKeyInternal__ {
	tmp := ((SecretBoxKey)(k))
	return ((*KVBoxKeyInternal__)(tmp.Export()))
}

func (k KVBoxKeyInternal__) Import() KVBoxKey {
	tmp := (SecretBoxKeyInternal__)(k)
	return KVBoxKey((func(x *SecretBoxKeyInternal__) (ret SecretBoxKey) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (k *KVBoxKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVBoxKey) Decode(dec rpc.Decoder) error {
	var tmp KVBoxKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KVBoxKey) Bytes() []byte {
	return ((SecretBoxKey)(k)).Bytes()
}

type KVNamePlaintext string
type KVNamePlaintextInternal__ string

func (k KVNamePlaintext) Export() *KVNamePlaintextInternal__ {
	tmp := ((string)(k))
	return ((*KVNamePlaintextInternal__)(&tmp))
}

func (k KVNamePlaintextInternal__) Import() KVNamePlaintext {
	tmp := (string)(k)
	return KVNamePlaintext((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KVNamePlaintext) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVNamePlaintext) Decode(dec rpc.Decoder) error {
	var tmp KVNamePlaintextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KVNamePlaintextTypeUniqueID = rpc.TypeUniqueID(0x9f9fe83fe9f0d475)

func (k *KVNamePlaintext) GetTypeUniqueID() rpc.TypeUniqueID {
	return KVNamePlaintextTypeUniqueID
}

func (k KVNamePlaintext) Bytes() []byte {
	return nil
}

type KVNameNonceInput struct {
	ParentDir DirID
	Name      KVNamePlaintext
}

type KVNameNonceInputInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ParentDir *DirIDInternal__
	Name      *KVNamePlaintextInternal__
}

func (k KVNameNonceInputInternal__) Import() KVNameNonceInput {
	return KVNameNonceInput{
		ParentDir: (func(x *DirIDInternal__) (ret DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.ParentDir),
		Name: (func(x *KVNamePlaintextInternal__) (ret KVNamePlaintext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Name),
	}
}

func (k KVNameNonceInput) Export() *KVNameNonceInputInternal__ {
	return &KVNameNonceInputInternal__{
		ParentDir: k.ParentDir.Export(),
		Name:      k.Name.Export(),
	}
}

func (k *KVNameNonceInput) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVNameNonceInput) Decode(dec rpc.Decoder) error {
	var tmp KVNameNonceInputInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KVNameNonceInputTypeUniqueID = rpc.TypeUniqueID(0x8f02a15745471874)

func (k *KVNameNonceInput) GetTypeUniqueID() rpc.TypeUniqueID {
	return KVNameNonceInputTypeUniqueID
}

func (k *KVNameNonceInput) Bytes() []byte { return nil }

type KVNodeType int

const (
	KVNodeType_None      KVNodeType = 0
	KVNodeType_Dir       KVNodeType = 1
	KVNodeType_File      KVNodeType = 2
	KVNodeType_SmallFile KVNodeType = 3
	KVNodeType_Symlink   KVNodeType = 4
)

var KVNodeTypeMap = map[string]KVNodeType{
	"None":      0,
	"Dir":       1,
	"File":      2,
	"SmallFile": 3,
	"Symlink":   4,
}

var KVNodeTypeRevMap = map[KVNodeType]string{
	0: "None",
	1: "Dir",
	2: "File",
	3: "SmallFile",
	4: "Symlink",
}

type KVNodeTypeInternal__ KVNodeType

func (k KVNodeTypeInternal__) Import() KVNodeType {
	return KVNodeType(k)
}

func (k KVNodeType) Export() *KVNodeTypeInternal__ {
	return ((*KVNodeTypeInternal__)(&k))
}

type KVVersion uint64
type KVVersionInternal__ uint64

func (k KVVersion) Export() *KVVersionInternal__ {
	tmp := ((uint64)(k))
	return ((*KVVersionInternal__)(&tmp))
}

func (k KVVersionInternal__) Import() KVVersion {
	tmp := (uint64)(k)
	return KVVersion((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KVVersion) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVVersion) Decode(dec rpc.Decoder) error {
	var tmp KVVersionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KVVersion) Bytes() []byte {
	return nil
}

type PathVersionVector struct {
	Root KVVersion
	Path []DirVersion
}

type PathVersionVectorInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Root    *KVVersionInternal__
	Path    *[](*DirVersionInternal__)
}

func (p PathVersionVectorInternal__) Import() PathVersionVector {
	return PathVersionVector{
		Root: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Root),
		Path: (func(x *[](*DirVersionInternal__)) (ret []DirVersion) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]DirVersion, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *DirVersionInternal__) (ret DirVersion) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(p.Path),
	}
}

func (p PathVersionVector) Export() *PathVersionVectorInternal__ {
	return &PathVersionVectorInternal__{
		Root: p.Root.Export(),
		Path: (func(x []DirVersion) *[](*DirVersionInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*DirVersionInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(p.Path),
	}
}

func (p *PathVersionVector) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PathVersionVector) Decode(dec rpc.Decoder) error {
	var tmp PathVersionVectorInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PathVersionVector) Bytes() []byte { return nil }

type DirVersion struct {
	Id   DirID
	Vers KVVersion
	De   []DirentVersion
}

type DirVersionInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *DirIDInternal__
	Vers    *KVVersionInternal__
	De      *[](*DirentVersionInternal__)
}

func (d DirVersionInternal__) Import() DirVersion {
	return DirVersion{
		Id: (func(x *DirIDInternal__) (ret DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Id),
		Vers: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Vers),
		De: (func(x *[](*DirentVersionInternal__)) (ret []DirentVersion) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]DirentVersion, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *DirentVersionInternal__) (ret DirentVersion) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(d.De),
	}
}

func (d DirVersion) Export() *DirVersionInternal__ {
	return &DirVersionInternal__{
		Id:   d.Id.Export(),
		Vers: d.Vers.Export(),
		De: (func(x []DirentVersion) *[](*DirentVersionInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*DirentVersionInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(d.De),
	}
}

func (d *DirVersion) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DirVersion) Decode(dec rpc.Decoder) error {
	var tmp DirVersionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DirVersion) Bytes() []byte { return nil }

type FileID [16]byte
type FileIDInternal__ [16]byte

func (f FileID) Export() *FileIDInternal__ {
	tmp := (([16]byte)(f))
	return ((*FileIDInternal__)(&tmp))
}

func (f FileIDInternal__) Import() FileID {
	tmp := ([16]byte)(f)
	return FileID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (f *FileID) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FileID) Decode(dec rpc.Decoder) error {
	var tmp FileIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f FileID) Bytes() []byte {
	return (f)[:]
}

type SmallFileID [16]byte
type SmallFileIDInternal__ [16]byte

func (s SmallFileID) Export() *SmallFileIDInternal__ {
	tmp := (([16]byte)(s))
	return ((*SmallFileIDInternal__)(&tmp))
}

func (s SmallFileIDInternal__) Import() SmallFileID {
	tmp := ([16]byte)(s)
	return SmallFileID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SmallFileID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SmallFileID) Decode(dec rpc.Decoder) error {
	var tmp SmallFileIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SmallFileID) Bytes() []byte {
	return (s)[:]
}

type SymlinkID [16]byte
type SymlinkIDInternal__ [16]byte

func (s SymlinkID) Export() *SymlinkIDInternal__ {
	tmp := (([16]byte)(s))
	return ((*SymlinkIDInternal__)(&tmp))
}

func (s SymlinkIDInternal__) Import() SymlinkID {
	tmp := ([16]byte)(s)
	return SymlinkID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SymlinkID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SymlinkID) Decode(dec rpc.Decoder) error {
	var tmp SymlinkIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SymlinkID) Bytes() []byte {
	return (s)[:]
}

type DirID [16]byte
type DirIDInternal__ [16]byte

func (d DirID) Export() *DirIDInternal__ {
	tmp := (([16]byte)(d))
	return ((*DirIDInternal__)(&tmp))
}

func (d DirIDInternal__) Import() DirID {
	tmp := ([16]byte)(d)
	return DirID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DirID) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DirID) Decode(dec rpc.Decoder) error {
	var tmp DirIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DirID) Bytes() []byte {
	return (d)[:]
}

type DirentID [16]byte
type DirentIDInternal__ [16]byte

func (d DirentID) Export() *DirentIDInternal__ {
	tmp := (([16]byte)(d))
	return ((*DirentIDInternal__)(&tmp))
}

func (d DirentIDInternal__) Import() DirentID {
	tmp := ([16]byte)(d)
	return DirentID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DirentID) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DirentID) Decode(dec rpc.Decoder) error {
	var tmp DirentIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DirentID) Bytes() []byte {
	return (d)[:]
}

type DirentVersion struct {
	Id   DirentID
	Vers KVVersion
}

type DirentVersionInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *DirentIDInternal__
	Vers    *KVVersionInternal__
}

func (d DirentVersionInternal__) Import() DirentVersion {
	return DirentVersion{
		Id: (func(x *DirentIDInternal__) (ret DirentID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Id),
		Vers: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Vers),
	}
}

func (d DirentVersion) Export() *DirentVersionInternal__ {
	return &DirentVersionInternal__{
		Id:   d.Id.Export(),
		Vers: d.Vers.Export(),
	}
}

func (d *DirentVersion) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DirentVersion) Decode(dec rpc.Decoder) error {
	var tmp DirentVersionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DirentVersion) Bytes() []byte { return nil }

type RolePair struct {
	Read  Role
	Write Role
}

type RolePairInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Read    *RoleInternal__
	Write   *RoleInternal__
}

func (r RolePairInternal__) Import() RolePair {
	return RolePair{
		Read: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Read),
		Write: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Write),
	}
}

func (r RolePair) Export() *RolePairInternal__ {
	return &RolePairInternal__{
		Read:  r.Read.Export(),
		Write: r.Write.Export(),
	}
}

func (r *RolePair) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RolePair) Decode(dec rpc.Decoder) error {
	var tmp RolePairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RolePair) Bytes() []byte { return nil }

type RolePairOpt struct {
	Read  *Role
	Write *Role
}

type RolePairOptInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Read    *RoleInternal__
	Write   *RoleInternal__
}

func (r RolePairOptInternal__) Import() RolePairOpt {
	return RolePairOpt{
		Read: (func(x *RoleInternal__) *Role {
			if x == nil {
				return nil
			}
			tmp := (func(x *RoleInternal__) (ret Role) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Read),
		Write: (func(x *RoleInternal__) *Role {
			if x == nil {
				return nil
			}
			tmp := (func(x *RoleInternal__) (ret Role) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(r.Write),
	}
}

func (r RolePairOpt) Export() *RolePairOptInternal__ {
	return &RolePairOptInternal__{
		Read: (func(x *Role) *RoleInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Read),
		Write: (func(x *Role) *RoleInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(r.Write),
	}
}

func (r *RolePairOpt) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RolePairOpt) Decode(dec rpc.Decoder) error {
	var tmp RolePairOptInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RolePairOpt) Bytes() []byte { return nil }

type LocalFSPath string
type LocalFSPathInternal__ string

func (l LocalFSPath) Export() *LocalFSPathInternal__ {
	tmp := ((string)(l))
	return ((*LocalFSPathInternal__)(&tmp))
}

func (l LocalFSPathInternal__) Import() LocalFSPath {
	tmp := (string)(l)
	return LocalFSPath((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (l *LocalFSPath) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LocalFSPath) Decode(dec rpc.Decoder) error {
	var tmp LocalFSPathInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l LocalFSPath) Bytes() []byte {
	return nil
}

type KVDirent struct {
	ParentDir  DirID
	Id         DirentID
	Value      KVNodeID
	Version    KVVersion
	DirVersion KVVersion
	WriteRole  Role
	NameMac    HMAC
	NameBox    SecretBox
	DirStatus  KVDirStatus
	BindingMac HMAC
	Ctime      TimeMicro
}

type KVDirentInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ParentDir  *DirIDInternal__
	Id         *DirentIDInternal__
	Value      *KVNodeIDInternal__
	Version    *KVVersionInternal__
	DirVersion *KVVersionInternal__
	WriteRole  *RoleInternal__
	NameMac    *HMACInternal__
	NameBox    *SecretBoxInternal__
	DirStatus  *KVDirStatusInternal__
	BindingMac *HMACInternal__
	Ctime      *TimeMicroInternal__
}

func (k KVDirentInternal__) Import() KVDirent {
	return KVDirent{
		ParentDir: (func(x *DirIDInternal__) (ret DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.ParentDir),
		Id: (func(x *DirentIDInternal__) (ret DirentID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Id),
		Value: (func(x *KVNodeIDInternal__) (ret KVNodeID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Value),
		Version: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Version),
		DirVersion: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.DirVersion),
		WriteRole: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.WriteRole),
		NameMac: (func(x *HMACInternal__) (ret HMAC) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.NameMac),
		NameBox: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.NameBox),
		DirStatus: (func(x *KVDirStatusInternal__) (ret KVDirStatus) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.DirStatus),
		BindingMac: (func(x *HMACInternal__) (ret HMAC) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.BindingMac),
		Ctime: (func(x *TimeMicroInternal__) (ret TimeMicro) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Ctime),
	}
}

func (k KVDirent) Export() *KVDirentInternal__ {
	return &KVDirentInternal__{
		ParentDir:  k.ParentDir.Export(),
		Id:         k.Id.Export(),
		Value:      k.Value.Export(),
		Version:    k.Version.Export(),
		DirVersion: k.DirVersion.Export(),
		WriteRole:  k.WriteRole.Export(),
		NameMac:    k.NameMac.Export(),
		NameBox:    k.NameBox.Export(),
		DirStatus:  k.DirStatus.Export(),
		BindingMac: k.BindingMac.Export(),
		Ctime:      k.Ctime.Export(),
	}
}

func (k *KVDirent) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVDirent) Decode(dec rpc.Decoder) error {
	var tmp KVDirentInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVDirent) Bytes() []byte { return nil }

type SmallFileBox struct {
	Rg      RoleAndGen
	DataBox NaclCiphertext
}

type SmallFileBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenInternal__
	DataBox *NaclCiphertextInternal__
}

func (s SmallFileBoxInternal__) Import() SmallFileBox {
	return SmallFileBox{
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Rg),
		DataBox: (func(x *NaclCiphertextInternal__) (ret NaclCiphertext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.DataBox),
	}
}

func (s SmallFileBox) Export() *SmallFileBoxInternal__ {
	return &SmallFileBoxInternal__{
		Rg:      s.Rg.Export(),
		DataBox: s.DataBox.Export(),
	}
}

func (s *SmallFileBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SmallFileBox) Decode(dec rpc.Decoder) error {
	var tmp SmallFileBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SmallFileBox) Bytes() []byte { return nil }

type KVNodeID [17]byte
type KVNodeIDInternal__ [17]byte

func (k KVNodeID) Export() *KVNodeIDInternal__ {
	tmp := (([17]byte)(k))
	return ((*KVNodeIDInternal__)(&tmp))
}

func (k KVNodeIDInternal__) Import() KVNodeID {
	tmp := ([17]byte)(k)
	return KVNodeID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KVNodeID) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVNodeID) Decode(dec rpc.Decoder) error {
	var tmp KVNodeIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KVNodeID) Bytes() []byte {
	return (k)[:]
}

type KVDirStatus int

const (
	KVDirStatus_Active     KVDirStatus = 0
	KVDirStatus_Encrypting KVDirStatus = 1
	KVDirStatus_Dead       KVDirStatus = 2
)

var KVDirStatusMap = map[string]KVDirStatus{
	"Active":     0,
	"Encrypting": 1,
	"Dead":       2,
}

var KVDirStatusRevMap = map[KVDirStatus]string{
	0: "Active",
	1: "Encrypting",
	2: "Dead",
}

type KVDirStatusInternal__ KVDirStatus

func (k KVDirStatusInternal__) Import() KVDirStatus {
	return KVDirStatus(k)
}

func (k KVDirStatus) Export() *KVDirStatusInternal__ {
	return ((*KVDirStatusInternal__)(&k))
}

type KVPath string
type KVPathInternal__ string

func (k KVPath) Export() *KVPathInternal__ {
	tmp := ((string)(k))
	return ((*KVPathInternal__)(&tmp))
}

func (k KVPathInternal__) Import() KVPath {
	tmp := (string)(k)
	return KVPath((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KVPath) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVPath) Decode(dec rpc.Decoder) error {
	var tmp KVPathInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KVPathTypeUniqueID = rpc.TypeUniqueID(0xc05a71f8cf1dfa5c)

func (k *KVPath) GetTypeUniqueID() rpc.TypeUniqueID {
	return KVPathTypeUniqueID
}

func (k KVPath) Bytes() []byte {
	return nil
}

type KVListPaginationType int

const (
	KVListPaginationType_None KVListPaginationType = 0
	KVListPaginationType_MAC  KVListPaginationType = 1
	KVListPaginationType_Time KVListPaginationType = 2
)

var KVListPaginationTypeMap = map[string]KVListPaginationType{
	"None": 0,
	"MAC":  1,
	"Time": 2,
}

var KVListPaginationTypeRevMap = map[KVListPaginationType]string{
	0: "None",
	1: "MAC",
	2: "Time",
}

type KVListPaginationTypeInternal__ KVListPaginationType

func (k KVListPaginationTypeInternal__) Import() KVListPaginationType {
	return KVListPaginationType(k)
}

func (k KVListPaginationType) Export() *KVListPaginationTypeInternal__ {
	return ((*KVListPaginationTypeInternal__)(&k))
}

type SeedBox struct {
	Rg  RoleAndGen
	Box SecretBox
}

type SeedBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenInternal__
	Box     *SecretBoxInternal__
}

func (s SeedBoxInternal__) Import() SeedBox {
	return SeedBox{
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Rg),
		Box: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Box),
	}
}

func (s SeedBox) Export() *SeedBoxInternal__ {
	return &SeedBoxInternal__{
		Rg:  s.Rg.Export(),
		Box: s.Box.Export(),
	}
}

func (s *SeedBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SeedBox) Decode(dec rpc.Decoder) error {
	var tmp SeedBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SeedBox) Bytes() []byte { return nil }

type KVListPagination struct {
	T     KVListPaginationType
	F_1__ *HMAC      `json:"f1,omitempty"`
	F_2__ *TimeMicro `json:"f2,omitempty"`
}

type KVListPaginationInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        KVListPaginationType
	Switch__ KVListPaginationInternalSwitch__
}

type KVListPaginationInternalSwitch__ struct {
	_struct struct{}             `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *HMACInternal__      `codec:"1"`
	F_2__   *TimeMicroInternal__ `codec:"2"`
}

func (k KVListPagination) GetT() (ret KVListPaginationType, err error) {
	switch k.T {
	case KVListPaginationType_None:
		break
	case KVListPaginationType_MAC:
		if k.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case KVListPaginationType_Time:
		if k.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	}
	return k.T, nil
}

func (k KVListPagination) Mac() HMAC {
	if k.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if k.T != KVListPaginationType_MAC {
		panic(fmt.Sprintf("unexpected switch value (%v) when Mac is called", k.T))
	}
	return *k.F_1__
}

func (k KVListPagination) Time() TimeMicro {
	if k.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if k.T != KVListPaginationType_Time {
		panic(fmt.Sprintf("unexpected switch value (%v) when Time is called", k.T))
	}
	return *k.F_2__
}

func NewKVListPaginationWithNone() KVListPagination {
	return KVListPagination{
		T: KVListPaginationType_None,
	}
}

func NewKVListPaginationWithMac(v HMAC) KVListPagination {
	return KVListPagination{
		T:     KVListPaginationType_MAC,
		F_1__: &v,
	}
}

func NewKVListPaginationWithTime(v TimeMicro) KVListPagination {
	return KVListPagination{
		T:     KVListPaginationType_Time,
		F_2__: &v,
	}
}

func (k KVListPaginationInternal__) Import() KVListPagination {
	return KVListPagination{
		T: k.T,
		F_1__: (func(x *HMACInternal__) *HMAC {
			if x == nil {
				return nil
			}
			tmp := (func(x *HMACInternal__) (ret HMAC) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_1__),
		F_2__: (func(x *TimeMicroInternal__) *TimeMicro {
			if x == nil {
				return nil
			}
			tmp := (func(x *TimeMicroInternal__) (ret TimeMicro) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_2__),
	}
}

func (k KVListPagination) Export() *KVListPaginationInternal__ {
	return &KVListPaginationInternal__{
		T: k.T,
		Switch__: KVListPaginationInternalSwitch__{
			F_1__: (func(x *HMAC) *HMACInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_1__),
			F_2__: (func(x *TimeMicro) *TimeMicroInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_2__),
		},
	}
}

func (k *KVListPagination) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVListPagination) Decode(dec rpc.Decoder) error {
	var tmp KVListPaginationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVListPagination) Bytes() []byte { return nil }

type ChunkPlaintext []byte
type ChunkPlaintextInternal__ []byte

func (c ChunkPlaintext) Export() *ChunkPlaintextInternal__ {
	tmp := (([]byte)(c))
	return ((*ChunkPlaintextInternal__)(&tmp))
}

func (c ChunkPlaintextInternal__) Import() ChunkPlaintext {
	tmp := ([]byte)(c)
	return ChunkPlaintext((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *ChunkPlaintext) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChunkPlaintext) Decode(dec rpc.Decoder) error {
	var tmp ChunkPlaintextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var ChunkPlaintextTypeUniqueID = rpc.TypeUniqueID(0x8d2e290071d39250)

func (c *ChunkPlaintext) GetTypeUniqueID() rpc.TypeUniqueID {
	return ChunkPlaintextTypeUniqueID
}

func (c ChunkPlaintext) Bytes() []byte {
	return (c)[:]
}

type Size uint64
type SizeInternal__ uint64

func (s Size) Export() *SizeInternal__ {
	tmp := ((uint64)(s))
	return ((*SizeInternal__)(&tmp))
}

func (s SizeInternal__) Import() Size {
	tmp := (uint64)(s)
	return Size((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *Size) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *Size) Decode(dec rpc.Decoder) error {
	var tmp SizeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s Size) Bytes() []byte {
	return nil
}

type KVPathComponent string
type KVPathComponentInternal__ string

func (k KVPathComponent) Export() *KVPathComponentInternal__ {
	tmp := ((string)(k))
	return ((*KVPathComponentInternal__)(&tmp))
}

func (k KVPathComponentInternal__) Import() KVPathComponent {
	tmp := (string)(k)
	return KVPathComponent((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KVPathComponent) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVPathComponent) Decode(dec rpc.Decoder) error {
	var tmp KVPathComponentInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KVPathComponent) Bytes() []byte {
	return nil
}

type KVNameNonce NaclNonce
type KVNameNonceInternal__ NaclNonceInternal__

func (k KVNameNonce) Export() *KVNameNonceInternal__ {
	tmp := ((NaclNonce)(k))
	return ((*KVNameNonceInternal__)(tmp.Export()))
}

func (k KVNameNonceInternal__) Import() KVNameNonce {
	tmp := (NaclNonceInternal__)(k)
	return KVNameNonce((func(x *NaclNonceInternal__) (ret NaclNonce) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (k *KVNameNonce) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVNameNonce) Decode(dec rpc.Decoder) error {
	var tmp KVNameNonceInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KVNameNonce) Bytes() []byte {
	return ((NaclNonce)(k)).Bytes()
}

type KVUploadID [16]byte
type KVUploadIDInternal__ [16]byte

func (k KVUploadID) Export() *KVUploadIDInternal__ {
	tmp := (([16]byte)(k))
	return ((*KVUploadIDInternal__)(&tmp))
}

func (k KVUploadIDInternal__) Import() KVUploadID {
	tmp := ([16]byte)(k)
	return KVUploadID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KVUploadID) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVUploadID) Decode(dec rpc.Decoder) error {
	var tmp KVUploadIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KVUploadID) Bytes() []byte {
	return (k)[:]
}

type Offset uint64
type OffsetInternal__ uint64

func (o Offset) Export() *OffsetInternal__ {
	tmp := ((uint64)(o))
	return ((*OffsetInternal__)(&tmp))
}

func (o OffsetInternal__) Import() Offset {
	tmp := (uint64)(o)
	return Offset((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *Offset) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *Offset) Decode(dec rpc.Decoder) error {
	var tmp OffsetInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o Offset) Bytes() []byte {
	return nil
}

type KVUsageStats struct {
	Num uint64
	Sum Size
}

type KVUsageStatsInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Num     *uint64
	Sum     *SizeInternal__
}

func (k KVUsageStatsInternal__) Import() KVUsageStats {
	return KVUsageStats{
		Num: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(k.Num),
		Sum: (func(x *SizeInternal__) (ret Size) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Sum),
	}
}

func (k KVUsageStats) Export() *KVUsageStatsInternal__ {
	return &KVUsageStatsInternal__{
		Num: &k.Num,
		Sum: k.Sum.Export(),
	}
}

func (k *KVUsageStats) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVUsageStats) Decode(dec rpc.Decoder) error {
	var tmp KVUsageStatsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVUsageStats) Bytes() []byte { return nil }

type KVUsageStatsChunked struct {
	Base      KVUsageStats
	NumChunks uint64
}

type KVUsageStatsChunkedInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Base      *KVUsageStatsInternal__
	NumChunks *uint64
}

func (k KVUsageStatsChunkedInternal__) Import() KVUsageStatsChunked {
	return KVUsageStatsChunked{
		Base: (func(x *KVUsageStatsInternal__) (ret KVUsageStats) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Base),
		NumChunks: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(k.NumChunks),
	}
}

func (k KVUsageStatsChunked) Export() *KVUsageStatsChunkedInternal__ {
	return &KVUsageStatsChunkedInternal__{
		Base:      k.Base.Export(),
		NumChunks: &k.NumChunks,
	}
}

func (k *KVUsageStatsChunked) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVUsageStatsChunked) Decode(dec rpc.Decoder) error {
	var tmp KVUsageStatsChunkedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVUsageStatsChunked) Bytes() []byte { return nil }

type KVUsage struct {
	Small KVUsageStats
	Large KVUsageStatsChunked
}

type KVUsageInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Small   *KVUsageStatsInternal__
	Large   *KVUsageStatsChunkedInternal__
}

func (k KVUsageInternal__) Import() KVUsage {
	return KVUsage{
		Small: (func(x *KVUsageStatsInternal__) (ret KVUsageStats) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Small),
		Large: (func(x *KVUsageStatsChunkedInternal__) (ret KVUsageStatsChunked) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Large),
	}
}

func (k KVUsage) Export() *KVUsageInternal__ {
	return &KVUsageInternal__{
		Small: k.Small.Export(),
		Large: k.Large.Export(),
	}
}

func (k *KVUsage) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVUsage) Decode(dec rpc.Decoder) error {
	var tmp KVUsageInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVUsage) Bytes() []byte { return nil }

type SeedBoxExternalNonce struct {
	Rg    RoleAndGen
	Ctext NaclCiphertext
}

type SeedBoxExternalNonceInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg      *RoleAndGenInternal__
	Ctext   *NaclCiphertextInternal__
}

func (s SeedBoxExternalNonceInternal__) Import() SeedBoxExternalNonce {
	return SeedBoxExternalNonce{
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Rg),
		Ctext: (func(x *NaclCiphertextInternal__) (ret NaclCiphertext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Ctext),
	}
}

func (s SeedBoxExternalNonce) Export() *SeedBoxExternalNonceInternal__ {
	return &SeedBoxExternalNonceInternal__{
		Rg:    s.Rg.Export(),
		Ctext: s.Ctext.Export(),
	}
}

func (s *SeedBoxExternalNonce) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SeedBoxExternalNonce) Decode(dec rpc.Decoder) error {
	var tmp SeedBoxExternalNonceInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SeedBoxExternalNonce) Bytes() []byte { return nil }

type KVDir struct {
	Id        DirID
	Version   KVVersion
	Box       SeedBoxExternalNonce
	WriteRole Role
	Status    KVDirStatus
}

type KVDirInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id        *DirIDInternal__
	Version   *KVVersionInternal__
	Box       *SeedBoxExternalNonceInternal__
	WriteRole *RoleInternal__
	Status    *KVDirStatusInternal__
}

func (k KVDirInternal__) Import() KVDir {
	return KVDir{
		Id: (func(x *DirIDInternal__) (ret DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Id),
		Version: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Version),
		Box: (func(x *SeedBoxExternalNonceInternal__) (ret SeedBoxExternalNonce) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Box),
		WriteRole: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.WriteRole),
		Status: (func(x *KVDirStatusInternal__) (ret KVDirStatus) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Status),
	}
}

func (k KVDir) Export() *KVDirInternal__ {
	return &KVDirInternal__{
		Id:        k.Id.Export(),
		Version:   k.Version.Export(),
		Box:       k.Box.Export(),
		WriteRole: k.WriteRole.Export(),
		Status:    k.Status.Export(),
	}
}

func (k *KVDir) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVDir) Decode(dec rpc.Decoder) error {
	var tmp KVDirInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVDir) Bytes() []byte { return nil }

type KVRoot struct {
	Root       DirID
	Vers       KVVersion
	Rg         RoleAndGen
	BindingMac HMAC
}

type KVRootInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Root       *DirIDInternal__
	Vers       *KVVersionInternal__
	Rg         *RoleAndGenInternal__
	BindingMac *HMACInternal__
}

func (k KVRootInternal__) Import() KVRoot {
	return KVRoot{
		Root: (func(x *DirIDInternal__) (ret DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Root),
		Vers: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Vers),
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Rg),
		BindingMac: (func(x *HMACInternal__) (ret HMAC) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.BindingMac),
	}
}

func (k KVRoot) Export() *KVRootInternal__ {
	return &KVRootInternal__{
		Root:       k.Root.Export(),
		Vers:       k.Vers.Export(),
		Rg:         k.Rg.Export(),
		BindingMac: k.BindingMac.Export(),
	}
}

func (k *KVRoot) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVRoot) Decode(dec rpc.Decoder) error {
	var tmp KVRootInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVRoot) Bytes() []byte { return nil }

type LargeFileMetadata struct {
	Rg             RoleAndGen
	KeySeed        SecretBox
	Vers           KVVersion
	CustomMetadata *SecretBox
}

type LargeFileMetadataInternal__ struct {
	_struct        struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Rg             *RoleAndGenInternal__
	KeySeed        *SecretBoxInternal__
	Vers           *KVVersionInternal__
	CustomMetadata *SecretBoxInternal__
}

func (l LargeFileMetadataInternal__) Import() LargeFileMetadata {
	return LargeFileMetadata{
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Rg),
		KeySeed: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.KeySeed),
		Vers: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Vers),
		CustomMetadata: (func(x *SecretBoxInternal__) *SecretBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *SecretBoxInternal__) (ret SecretBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(l.CustomMetadata),
	}
}

func (l LargeFileMetadata) Export() *LargeFileMetadataInternal__ {
	return &LargeFileMetadataInternal__{
		Rg:      l.Rg.Export(),
		KeySeed: l.KeySeed.Export(),
		Vers:    l.Vers.Export(),
		CustomMetadata: (func(x *SecretBox) *SecretBoxInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(l.CustomMetadata),
	}
}

func (l *LargeFileMetadata) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LargeFileMetadata) Decode(dec rpc.Decoder) error {
	var tmp LargeFileMetadataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LargeFileMetadata) Bytes() []byte { return nil }

type UploadFinal struct {
	Sz       Size
	ChunkSum StdHash
}

type UploadFinalInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Sz       *SizeInternal__
	ChunkSum *StdHashInternal__
}

func (u UploadFinalInternal__) Import() UploadFinal {
	return UploadFinal{
		Sz: (func(x *SizeInternal__) (ret Size) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Sz),
		ChunkSum: (func(x *StdHashInternal__) (ret StdHash) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.ChunkSum),
	}
}

func (u UploadFinal) Export() *UploadFinalInternal__ {
	return &UploadFinalInternal__{
		Sz:       u.Sz.Export(),
		ChunkSum: u.ChunkSum.Export(),
	}
}

func (u *UploadFinal) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UploadFinal) Decode(dec rpc.Decoder) error {
	var tmp UploadFinalInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UploadFinal) Bytes() []byte { return nil }

type UploadChunk struct {
	Data   NaclCiphertext
	Offset Offset
	Final  *UploadFinal
}

type UploadChunkInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Data    *NaclCiphertextInternal__
	Offset  *OffsetInternal__
	Final   *UploadFinalInternal__
}

func (u UploadChunkInternal__) Import() UploadChunk {
	return UploadChunk{
		Data: (func(x *NaclCiphertextInternal__) (ret NaclCiphertext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Data),
		Offset: (func(x *OffsetInternal__) (ret Offset) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(u.Offset),
		Final: (func(x *UploadFinalInternal__) *UploadFinal {
			if x == nil {
				return nil
			}
			tmp := (func(x *UploadFinalInternal__) (ret UploadFinal) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(u.Final),
	}
}

func (u UploadChunk) Export() *UploadChunkInternal__ {
	return &UploadChunkInternal__{
		Data:   u.Data.Export(),
		Offset: u.Offset.Export(),
		Final: (func(x *UploadFinal) *UploadFinalInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(u.Final),
	}
}

func (u *UploadChunk) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UploadChunk) Decode(dec rpc.Decoder) error {
	var tmp UploadChunkInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u *UploadChunk) Bytes() []byte { return nil }

type KVExtendedDirent struct {
	Pos uint64
	Sfb SmallFileBox
}

type KVExtendedDirentInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Pos     *uint64
	Sfb     *SmallFileBoxInternal__
}

func (k KVExtendedDirentInternal__) Import() KVExtendedDirent {
	return KVExtendedDirent{
		Pos: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(k.Pos),
		Sfb: (func(x *SmallFileBoxInternal__) (ret SmallFileBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Sfb),
	}
}

func (k KVExtendedDirent) Export() *KVExtendedDirentInternal__ {
	return &KVExtendedDirentInternal__{
		Pos: &k.Pos,
		Sfb: k.Sfb.Export(),
	}
}

func (k *KVExtendedDirent) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVExtendedDirent) Decode(dec rpc.Decoder) error {
	var tmp KVExtendedDirentInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVExtendedDirent) Bytes() []byte { return nil }

type KVDirentIDPair struct {
	ParentDirID DirID
	DirentID    DirentID
}

type KVDirentIDPairInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ParentDirID *DirIDInternal__
	DirentID    *DirentIDInternal__
}

func (k KVDirentIDPairInternal__) Import() KVDirentIDPair {
	return KVDirentIDPair{
		ParentDirID: (func(x *DirIDInternal__) (ret DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.ParentDirID),
		DirentID: (func(x *DirentIDInternal__) (ret DirentID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.DirentID),
	}
}

func (k KVDirentIDPair) Export() *KVDirentIDPairInternal__ {
	return &KVDirentIDPairInternal__{
		ParentDirID: k.ParentDirID.Export(),
		DirentID:    k.DirentID.Export(),
	}
}

func (k *KVDirentIDPair) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVDirentIDPair) Decode(dec rpc.Decoder) error {
	var tmp KVDirentIDPairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVDirentIDPair) Bytes() []byte { return nil }

type KVDirPair struct {
	Active     KVDir
	Encrypting *KVDir
}

type KVDirPairInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Active     *KVDirInternal__
	Encrypting *KVDirInternal__
}

func (k KVDirPairInternal__) Import() KVDirPair {
	return KVDirPair{
		Active: (func(x *KVDirInternal__) (ret KVDir) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Active),
		Encrypting: (func(x *KVDirInternal__) *KVDir {
			if x == nil {
				return nil
			}
			tmp := (func(x *KVDirInternal__) (ret KVDir) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Encrypting),
	}
}

func (k KVDirPair) Export() *KVDirPairInternal__ {
	return &KVDirPairInternal__{
		Active: k.Active.Export(),
		Encrypting: (func(x *KVDir) *KVDirInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(k.Encrypting),
	}
}

func (k *KVDirPair) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVDirPair) Decode(dec rpc.Decoder) error {
	var tmp KVDirPairInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVDirPair) Bytes() []byte { return nil }

type Chunk []byte
type ChunkInternal__ []byte

func (c Chunk) Export() *ChunkInternal__ {
	tmp := (([]byte)(c))
	return ((*ChunkInternal__)(&tmp))
}

func (c ChunkInternal__) Import() Chunk {
	tmp := ([]byte)(c)
	return Chunk((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *Chunk) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *Chunk) Decode(dec rpc.Decoder) error {
	var tmp ChunkInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c Chunk) Bytes() []byte {
	return (c)[:]
}

type KVDirentBindingPayload struct {
	ParentDir  DirID
	Id         DirentID
	Value      KVNodeID
	Version    KVVersion
	DirVersion KVVersion
	WriteRole  Role
	NameMac    HMAC
	NameBox    SecretBox
}

type KVDirentBindingPayloadInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ParentDir  *DirIDInternal__
	Id         *DirentIDInternal__
	Value      *KVNodeIDInternal__
	Version    *KVVersionInternal__
	DirVersion *KVVersionInternal__
	WriteRole  *RoleInternal__
	NameMac    *HMACInternal__
	NameBox    *SecretBoxInternal__
}

func (k KVDirentBindingPayloadInternal__) Import() KVDirentBindingPayload {
	return KVDirentBindingPayload{
		ParentDir: (func(x *DirIDInternal__) (ret DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.ParentDir),
		Id: (func(x *DirentIDInternal__) (ret DirentID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Id),
		Value: (func(x *KVNodeIDInternal__) (ret KVNodeID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Value),
		Version: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Version),
		DirVersion: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.DirVersion),
		WriteRole: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.WriteRole),
		NameMac: (func(x *HMACInternal__) (ret HMAC) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.NameMac),
		NameBox: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.NameBox),
	}
}

func (k KVDirentBindingPayload) Export() *KVDirentBindingPayloadInternal__ {
	return &KVDirentBindingPayloadInternal__{
		ParentDir:  k.ParentDir.Export(),
		Id:         k.Id.Export(),
		Value:      k.Value.Export(),
		Version:    k.Version.Export(),
		DirVersion: k.DirVersion.Export(),
		WriteRole:  k.WriteRole.Export(),
		NameMac:    k.NameMac.Export(),
		NameBox:    k.NameBox.Export(),
	}
}

func (k *KVDirentBindingPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVDirentBindingPayload) Decode(dec rpc.Decoder) error {
	var tmp KVDirentBindingPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KVDirentBindingPayloadTypeUniqueID = rpc.TypeUniqueID(0x9cc37c8363dc39fa)

func (k *KVDirentBindingPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return KVDirentBindingPayloadTypeUniqueID
}

func (k *KVDirentBindingPayload) Bytes() []byte { return nil }

type KVRootBindingPayload struct {
	Party FQParty
	Rg    RoleAndGen
	Root  DirID
	Vers  KVVersion
}

type KVRootBindingPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Party   *FQPartyInternal__
	Rg      *RoleAndGenInternal__
	Root    *DirIDInternal__
	Vers    *KVVersionInternal__
}

func (k KVRootBindingPayloadInternal__) Import() KVRootBindingPayload {
	return KVRootBindingPayload{
		Party: (func(x *FQPartyInternal__) (ret FQParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Party),
		Rg: (func(x *RoleAndGenInternal__) (ret RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Rg),
		Root: (func(x *DirIDInternal__) (ret DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Root),
		Vers: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Vers),
	}
}

func (k KVRootBindingPayload) Export() *KVRootBindingPayloadInternal__ {
	return &KVRootBindingPayloadInternal__{
		Party: k.Party.Export(),
		Rg:    k.Rg.Export(),
		Root:  k.Root.Export(),
		Vers:  k.Vers.Export(),
	}
}

func (k *KVRootBindingPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVRootBindingPayload) Decode(dec rpc.Decoder) error {
	var tmp KVRootBindingPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KVRootBindingPayloadTypeUniqueID = rpc.TypeUniqueID(0xcfacdd4eab213a36)

func (k *KVRootBindingPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return KVRootBindingPayloadTypeUniqueID
}

func (k *KVRootBindingPayload) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(FileKeySeedTypeUniqueID)
	rpc.AddUnique(DirKeySeedTypeUniqueID)
	rpc.AddUnique(KVNamePlaintextTypeUniqueID)
	rpc.AddUnique(KVNameNonceInputTypeUniqueID)
	rpc.AddUnique(KVPathTypeUniqueID)
	rpc.AddUnique(ChunkPlaintextTypeUniqueID)
	rpc.AddUnique(KVDirentBindingPayloadTypeUniqueID)
	rpc.AddUnique(KVRootBindingPayloadTypeUniqueID)
}
