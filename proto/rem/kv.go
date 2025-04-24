// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/rem/kv.snowp

package rem

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type KVAuthType int

const (
	KVAuthType_User KVAuthType = 0
	KVAuthType_Team KVAuthType = 1
)

var KVAuthTypeMap = map[string]KVAuthType{
	"User": 0,
	"Team": 1,
}

var KVAuthTypeRevMap = map[KVAuthType]string{
	0: "User",
	1: "Team",
}

type KVAuthTypeInternal__ KVAuthType

func (k KVAuthTypeInternal__) Import() KVAuthType {
	return KVAuthType(k)
}

func (k KVAuthType) Export() *KVAuthTypeInternal__ {
	return ((*KVAuthTypeInternal__)(&k))
}

type KVAuth struct {
	T     KVAuthType
	F_1__ *TeamVOBearerToken `json:"f1,omitempty"`
}

type KVAuthInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        KVAuthType
	Switch__ KVAuthInternalSwitch__
}

type KVAuthInternalSwitch__ struct {
	_struct struct{}                     `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *TeamVOBearerTokenInternal__ `codec:"1"`
}

func (k KVAuth) GetT() (ret KVAuthType, err error) {
	switch k.T {
	case KVAuthType_Team:
		if k.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return k.T, nil
}

func (k KVAuth) Team() TeamVOBearerToken {
	if k.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if k.T != KVAuthType_Team {
		panic(fmt.Sprintf("unexpected switch value (%v) when Team is called", k.T))
	}
	return *k.F_1__
}

func NewKVAuthWithTeam(v TeamVOBearerToken) KVAuth {
	return KVAuth{
		T:     KVAuthType_Team,
		F_1__: &v,
	}
}

func (k KVAuthInternal__) Import() KVAuth {
	return KVAuth{
		T: k.T,
		F_1__: (func(x *TeamVOBearerTokenInternal__) *TeamVOBearerToken {
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
		})(k.Switch__.F_1__),
	}
}

func (k KVAuth) Export() *KVAuthInternal__ {
	return &KVAuthInternal__{
		T: k.T,
		Switch__: KVAuthInternalSwitch__{
			F_1__: (func(x *TeamVOBearerToken) *TeamVOBearerTokenInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_1__),
		},
	}
}

func (k *KVAuth) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVAuth) Decode(dec rpc.Decoder) error {
	var tmp KVAuthInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVAuth) Bytes() []byte { return nil }

type KVReqHeader struct {
	Auth         KVAuth
	Precondition *lib.PathVersionVector
}

type KVReqHeaderInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth         *KVAuthInternal__
	Precondition *lib.PathVersionVectorInternal__
}

func (k KVReqHeaderInternal__) Import() KVReqHeader {
	return KVReqHeader{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		Precondition: (func(x *lib.PathVersionVectorInternal__) *lib.PathVersionVector {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.PathVersionVectorInternal__) (ret lib.PathVersionVector) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Precondition),
	}
}

func (k KVReqHeader) Export() *KVReqHeaderInternal__ {
	return &KVReqHeaderInternal__{
		Auth: k.Auth.Export(),
		Precondition: (func(x *lib.PathVersionVector) *lib.PathVersionVectorInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(k.Precondition),
	}
}

func (k *KVReqHeader) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVReqHeader) Decode(dec rpc.Decoder) error {
	var tmp KVReqHeaderInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVReqHeader) Bytes() []byte { return nil }

type KVNameMACAtDirVersion struct {
	DirVers lib.KVVersion
	Mac     lib.HMAC
}

type KVNameMACAtDirVersionInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	DirVers *lib.KVVersionInternal__
	Mac     *lib.HMACInternal__
}

func (k KVNameMACAtDirVersionInternal__) Import() KVNameMACAtDirVersion {
	return KVNameMACAtDirVersion{
		DirVers: (func(x *lib.KVVersionInternal__) (ret lib.KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.DirVers),
		Mac: (func(x *lib.HMACInternal__) (ret lib.HMAC) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Mac),
	}
}

func (k KVNameMACAtDirVersion) Export() *KVNameMACAtDirVersionInternal__ {
	return &KVNameMACAtDirVersionInternal__{
		DirVers: k.DirVers.Export(),
		Mac:     k.Mac.Export(),
	}
}

func (k *KVNameMACAtDirVersion) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVNameMACAtDirVersion) Decode(dec rpc.Decoder) error {
	var tmp KVNameMACAtDirVersionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVNameMACAtDirVersion) Bytes() []byte { return nil }

type KVNodePathMultiple struct {
	ParentDir lib.DirID
	Names     []KVNameMACAtDirVersion
}

type KVNodePathMultipleInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ParentDir *lib.DirIDInternal__
	Names     *[](*KVNameMACAtDirVersionInternal__)
}

func (k KVNodePathMultipleInternal__) Import() KVNodePathMultiple {
	return KVNodePathMultiple{
		ParentDir: (func(x *lib.DirIDInternal__) (ret lib.DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.ParentDir),
		Names: (func(x *[](*KVNameMACAtDirVersionInternal__)) (ret []KVNameMACAtDirVersion) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]KVNameMACAtDirVersion, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *KVNameMACAtDirVersionInternal__) (ret KVNameMACAtDirVersion) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(k.Names),
	}
}

func (k KVNodePathMultiple) Export() *KVNodePathMultipleInternal__ {
	return &KVNodePathMultipleInternal__{
		ParentDir: k.ParentDir.Export(),
		Names: (func(x []KVNameMACAtDirVersion) *[](*KVNameMACAtDirVersionInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*KVNameMACAtDirVersionInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(k.Names),
	}
}

func (k *KVNodePathMultiple) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVNodePathMultiple) Decode(dec rpc.Decoder) error {
	var tmp KVNodePathMultipleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KVNodePathMultipleTypeUniqueID = rpc.TypeUniqueID(0xa191f889d8296b64)

func (k *KVNodePathMultiple) GetTypeUniqueID() rpc.TypeUniqueID {
	return KVNodePathMultipleTypeUniqueID
}

func (k *KVNodePathMultiple) Bytes() []byte { return nil }

type FollowBehavior int

const (
	FollowBehavior_None    FollowBehavior = 0
	FollowBehavior_DirOnly FollowBehavior = 1
	FollowBehavior_Any     FollowBehavior = 2
)

var FollowBehaviorMap = map[string]FollowBehavior{
	"None":    0,
	"DirOnly": 1,
	"Any":     2,
}

var FollowBehaviorRevMap = map[FollowBehavior]string{
	0: "None",
	1: "DirOnly",
	2: "Any",
}

type FollowBehaviorInternal__ FollowBehavior

func (f FollowBehaviorInternal__) Import() FollowBehavior {
	return FollowBehavior(f)
}

func (f FollowBehavior) Export() *FollowBehaviorInternal__ {
	return ((*FollowBehaviorInternal__)(&f))
}

type KVGetNodeRes struct {
	T     lib.KVNodeType
	F_0__ *lib.LargeFileMetadata `json:"f0,omitempty"`
	F_2__ *lib.SmallFileBox      `json:"f2,omitempty"`
	F_3__ *lib.SmallFileBox      `json:"f3,omitempty"`
	F_4__ *lib.KVDirPair         `json:"f4,omitempty"`
}

type KVGetNodeResInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        lib.KVNodeType
	Switch__ KVGetNodeResInternalSwitch__
}

type KVGetNodeResInternalSwitch__ struct {
	_struct struct{}                         `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *lib.LargeFileMetadataInternal__ `codec:"0"`
	F_2__   *lib.SmallFileBoxInternal__      `codec:"2"`
	F_3__   *lib.SmallFileBoxInternal__      `codec:"3"`
	F_4__   *lib.KVDirPairInternal__         `codec:"4"`
}

func (k KVGetNodeRes) GetT() (ret lib.KVNodeType, err error) {
	switch k.T {
	case lib.KVNodeType_File:
		if k.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case lib.KVNodeType_SmallFile:
		if k.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case lib.KVNodeType_Symlink:
		if k.F_3__ == nil {
			return ret, errors.New("unexpected nil case for F_3__")
		}
	case lib.KVNodeType_Dir:
		if k.F_4__ == nil {
			return ret, errors.New("unexpected nil case for F_4__")
		}
	}
	return k.T, nil
}

func (k KVGetNodeRes) File() lib.LargeFileMetadata {
	if k.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if k.T != lib.KVNodeType_File {
		panic(fmt.Sprintf("unexpected switch value (%v) when File is called", k.T))
	}
	return *k.F_0__
}

func (k KVGetNodeRes) Smallfile() lib.SmallFileBox {
	if k.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if k.T != lib.KVNodeType_SmallFile {
		panic(fmt.Sprintf("unexpected switch value (%v) when Smallfile is called", k.T))
	}
	return *k.F_2__
}

func (k KVGetNodeRes) Symlink() lib.SmallFileBox {
	if k.F_3__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if k.T != lib.KVNodeType_Symlink {
		panic(fmt.Sprintf("unexpected switch value (%v) when Symlink is called", k.T))
	}
	return *k.F_3__
}

func (k KVGetNodeRes) Dir() lib.KVDirPair {
	if k.F_4__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if k.T != lib.KVNodeType_Dir {
		panic(fmt.Sprintf("unexpected switch value (%v) when Dir is called", k.T))
	}
	return *k.F_4__
}

func NewKVGetNodeResWithFile(v lib.LargeFileMetadata) KVGetNodeRes {
	return KVGetNodeRes{
		T:     lib.KVNodeType_File,
		F_0__: &v,
	}
}

func NewKVGetNodeResWithSmallfile(v lib.SmallFileBox) KVGetNodeRes {
	return KVGetNodeRes{
		T:     lib.KVNodeType_SmallFile,
		F_2__: &v,
	}
}

func NewKVGetNodeResWithSymlink(v lib.SmallFileBox) KVGetNodeRes {
	return KVGetNodeRes{
		T:     lib.KVNodeType_Symlink,
		F_3__: &v,
	}
}

func NewKVGetNodeResWithDir(v lib.KVDirPair) KVGetNodeRes {
	return KVGetNodeRes{
		T:     lib.KVNodeType_Dir,
		F_4__: &v,
	}
}

func (k KVGetNodeResInternal__) Import() KVGetNodeRes {
	return KVGetNodeRes{
		T: k.T,
		F_0__: (func(x *lib.LargeFileMetadataInternal__) *lib.LargeFileMetadata {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.LargeFileMetadataInternal__) (ret lib.LargeFileMetadata) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_0__),
		F_2__: (func(x *lib.SmallFileBoxInternal__) *lib.SmallFileBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.SmallFileBoxInternal__) (ret lib.SmallFileBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_2__),
		F_3__: (func(x *lib.SmallFileBoxInternal__) *lib.SmallFileBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.SmallFileBoxInternal__) (ret lib.SmallFileBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_3__),
		F_4__: (func(x *lib.KVDirPairInternal__) *lib.KVDirPair {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.KVDirPairInternal__) (ret lib.KVDirPair) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_4__),
	}
}

func (k KVGetNodeRes) Export() *KVGetNodeResInternal__ {
	return &KVGetNodeResInternal__{
		T: k.T,
		Switch__: KVGetNodeResInternalSwitch__{
			F_0__: (func(x *lib.LargeFileMetadata) *lib.LargeFileMetadataInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_0__),
			F_2__: (func(x *lib.SmallFileBox) *lib.SmallFileBoxInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_2__),
			F_3__: (func(x *lib.SmallFileBox) *lib.SmallFileBoxInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_3__),
			F_4__: (func(x *lib.KVDirPair) *lib.KVDirPairInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_4__),
		},
	}
}

func (k *KVGetNodeRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVGetNodeRes) Decode(dec rpc.Decoder) error {
	var tmp KVGetNodeResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVGetNodeRes) Bytes() []byte { return nil }

type KVGetRes struct {
	De   lib.KVDirent
	Data *KVGetNodeRes
}

type KVGetResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	De      *lib.KVDirentInternal__
	Data    *KVGetNodeResInternal__
}

func (k KVGetResInternal__) Import() KVGetRes {
	return KVGetRes{
		De: (func(x *lib.KVDirentInternal__) (ret lib.KVDirent) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.De),
		Data: (func(x *KVGetNodeResInternal__) *KVGetNodeRes {
			if x == nil {
				return nil
			}
			tmp := (func(x *KVGetNodeResInternal__) (ret KVGetNodeRes) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Data),
	}
}

func (k KVGetRes) Export() *KVGetResInternal__ {
	return &KVGetResInternal__{
		De: k.De.Export(),
		Data: (func(x *KVGetNodeRes) *KVGetNodeResInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(k.Data),
	}
}

func (k *KVGetRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVGetRes) Decode(dec rpc.Decoder) error {
	var tmp KVGetResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVGetRes) Bytes() []byte { return nil }

type GetEncryptedChunkRes struct {
	Chunk  lib.Chunk
	Offset lib.Offset
	Final  bool
}

type GetEncryptedChunkResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Chunk   *lib.ChunkInternal__
	Offset  *lib.OffsetInternal__
	Final   *bool
}

func (g GetEncryptedChunkResInternal__) Import() GetEncryptedChunkRes {
	return GetEncryptedChunkRes{
		Chunk: (func(x *lib.ChunkInternal__) (ret lib.Chunk) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Chunk),
		Offset: (func(x *lib.OffsetInternal__) (ret lib.Offset) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Offset),
		Final: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(g.Final),
	}
}

func (g GetEncryptedChunkRes) Export() *GetEncryptedChunkResInternal__ {
	return &GetEncryptedChunkResInternal__{
		Chunk:  g.Chunk.Export(),
		Offset: g.Offset.Export(),
		Final:  &g.Final,
	}
}

func (g *GetEncryptedChunkRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetEncryptedChunkRes) Decode(dec rpc.Decoder) error {
	var tmp GetEncryptedChunkResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetEncryptedChunkRes) Bytes() []byte { return nil }

type KVListOpts struct {
	Start          lib.KVListPagination
	Num            uint64
	LoadSmallFiles bool
}

type KVListOptsInternal__ struct {
	_struct        struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Start          *lib.KVListPaginationInternal__
	Num            *uint64
	LoadSmallFiles *bool
}

func (k KVListOptsInternal__) Import() KVListOpts {
	return KVListOpts{
		Start: (func(x *lib.KVListPaginationInternal__) (ret lib.KVListPagination) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Start),
		Num: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(k.Num),
		LoadSmallFiles: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(k.LoadSmallFiles),
	}
}

func (k KVListOpts) Export() *KVListOptsInternal__ {
	return &KVListOptsInternal__{
		Start:          k.Start.Export(),
		Num:            &k.Num,
		LoadSmallFiles: &k.LoadSmallFiles,
	}
}

func (k *KVListOpts) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVListOpts) Decode(dec rpc.Decoder) error {
	var tmp KVListOptsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVListOpts) Bytes() []byte { return nil }

type KVListRes struct {
	Ents    []lib.KVDirent
	Final   bool
	ExtEnts []lib.KVExtendedDirent
}

type KVListResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ents    *[](*lib.KVDirentInternal__)
	Final   *bool
	ExtEnts *[](*lib.KVExtendedDirentInternal__)
}

func (k KVListResInternal__) Import() KVListRes {
	return KVListRes{
		Ents: (func(x *[](*lib.KVDirentInternal__)) (ret []lib.KVDirent) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.KVDirent, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.KVDirentInternal__) (ret lib.KVDirent) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(k.Ents),
		Final: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(k.Final),
		ExtEnts: (func(x *[](*lib.KVExtendedDirentInternal__)) (ret []lib.KVExtendedDirent) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.KVExtendedDirent, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.KVExtendedDirentInternal__) (ret lib.KVExtendedDirent) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(k.ExtEnts),
	}
}

func (k KVListRes) Export() *KVListResInternal__ {
	return &KVListResInternal__{
		Ents: (func(x []lib.KVDirent) *[](*lib.KVDirentInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.KVDirentInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(k.Ents),
		Final: &k.Final,
		ExtEnts: (func(x []lib.KVExtendedDirent) *[](*lib.KVExtendedDirentInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.KVExtendedDirentInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(k.ExtEnts),
	}
}

func (k *KVListRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVListRes) Decode(dec rpc.Decoder) error {
	var tmp KVListResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVListRes) Bytes() []byte { return nil }

type LockID [16]byte
type LockIDInternal__ [16]byte

func (l LockID) Export() *LockIDInternal__ {
	tmp := (([16]byte)(l))
	return ((*LockIDInternal__)(&tmp))
}

func (l LockIDInternal__) Import() LockID {
	tmp := ([16]byte)(l)
	return LockID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (l *LockID) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LockID) Decode(dec rpc.Decoder) error {
	var tmp LockIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l LockID) Bytes() []byte {
	return (l)[:]
}

type KVLock struct {
	Idp    lib.KVDirentIDPair
	LockID LockID
}

type KVLockInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Idp     *lib.KVDirentIDPairInternal__
	LockID  *LockIDInternal__
}

func (k KVLockInternal__) Import() KVLock {
	return KVLock{
		Idp: (func(x *lib.KVDirentIDPairInternal__) (ret lib.KVDirentIDPair) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Idp),
		LockID: (func(x *LockIDInternal__) (ret LockID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.LockID),
	}
}

func (k KVLock) Export() *KVLockInternal__ {
	return &KVLockInternal__{
		Idp:    k.Idp.Export(),
		LockID: k.LockID.Export(),
	}
}

func (k *KVLock) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVLock) Decode(dec rpc.Decoder) error {
	var tmp KVLockInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVLock) Bytes() []byte { return nil }

var KVStoreProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x8ee37b6b)

type KvMkdirArg struct {
	Hdr KVReqHeader
	Dir lib.KVDir
}

type KvMkdirArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Hdr     *KVReqHeaderInternal__
	Dir     *lib.KVDirInternal__
}

func (k KvMkdirArgInternal__) Import() KvMkdirArg {
	return KvMkdirArg{
		Hdr: (func(x *KVReqHeaderInternal__) (ret KVReqHeader) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Hdr),
		Dir: (func(x *lib.KVDirInternal__) (ret lib.KVDir) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Dir),
	}
}

func (k KvMkdirArg) Export() *KvMkdirArgInternal__ {
	return &KvMkdirArgInternal__{
		Hdr: k.Hdr.Export(),
		Dir: k.Dir.Export(),
	}
}

func (k *KvMkdirArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvMkdirArg) Decode(dec rpc.Decoder) error {
	var tmp KvMkdirArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvMkdirArg) Bytes() []byte { return nil }

type KvPutArg struct {
	Hdr     KVReqHeader
	Dirents []lib.KVDirent
}

type KvPutArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Hdr     *KVReqHeaderInternal__
	Dirents *[](*lib.KVDirentInternal__)
}

func (k KvPutArgInternal__) Import() KvPutArg {
	return KvPutArg{
		Hdr: (func(x *KVReqHeaderInternal__) (ret KVReqHeader) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Hdr),
		Dirents: (func(x *[](*lib.KVDirentInternal__)) (ret []lib.KVDirent) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.KVDirent, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.KVDirentInternal__) (ret lib.KVDirent) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(k.Dirents),
	}
}

func (k KvPutArg) Export() *KvPutArgInternal__ {
	return &KvPutArgInternal__{
		Hdr: k.Hdr.Export(),
		Dirents: (func(x []lib.KVDirent) *[](*lib.KVDirentInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.KVDirentInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(k.Dirents),
	}
}

func (k *KvPutArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvPutArg) Decode(dec rpc.Decoder) error {
	var tmp KvPutArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvPutArg) Bytes() []byte { return nil }

type KvPutRootArg struct {
	Auth KVAuth
	Root lib.KVRoot
}

type KvPutRootArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	Root    *lib.KVRootInternal__
}

func (k KvPutRootArgInternal__) Import() KvPutRootArg {
	return KvPutRootArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		Root: (func(x *lib.KVRootInternal__) (ret lib.KVRoot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Root),
	}
}

func (k KvPutRootArg) Export() *KvPutRootArgInternal__ {
	return &KvPutRootArgInternal__{
		Auth: k.Auth.Export(),
		Root: k.Root.Export(),
	}
}

func (k *KvPutRootArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvPutRootArg) Decode(dec rpc.Decoder) error {
	var tmp KvPutRootArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvPutRootArg) Bytes() []byte { return nil }

type KvFileUploadInitArg struct {
	Auth   KVAuth
	FileID lib.FileID
	Md     lib.LargeFileMetadata
	Chunk  lib.UploadChunk
}

type KvFileUploadInitArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	FileID  *lib.FileIDInternal__
	Md      *lib.LargeFileMetadataInternal__
	Chunk   *lib.UploadChunkInternal__
}

func (k KvFileUploadInitArgInternal__) Import() KvFileUploadInitArg {
	return KvFileUploadInitArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		FileID: (func(x *lib.FileIDInternal__) (ret lib.FileID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.FileID),
		Md: (func(x *lib.LargeFileMetadataInternal__) (ret lib.LargeFileMetadata) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Md),
		Chunk: (func(x *lib.UploadChunkInternal__) (ret lib.UploadChunk) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Chunk),
	}
}

func (k KvFileUploadInitArg) Export() *KvFileUploadInitArgInternal__ {
	return &KvFileUploadInitArgInternal__{
		Auth:   k.Auth.Export(),
		FileID: k.FileID.Export(),
		Md:     k.Md.Export(),
		Chunk:  k.Chunk.Export(),
	}
}

func (k *KvFileUploadInitArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvFileUploadInitArg) Decode(dec rpc.Decoder) error {
	var tmp KvFileUploadInitArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvFileUploadInitArg) Bytes() []byte { return nil }

type KvFileUploadChunkArg struct {
	Auth   KVAuth
	FileID lib.FileID
	Chunk  lib.UploadChunk
}

type KvFileUploadChunkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	FileID  *lib.FileIDInternal__
	Chunk   *lib.UploadChunkInternal__
}

func (k KvFileUploadChunkArgInternal__) Import() KvFileUploadChunkArg {
	return KvFileUploadChunkArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		FileID: (func(x *lib.FileIDInternal__) (ret lib.FileID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.FileID),
		Chunk: (func(x *lib.UploadChunkInternal__) (ret lib.UploadChunk) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Chunk),
	}
}

func (k KvFileUploadChunkArg) Export() *KvFileUploadChunkArgInternal__ {
	return &KvFileUploadChunkArgInternal__{
		Auth:   k.Auth.Export(),
		FileID: k.FileID.Export(),
		Chunk:  k.Chunk.Export(),
	}
}

func (k *KvFileUploadChunkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvFileUploadChunkArg) Decode(dec rpc.Decoder) error {
	var tmp KvFileUploadChunkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvFileUploadChunkArg) Bytes() []byte { return nil }

type KvPutSmallFileOrSymlinkArg struct {
	Auth KVAuth
	Id   lib.KVNodeID
	Sfb  lib.SmallFileBox
}

type KvPutSmallFileOrSymlinkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	Id      *lib.KVNodeIDInternal__
	Sfb     *lib.SmallFileBoxInternal__
}

func (k KvPutSmallFileOrSymlinkArgInternal__) Import() KvPutSmallFileOrSymlinkArg {
	return KvPutSmallFileOrSymlinkArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		Id: (func(x *lib.KVNodeIDInternal__) (ret lib.KVNodeID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Id),
		Sfb: (func(x *lib.SmallFileBoxInternal__) (ret lib.SmallFileBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Sfb),
	}
}

func (k KvPutSmallFileOrSymlinkArg) Export() *KvPutSmallFileOrSymlinkArgInternal__ {
	return &KvPutSmallFileOrSymlinkArgInternal__{
		Auth: k.Auth.Export(),
		Id:   k.Id.Export(),
		Sfb:  k.Sfb.Export(),
	}
}

func (k *KvPutSmallFileOrSymlinkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvPutSmallFileOrSymlinkArg) Decode(dec rpc.Decoder) error {
	var tmp KvPutSmallFileOrSymlinkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvPutSmallFileOrSymlinkArg) Bytes() []byte { return nil }

type KvGetRootArg struct {
	Auth KVAuth
}

type KvGetRootArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
}

func (k KvGetRootArgInternal__) Import() KvGetRootArg {
	return KvGetRootArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
	}
}

func (k KvGetRootArg) Export() *KvGetRootArgInternal__ {
	return &KvGetRootArgInternal__{
		Auth: k.Auth.Export(),
	}
}

func (k *KvGetRootArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvGetRootArg) Decode(dec rpc.Decoder) error {
	var tmp KvGetRootArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvGetRootArg) Bytes() []byte { return nil }

type KvGetArg struct {
	Hdr    KVReqHeader
	Path   KVNodePathMultiple
	Follow FollowBehavior
}

type KvGetArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Hdr     *KVReqHeaderInternal__
	Path    *KVNodePathMultipleInternal__
	Follow  *FollowBehaviorInternal__
}

func (k KvGetArgInternal__) Import() KvGetArg {
	return KvGetArg{
		Hdr: (func(x *KVReqHeaderInternal__) (ret KVReqHeader) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Hdr),
		Path: (func(x *KVNodePathMultipleInternal__) (ret KVNodePathMultiple) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Path),
		Follow: (func(x *FollowBehaviorInternal__) (ret FollowBehavior) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Follow),
	}
}

func (k KvGetArg) Export() *KvGetArgInternal__ {
	return &KvGetArgInternal__{
		Hdr:    k.Hdr.Export(),
		Path:   k.Path.Export(),
		Follow: k.Follow.Export(),
	}
}

func (k *KvGetArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvGetArg) Decode(dec rpc.Decoder) error {
	var tmp KvGetArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvGetArg) Bytes() []byte { return nil }

type KvGetNodeArg struct {
	Auth KVAuth
	Id   lib.KVNodeID
}

type KvGetNodeArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	Id      *lib.KVNodeIDInternal__
}

func (k KvGetNodeArgInternal__) Import() KvGetNodeArg {
	return KvGetNodeArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		Id: (func(x *lib.KVNodeIDInternal__) (ret lib.KVNodeID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Id),
	}
}

func (k KvGetNodeArg) Export() *KvGetNodeArgInternal__ {
	return &KvGetNodeArgInternal__{
		Auth: k.Auth.Export(),
		Id:   k.Id.Export(),
	}
}

func (k *KvGetNodeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvGetNodeArg) Decode(dec rpc.Decoder) error {
	var tmp KvGetNodeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvGetNodeArg) Bytes() []byte { return nil }

type KvGetEncryptedChunkArg struct {
	Auth   KVAuth
	Id     lib.FileID
	Offset lib.Offset
}

type KvGetEncryptedChunkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	Id      *lib.FileIDInternal__
	Offset  *lib.OffsetInternal__
}

func (k KvGetEncryptedChunkArgInternal__) Import() KvGetEncryptedChunkArg {
	return KvGetEncryptedChunkArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		Id: (func(x *lib.FileIDInternal__) (ret lib.FileID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Id),
		Offset: (func(x *lib.OffsetInternal__) (ret lib.Offset) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Offset),
	}
}

func (k KvGetEncryptedChunkArg) Export() *KvGetEncryptedChunkArgInternal__ {
	return &KvGetEncryptedChunkArgInternal__{
		Auth:   k.Auth.Export(),
		Id:     k.Id.Export(),
		Offset: k.Offset.Export(),
	}
}

func (k *KvGetEncryptedChunkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvGetEncryptedChunkArg) Decode(dec rpc.Decoder) error {
	var tmp KvGetEncryptedChunkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvGetEncryptedChunkArg) Bytes() []byte { return nil }

type KvGetDirArg struct {
	Auth KVAuth
	Id   lib.DirID
}

type KvGetDirArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	Id      *lib.DirIDInternal__
}

func (k KvGetDirArgInternal__) Import() KvGetDirArg {
	return KvGetDirArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		Id: (func(x *lib.DirIDInternal__) (ret lib.DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Id),
	}
}

func (k KvGetDirArg) Export() *KvGetDirArgInternal__ {
	return &KvGetDirArgInternal__{
		Auth: k.Auth.Export(),
		Id:   k.Id.Export(),
	}
}

func (k *KvGetDirArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvGetDirArg) Decode(dec rpc.Decoder) error {
	var tmp KvGetDirArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvGetDirArg) Bytes() []byte { return nil }

type KvCacheCheckArg struct {
	Req KVReqHeader
}

type KvCacheCheckArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Req     *KVReqHeaderInternal__
}

func (k KvCacheCheckArgInternal__) Import() KvCacheCheckArg {
	return KvCacheCheckArg{
		Req: (func(x *KVReqHeaderInternal__) (ret KVReqHeader) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Req),
	}
}

func (k KvCacheCheckArg) Export() *KvCacheCheckArgInternal__ {
	return &KvCacheCheckArgInternal__{
		Req: k.Req.Export(),
	}
}

func (k *KvCacheCheckArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvCacheCheckArg) Decode(dec rpc.Decoder) error {
	var tmp KvCacheCheckArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvCacheCheckArg) Bytes() []byte { return nil }

type KvListArg struct {
	Auth KVAuth
	Dir  lib.DirID
	Opts KVListOpts
}

type KvListArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	Dir     *lib.DirIDInternal__
	Opts    *KVListOptsInternal__
}

func (k KvListArgInternal__) Import() KvListArg {
	return KvListArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		Dir: (func(x *lib.DirIDInternal__) (ret lib.DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Dir),
		Opts: (func(x *KVListOptsInternal__) (ret KVListOpts) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Opts),
	}
}

func (k KvListArg) Export() *KvListArgInternal__ {
	return &KvListArgInternal__{
		Auth: k.Auth.Export(),
		Dir:  k.Dir.Export(),
		Opts: k.Opts.Export(),
	}
}

func (k *KvListArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvListArg) Decode(dec rpc.Decoder) error {
	var tmp KvListArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvListArg) Bytes() []byte { return nil }

type KvLockAcquireArg struct {
	Auth    KVAuth
	Lock    KVLock
	Timeout lib.DurationMilli
}

type KvLockAcquireArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	Lock    *KVLockInternal__
	Timeout *lib.DurationMilliInternal__
}

func (k KvLockAcquireArgInternal__) Import() KvLockAcquireArg {
	return KvLockAcquireArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		Lock: (func(x *KVLockInternal__) (ret KVLock) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Lock),
		Timeout: (func(x *lib.DurationMilliInternal__) (ret lib.DurationMilli) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Timeout),
	}
}

func (k KvLockAcquireArg) Export() *KvLockAcquireArgInternal__ {
	return &KvLockAcquireArgInternal__{
		Auth:    k.Auth.Export(),
		Lock:    k.Lock.Export(),
		Timeout: k.Timeout.Export(),
	}
}

func (k *KvLockAcquireArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvLockAcquireArg) Decode(dec rpc.Decoder) error {
	var tmp KvLockAcquireArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvLockAcquireArg) Bytes() []byte { return nil }

type KvLockReleaseArg struct {
	Auth KVAuth
	Lock KVLock
}

type KvLockReleaseArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
	Lock    *KVLockInternal__
}

func (k KvLockReleaseArgInternal__) Import() KvLockReleaseArg {
	return KvLockReleaseArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
		Lock: (func(x *KVLockInternal__) (ret KVLock) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Lock),
	}
}

func (k KvLockReleaseArg) Export() *KvLockReleaseArgInternal__ {
	return &KvLockReleaseArgInternal__{
		Auth: k.Auth.Export(),
		Lock: k.Lock.Export(),
	}
}

func (k *KvLockReleaseArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvLockReleaseArg) Decode(dec rpc.Decoder) error {
	var tmp KvLockReleaseArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvLockReleaseArg) Bytes() []byte { return nil }

type KvUsageArg struct {
	Auth KVAuth
}

type KvUsageArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Auth    *KVAuthInternal__
}

func (k KvUsageArgInternal__) Import() KvUsageArg {
	return KvUsageArg{
		Auth: (func(x *KVAuthInternal__) (ret KVAuth) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Auth),
	}
}

func (k KvUsageArg) Export() *KvUsageArgInternal__ {
	return &KvUsageArgInternal__{
		Auth: k.Auth.Export(),
	}
}

func (k *KvUsageArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KvUsageArg) Decode(dec rpc.Decoder) error {
	var tmp KvUsageArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KvUsageArg) Bytes() []byte { return nil }

type KVStoreInterface interface {
	KvMkdir(context.Context, KvMkdirArg) error
	KvPut(context.Context, KvPutArg) error
	KvPutRoot(context.Context, KvPutRootArg) error
	KvFileUploadInit(context.Context, KvFileUploadInitArg) error
	KvFileUploadChunk(context.Context, KvFileUploadChunkArg) error
	KvPutSmallFileOrSymlink(context.Context, KvPutSmallFileOrSymlinkArg) error
	KvGetRoot(context.Context, KVAuth) (lib.KVRoot, error)
	KvGet(context.Context, KvGetArg) (KVGetRes, error)
	KvGetNode(context.Context, KvGetNodeArg) (KVGetNodeRes, error)
	KvGetEncryptedChunk(context.Context, KvGetEncryptedChunkArg) (GetEncryptedChunkRes, error)
	KvGetDir(context.Context, KvGetDirArg) (lib.KVDirPair, error)
	KvCacheCheck(context.Context, KVReqHeader) error
	KvList(context.Context, KvListArg) (KVListRes, error)
	KvLockAcquire(context.Context, KvLockAcquireArg) error
	KvLockRelease(context.Context, KvLockReleaseArg) error
	KvUsage(context.Context, KVAuth) (lib.KVUsage, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error

	MakeResHeader() lib.Header
}

func KVStoreMakeGenericErrorWrapper(f KVStoreErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type KVStoreErrorUnwrapper func(lib.Status) error
type KVStoreErrorWrapper func(error) lib.Status

type kVStoreErrorUnwrapperAdapter struct {
	h KVStoreErrorUnwrapper
}

func (k kVStoreErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (k kVStoreErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return k.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = kVStoreErrorUnwrapperAdapter{}

type KVStoreClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper KVStoreErrorUnwrapper
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c KVStoreClient) KvMkdir(ctx context.Context, arg KvMkdirArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *KvMkdirArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 0, "KVStore.kvMkdir"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvPut(ctx context.Context, arg KvPutArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *KvPutArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 1, "KVStore.kvPut"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvPutRoot(ctx context.Context, arg KvPutRootArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *KvPutRootArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 2, "KVStore.kvPutRoot"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvFileUploadInit(ctx context.Context, arg KvFileUploadInitArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *KvFileUploadInitArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 3, "KVStore.kvFileUploadInit"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvFileUploadChunk(ctx context.Context, arg KvFileUploadChunkArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *KvFileUploadChunkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 4, "KVStore.kvFileUploadChunk"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvPutSmallFileOrSymlink(ctx context.Context, arg KvPutSmallFileOrSymlinkArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *KvPutSmallFileOrSymlinkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 7, "KVStore.kvPutSmallFileOrSymlink"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvGetRoot(ctx context.Context, auth KVAuth) (res lib.KVRoot, err error) {
	arg := KvGetRootArg{
		Auth: auth,
	}
	warg := &rpc.DataWrap[lib.Header, *KvGetRootArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.KVRootInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 8, "KVStore.kvGetRoot"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvGet(ctx context.Context, arg KvGetArg) (res KVGetRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *KvGetArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, KVGetResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 9, "KVStore.kvGet"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvGetNode(ctx context.Context, arg KvGetNodeArg) (res KVGetNodeRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *KvGetNodeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, KVGetNodeResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 10, "KVStore.kvGetNode"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvGetEncryptedChunk(ctx context.Context, arg KvGetEncryptedChunkArg) (res GetEncryptedChunkRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *KvGetEncryptedChunkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, GetEncryptedChunkResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 11, "KVStore.kvGetEncryptedChunk"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvGetDir(ctx context.Context, arg KvGetDirArg) (res lib.KVDirPair, err error) {
	warg := &rpc.DataWrap[lib.Header, *KvGetDirArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.KVDirPairInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 12, "KVStore.kvGetDir"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvCacheCheck(ctx context.Context, req KVReqHeader) (err error) {
	arg := KvCacheCheckArg{
		Req: req,
	}
	warg := &rpc.DataWrap[lib.Header, *KvCacheCheckArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 13, "KVStore.kvCacheCheck"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvList(ctx context.Context, arg KvListArg) (res KVListRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *KvListArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, KVListResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 14, "KVStore.kvList"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvLockAcquire(ctx context.Context, arg KvLockAcquireArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *KvLockAcquireArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 15, "KVStore.kvLockAcquire"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvLockRelease(ctx context.Context, arg KvLockReleaseArg) (err error) {
	warg := &rpc.DataWrap[lib.Header, *KvLockReleaseArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 16, "KVStore.kvLockRelease"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c KVStoreClient) KvUsage(ctx context.Context, auth KVAuth) (res lib.KVUsage, err error) {
	arg := KvUsageArg{
		Auth: auth,
	}
	warg := &rpc.DataWrap[lib.Header, *KvUsageArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, lib.KVUsageInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVStoreProtocolID, 17, "KVStore.kvUsage"), warg, &tmp, 0*time.Millisecond, kVStoreErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func KVStoreProtocol(i KVStoreInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "KVStore",
		ID:   KVStoreProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvMkdirArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvMkdirArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvMkdirArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KvMkdir(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvMkdir",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvPutArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvPutArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvPutArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KvPut(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvPut",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvPutRootArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvPutRootArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvPutRootArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KvPutRoot(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvPutRoot",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvFileUploadInitArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvFileUploadInitArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvFileUploadInitArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KvFileUploadInit(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvFileUploadInit",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvFileUploadChunkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvFileUploadChunkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvFileUploadChunkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KvFileUploadChunk(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvFileUploadChunk",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvPutSmallFileOrSymlinkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvPutSmallFileOrSymlinkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvPutSmallFileOrSymlinkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KvPutSmallFileOrSymlink(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvPutSmallFileOrSymlink",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvGetRootArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvGetRootArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvGetRootArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.KvGetRoot(ctx, (typedArg.Import()).Auth)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.KVRootInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvGetRoot",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvGetArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvGetArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvGetArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.KvGet(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *KVGetResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvGet",
			},
			10: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvGetNodeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvGetNodeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvGetNodeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.KvGetNode(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *KVGetNodeResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvGetNode",
			},
			11: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvGetEncryptedChunkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvGetEncryptedChunkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvGetEncryptedChunkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.KvGetEncryptedChunk(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *GetEncryptedChunkResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvGetEncryptedChunk",
			},
			12: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvGetDirArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvGetDirArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvGetDirArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.KvGetDir(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.KVDirPairInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvGetDir",
			},
			13: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvCacheCheckArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvCacheCheckArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvCacheCheckArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KvCacheCheck(ctx, (typedArg.Import()).Req)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvCacheCheck",
			},
			14: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvListArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvListArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvListArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.KvList(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *KVListResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvList",
			},
			15: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvLockAcquireArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvLockAcquireArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvLockAcquireArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KvLockAcquire(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvLockAcquire",
			},
			16: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvLockReleaseArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvLockReleaseArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvLockReleaseArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.KvLockRelease(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvLockRelease",
			},
			17: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *KvUsageArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *KvUsageArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *KvUsageArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.KvUsage(ctx, (typedArg.Import()).Auth)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *lib.KVUsageInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "kvUsage",
			},
		},
		WrapError: KVStoreMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(KVNodePathMultipleTypeUniqueID)
	rpc.AddUnique(KVStoreProtocolID)
}
