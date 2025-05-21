// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lcl/kv.snowp

package lcl

import (
	"context"
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type SmallFileData []byte
type SmallFileDataInternal__ []byte

func (s SmallFileData) Export() *SmallFileDataInternal__ {
	tmp := (([]byte)(s))
	return ((*SmallFileDataInternal__)(&tmp))
}
func (s SmallFileDataInternal__) Import() SmallFileData {
	tmp := ([]byte)(s)
	return SmallFileData((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SmallFileData) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SmallFileData) Decode(dec rpc.Decoder) error {
	var tmp SmallFileDataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

var SmallFileDataTypeUniqueID = rpc.TypeUniqueID(0xc4107596b8b79aa5)

func (s *SmallFileData) GetTypeUniqueID() rpc.TypeUniqueID {
	return SmallFileDataTypeUniqueID
}
func (s SmallFileData) Bytes() []byte {
	return (s)[:]
}

type SmallFileBoxPayload struct {
	T     lib.KVNodeType
	F_0__ *SmallFileData `json:"f0,omitempty"`
	F_1__ *lib.KVPath    `json:"f1,omitempty"`
}
type SmallFileBoxPayloadInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        lib.KVNodeType
	Switch__ SmallFileBoxPayloadInternalSwitch__
}
type SmallFileBoxPayloadInternalSwitch__ struct {
	_struct struct{}                 `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *SmallFileDataInternal__ `codec:"0"`
	F_1__   *lib.KVPathInternal__    `codec:"1"`
}

func (s SmallFileBoxPayload) GetT() (ret lib.KVNodeType, err error) {
	switch s.T {
	case lib.KVNodeType_SmallFile:
		if s.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case lib.KVNodeType_Symlink:
		if s.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return s.T, nil
}
func (s SmallFileBoxPayload) Smallfile() SmallFileData {
	if s.F_0__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.T != lib.KVNodeType_SmallFile {
		panic(fmt.Sprintf("unexpected switch value (%v) when Smallfile is called", s.T))
	}
	return *s.F_0__
}
func (s SmallFileBoxPayload) Symlink() lib.KVPath {
	if s.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if s.T != lib.KVNodeType_Symlink {
		panic(fmt.Sprintf("unexpected switch value (%v) when Symlink is called", s.T))
	}
	return *s.F_1__
}
func NewSmallFileBoxPayloadWithSmallfile(v SmallFileData) SmallFileBoxPayload {
	return SmallFileBoxPayload{
		T:     lib.KVNodeType_SmallFile,
		F_0__: &v,
	}
}
func NewSmallFileBoxPayloadWithSymlink(v lib.KVPath) SmallFileBoxPayload {
	return SmallFileBoxPayload{
		T:     lib.KVNodeType_Symlink,
		F_1__: &v,
	}
}
func (s SmallFileBoxPayloadInternal__) Import() SmallFileBoxPayload {
	return SmallFileBoxPayload{
		T: s.T,
		F_0__: (func(x *SmallFileDataInternal__) *SmallFileData {
			if x == nil {
				return nil
			}
			tmp := (func(x *SmallFileDataInternal__) (ret SmallFileData) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_0__),
		F_1__: (func(x *lib.KVPathInternal__) *lib.KVPath {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_1__),
	}
}
func (s SmallFileBoxPayload) Export() *SmallFileBoxPayloadInternal__ {
	return &SmallFileBoxPayloadInternal__{
		T: s.T,
		Switch__: SmallFileBoxPayloadInternalSwitch__{
			F_0__: (func(x *SmallFileData) *SmallFileDataInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_0__),
			F_1__: (func(x *lib.KVPath) *lib.KVPathInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_1__),
		},
	}
}
func (s *SmallFileBoxPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SmallFileBoxPayload) Decode(dec rpc.Decoder) error {
	var tmp SmallFileBoxPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

var SmallFileBoxPayloadTypeUniqueID = rpc.TypeUniqueID(0xaeec688f3145fddf)

func (s *SmallFileBoxPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return SmallFileBoxPayloadTypeUniqueID
}
func (s *SmallFileBoxPayload) Bytes() []byte { return nil }

type KVDirentNamePayload struct {
	ParentDir  lib.DirID
	DirVersion lib.KVVersion
	Name       lib.KVPathComponent
}
type KVDirentNamePayloadInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ParentDir  *lib.DirIDInternal__
	DirVersion *lib.KVVersionInternal__
	Name       *lib.KVPathComponentInternal__
}

func (k KVDirentNamePayloadInternal__) Import() KVDirentNamePayload {
	return KVDirentNamePayload{
		ParentDir: (func(x *lib.DirIDInternal__) (ret lib.DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.ParentDir),
		DirVersion: (func(x *lib.KVVersionInternal__) (ret lib.KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.DirVersion),
		Name: (func(x *lib.KVPathComponentInternal__) (ret lib.KVPathComponent) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Name),
	}
}
func (k KVDirentNamePayload) Export() *KVDirentNamePayloadInternal__ {
	return &KVDirentNamePayloadInternal__{
		ParentDir:  k.ParentDir.Export(),
		DirVersion: k.DirVersion.Export(),
		Name:       k.Name.Export(),
	}
}
func (k *KVDirentNamePayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVDirentNamePayload) Decode(dec rpc.Decoder) error {
	var tmp KVDirentNamePayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KVDirentNamePayloadTypeUniqueID = rpc.TypeUniqueID(0xb9c1587fa732c2c9)

func (k *KVDirentNamePayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return KVDirentNamePayloadTypeUniqueID
}
func (k *KVDirentNamePayload) Bytes() []byte { return nil }

type FileKeyBoxPayload struct {
	Id   lib.FileID
	Vers lib.KVVersion
	Seed lib.FileKeySeed
}
type FileKeyBoxPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.FileIDInternal__
	Vers    *lib.KVVersionInternal__
	Seed    *lib.FileKeySeedInternal__
}

func (f FileKeyBoxPayloadInternal__) Import() FileKeyBoxPayload {
	return FileKeyBoxPayload{
		Id: (func(x *lib.FileIDInternal__) (ret lib.FileID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Id),
		Vers: (func(x *lib.KVVersionInternal__) (ret lib.KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Vers),
		Seed: (func(x *lib.FileKeySeedInternal__) (ret lib.FileKeySeed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Seed),
	}
}
func (f FileKeyBoxPayload) Export() *FileKeyBoxPayloadInternal__ {
	return &FileKeyBoxPayloadInternal__{
		Id:   f.Id.Export(),
		Vers: f.Vers.Export(),
		Seed: f.Seed.Export(),
	}
}
func (f *FileKeyBoxPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FileKeyBoxPayload) Decode(dec rpc.Decoder) error {
	var tmp FileKeyBoxPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

var FileKeyBoxPayloadTypeUniqueID = rpc.TypeUniqueID(0x9211ae1e17213884)

func (f *FileKeyBoxPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return FileKeyBoxPayloadTypeUniqueID
}
func (f *FileKeyBoxPayload) Bytes() []byte { return nil }

type KVConfig struct {
	ActingAs       *lib.FQTeamParsed
	Roles          lib.RolePairOpt
	MkdirP         bool
	OverwriteOk    bool
	NoFollow       bool
	NoFollowAny    bool
	AssertVersion  *lib.KVVersion
	SkipCacheCheck bool
	MtimeLower     *lib.TimeMicro
	Recursive      bool
}
type KVConfigInternal__ struct {
	_struct        struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	ActingAs       *lib.FQTeamParsedInternal__
	Roles          *lib.RolePairOptInternal__
	MkdirP         *bool
	OverwriteOk    *bool
	NoFollow       *bool
	NoFollowAny    *bool
	AssertVersion  *lib.KVVersionInternal__
	SkipCacheCheck *bool
	MtimeLower     *lib.TimeMicroInternal__
	Recursive      *bool
}

func (k KVConfigInternal__) Import() KVConfig {
	return KVConfig{
		ActingAs: (func(x *lib.FQTeamParsedInternal__) *lib.FQTeamParsed {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.FQTeamParsedInternal__) (ret lib.FQTeamParsed) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.ActingAs),
		Roles: (func(x *lib.RolePairOptInternal__) (ret lib.RolePairOpt) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Roles),
		MkdirP: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(k.MkdirP),
		OverwriteOk: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(k.OverwriteOk),
		NoFollow: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(k.NoFollow),
		NoFollowAny: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(k.NoFollowAny),
		AssertVersion: (func(x *lib.KVVersionInternal__) *lib.KVVersion {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.KVVersionInternal__) (ret lib.KVVersion) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.AssertVersion),
		SkipCacheCheck: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(k.SkipCacheCheck),
		MtimeLower: (func(x *lib.TimeMicroInternal__) *lib.TimeMicro {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.TimeMicroInternal__) (ret lib.TimeMicro) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.MtimeLower),
		Recursive: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(k.Recursive),
	}
}
func (k KVConfig) Export() *KVConfigInternal__ {
	return &KVConfigInternal__{
		ActingAs: (func(x *lib.FQTeamParsed) *lib.FQTeamParsedInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(k.ActingAs),
		Roles:       k.Roles.Export(),
		MkdirP:      &k.MkdirP,
		OverwriteOk: &k.OverwriteOk,
		NoFollow:    &k.NoFollow,
		NoFollowAny: &k.NoFollowAny,
		AssertVersion: (func(x *lib.KVVersion) *lib.KVVersionInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(k.AssertVersion),
		SkipCacheCheck: &k.SkipCacheCheck,
		MtimeLower: (func(x *lib.TimeMicro) *lib.TimeMicroInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(k.MtimeLower),
		Recursive: &k.Recursive,
	}
}
func (k *KVConfig) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVConfig) Decode(dec rpc.Decoder) error {
	var tmp KVConfigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVConfig) Bytes() []byte { return nil }

type GetFileChunkRes struct {
	Chunk lib.ChunkPlaintext
	Final bool
}
type GetFileChunkResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Chunk   *lib.ChunkPlaintextInternal__
	Final   *bool
}

func (g GetFileChunkResInternal__) Import() GetFileChunkRes {
	return GetFileChunkRes{
		Chunk: (func(x *lib.ChunkPlaintextInternal__) (ret lib.ChunkPlaintext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Chunk),
		Final: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(g.Final),
	}
}
func (g GetFileChunkRes) Export() *GetFileChunkResInternal__ {
	return &GetFileChunkResInternal__{
		Chunk: g.Chunk.Export(),
		Final: &g.Final,
	}
}
func (g *GetFileChunkRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetFileChunkRes) Decode(dec rpc.Decoder) error {
	var tmp GetFileChunkResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetFileChunkRes) Bytes() []byte { return nil }

type GetFileRes struct {
	Chunk GetFileChunkRes
	De    lib.KVDirent
	Id    *lib.FileID
}
type GetFileResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Chunk   *GetFileChunkResInternal__
	De      *lib.KVDirentInternal__
	Id      *lib.FileIDInternal__
}

func (g GetFileResInternal__) Import() GetFileRes {
	return GetFileRes{
		Chunk: (func(x *GetFileChunkResInternal__) (ret GetFileChunkRes) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Chunk),
		De: (func(x *lib.KVDirentInternal__) (ret lib.KVDirent) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.De),
		Id: (func(x *lib.FileIDInternal__) *lib.FileID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.FileIDInternal__) (ret lib.FileID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(g.Id),
	}
}
func (g GetFileRes) Export() *GetFileResInternal__ {
	return &GetFileResInternal__{
		Chunk: g.Chunk.Export(),
		De:    g.De.Export(),
		Id: (func(x *lib.FileID) *lib.FileIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(g.Id),
	}
}
func (g *GetFileRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GetFileRes) Decode(dec rpc.Decoder) error {
	var tmp GetFileResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GetFileRes) Bytes() []byte { return nil }

type KVStatFile struct {
	Size lib.Size
}
type KVStatFileInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Size    *lib.SizeInternal__
}

func (k KVStatFileInternal__) Import() KVStatFile {
	return KVStatFile{
		Size: (func(x *lib.SizeInternal__) (ret lib.Size) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Size),
	}
}
func (k KVStatFile) Export() *KVStatFileInternal__ {
	return &KVStatFileInternal__{
		Size: k.Size.Export(),
	}
}
func (k *KVStatFile) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVStatFile) Decode(dec rpc.Decoder) error {
	var tmp KVStatFileInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVStatFile) Bytes() []byte { return nil }

type KVStatSymlink struct {
	Target lib.KVPath
}
type KVStatSymlinkInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Target  *lib.KVPathInternal__
}

func (k KVStatSymlinkInternal__) Import() KVStatSymlink {
	return KVStatSymlink{
		Target: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Target),
	}
}
func (k KVStatSymlink) Export() *KVStatSymlinkInternal__ {
	return &KVStatSymlinkInternal__{
		Target: k.Target.Export(),
	}
}
func (k *KVStatSymlink) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVStatSymlink) Decode(dec rpc.Decoder) error {
	var tmp KVStatSymlinkInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVStatSymlink) Bytes() []byte { return nil }

type KVStatDir struct {
	Vers lib.KVVersion
}
type KVStatDirInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Vers    *lib.KVVersionInternal__
}

func (k KVStatDirInternal__) Import() KVStatDir {
	return KVStatDir{
		Vers: (func(x *lib.KVVersionInternal__) (ret lib.KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Vers),
	}
}
func (k KVStatDir) Export() *KVStatDirInternal__ {
	return &KVStatDirInternal__{
		Vers: k.Vers.Export(),
	}
}
func (k *KVStatDir) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVStatDir) Decode(dec rpc.Decoder) error {
	var tmp KVStatDirInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVStatDir) Bytes() []byte { return nil }

type KVStatVar struct {
	T     lib.KVNodeType
	F_1__ *KVStatDir     `json:"f1,omitempty"`
	F_2__ *KVStatFile    `json:"f2,omitempty"`
	F_4__ *KVStatSymlink `json:"f4,omitempty"`
}
type KVStatVarInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        lib.KVNodeType
	Switch__ KVStatVarInternalSwitch__
}
type KVStatVarInternalSwitch__ struct {
	_struct struct{}                 `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *KVStatDirInternal__     `codec:"1"`
	F_2__   *KVStatFileInternal__    `codec:"2"`
	F_4__   *KVStatSymlinkInternal__ `codec:"4"`
}

func (k KVStatVar) GetT() (ret lib.KVNodeType, err error) {
	switch k.T {
	case lib.KVNodeType_Dir:
		if k.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case lib.KVNodeType_SmallFile, lib.KVNodeType_File:
		if k.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case lib.KVNodeType_Symlink:
		if k.F_4__ == nil {
			return ret, errors.New("unexpected nil case for F_4__")
		}
	}
	return k.T, nil
}
func (k KVStatVar) Dir() KVStatDir {
	if k.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if k.T != lib.KVNodeType_Dir {
		panic(fmt.Sprintf("unexpected switch value (%v) when Dir is called", k.T))
	}
	return *k.F_1__
}
func (k KVStatVar) Smallfile() KVStatFile {
	if k.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if k.T != lib.KVNodeType_SmallFile {
		panic(fmt.Sprintf("unexpected switch value (%v) when Smallfile is called", k.T))
	}
	return *k.F_2__
}
func (k KVStatVar) File() KVStatFile {
	if k.F_2__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if k.T != lib.KVNodeType_File {
		panic(fmt.Sprintf("unexpected switch value (%v) when File is called", k.T))
	}
	return *k.F_2__
}
func (k KVStatVar) Symlink() KVStatSymlink {
	if k.F_4__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if k.T != lib.KVNodeType_Symlink {
		panic(fmt.Sprintf("unexpected switch value (%v) when Symlink is called", k.T))
	}
	return *k.F_4__
}
func NewKVStatVarWithDir(v KVStatDir) KVStatVar {
	return KVStatVar{
		T:     lib.KVNodeType_Dir,
		F_1__: &v,
	}
}
func NewKVStatVarWithSmallfile(v KVStatFile) KVStatVar {
	return KVStatVar{
		T:     lib.KVNodeType_SmallFile,
		F_2__: &v,
	}
}
func NewKVStatVarWithFile(v KVStatFile) KVStatVar {
	return KVStatVar{
		T:     lib.KVNodeType_File,
		F_2__: &v,
	}
}
func NewKVStatVarWithSymlink(v KVStatSymlink) KVStatVar {
	return KVStatVar{
		T:     lib.KVNodeType_Symlink,
		F_4__: &v,
	}
}
func (k KVStatVarInternal__) Import() KVStatVar {
	return KVStatVar{
		T: k.T,
		F_1__: (func(x *KVStatDirInternal__) *KVStatDir {
			if x == nil {
				return nil
			}
			tmp := (func(x *KVStatDirInternal__) (ret KVStatDir) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_1__),
		F_2__: (func(x *KVStatFileInternal__) *KVStatFile {
			if x == nil {
				return nil
			}
			tmp := (func(x *KVStatFileInternal__) (ret KVStatFile) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_2__),
		F_4__: (func(x *KVStatSymlinkInternal__) *KVStatSymlink {
			if x == nil {
				return nil
			}
			tmp := (func(x *KVStatSymlinkInternal__) (ret KVStatSymlink) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.Switch__.F_4__),
	}
}
func (k KVStatVar) Export() *KVStatVarInternal__ {
	return &KVStatVarInternal__{
		T: k.T,
		Switch__: KVStatVarInternalSwitch__{
			F_1__: (func(x *KVStatDir) *KVStatDirInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_1__),
			F_2__: (func(x *KVStatFile) *KVStatFileInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_2__),
			F_4__: (func(x *KVStatSymlink) *KVStatSymlinkInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(k.F_4__),
		},
	}
}
func (k *KVStatVar) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVStatVar) Decode(dec rpc.Decoder) error {
	var tmp KVStatVarInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVStatVar) Bytes() []byte { return nil }

type KVStat struct {
	De    *lib.KVDirent
	V     KVStatVar
	Read  lib.RoleAndGen
	Write lib.Role
}
type KVStatInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	De      *lib.KVDirentInternal__
	V       *KVStatVarInternal__
	Read    *lib.RoleAndGenInternal__
	Write   *lib.RoleInternal__
}

func (k KVStatInternal__) Import() KVStat {
	return KVStat{
		De: (func(x *lib.KVDirentInternal__) *lib.KVDirent {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.KVDirentInternal__) (ret lib.KVDirent) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(k.De),
		V: (func(x *KVStatVarInternal__) (ret KVStatVar) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.V),
		Read: (func(x *lib.RoleAndGenInternal__) (ret lib.RoleAndGen) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Read),
		Write: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Write),
	}
}
func (k KVStat) Export() *KVStatInternal__ {
	return &KVStatInternal__{
		De: (func(x *lib.KVDirent) *lib.KVDirentInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(k.De),
		V:     k.V.Export(),
		Read:  k.Read.Export(),
		Write: k.Write.Export(),
	}
}
func (k *KVStat) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVStat) Decode(dec rpc.Decoder) error {
	var tmp KVStatInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVStat) Bytes() []byte { return nil }

type KVListNext struct {
	Id  lib.DirID
	Nxt lib.KVListPagination
}
type KVListNextInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.DirIDInternal__
	Nxt     *lib.KVListPaginationInternal__
}

func (k KVListNextInternal__) Import() KVListNext {
	return KVListNext{
		Id: (func(x *lib.DirIDInternal__) (ret lib.DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Id),
		Nxt: (func(x *lib.KVListPaginationInternal__) (ret lib.KVListPagination) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Nxt),
	}
}
func (k KVListNext) Export() *KVListNextInternal__ {
	return &KVListNextInternal__{
		Id:  k.Id.Export(),
		Nxt: k.Nxt.Export(),
	}
}
func (k *KVListNext) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVListNext) Decode(dec rpc.Decoder) error {
	var tmp KVListNextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVListNext) Bytes() []byte { return nil }

type CliKVListRes struct {
	Ents   []KVListEntry
	Nxt    *KVListNext
	Parent lib.KVPath
}
type CliKVListResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ents    *[](*KVListEntryInternal__)
	Nxt     *KVListNextInternal__
	Parent  *lib.KVPathInternal__
}

func (c CliKVListResInternal__) Import() CliKVListRes {
	return CliKVListRes{
		Ents: (func(x *[](*KVListEntryInternal__)) (ret []KVListEntry) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]KVListEntry, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *KVListEntryInternal__) (ret KVListEntry) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(c.Ents),
		Nxt: (func(x *KVListNextInternal__) *KVListNext {
			if x == nil {
				return nil
			}
			tmp := (func(x *KVListNextInternal__) (ret KVListNext) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Nxt),
		Parent: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Parent),
	}
}
func (c CliKVListRes) Export() *CliKVListResInternal__ {
	return &CliKVListResInternal__{
		Ents: (func(x []KVListEntry) *[](*KVListEntryInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*KVListEntryInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(c.Ents),
		Nxt: (func(x *KVListNext) *KVListNextInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.Nxt),
		Parent: c.Parent.Export(),
	}
}
func (c *CliKVListRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CliKVListRes) Decode(dec rpc.Decoder) error {
	var tmp CliKVListResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CliKVListRes) Bytes() []byte { return nil }

type KVListEntry struct {
	De    lib.DirentID
	Name  lib.KVPathComponent
	Write lib.Role
	Value lib.KVNodeID
	Mtime lib.TimeMicro
	Ctime lib.TimeMicro
}
type KVListEntryInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	De      *lib.DirentIDInternal__
	Name    *lib.KVPathComponentInternal__
	Write   *lib.RoleInternal__
	Value   *lib.KVNodeIDInternal__
	Mtime   *lib.TimeMicroInternal__
	Ctime   *lib.TimeMicroInternal__
}

func (k KVListEntryInternal__) Import() KVListEntry {
	return KVListEntry{
		De: (func(x *lib.DirentIDInternal__) (ret lib.DirentID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.De),
		Name: (func(x *lib.KVPathComponentInternal__) (ret lib.KVPathComponent) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Name),
		Write: (func(x *lib.RoleInternal__) (ret lib.Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Write),
		Value: (func(x *lib.KVNodeIDInternal__) (ret lib.KVNodeID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Value),
		Mtime: (func(x *lib.TimeMicroInternal__) (ret lib.TimeMicro) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Mtime),
		Ctime: (func(x *lib.TimeMicroInternal__) (ret lib.TimeMicro) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Ctime),
	}
}
func (k KVListEntry) Export() *KVListEntryInternal__ {
	return &KVListEntryInternal__{
		De:    k.De.Export(),
		Name:  k.Name.Export(),
		Write: k.Write.Export(),
		Value: k.Value.Export(),
		Mtime: k.Mtime.Export(),
		Ctime: k.Ctime.Export(),
	}
}
func (k *KVListEntry) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KVListEntry) Decode(dec rpc.Decoder) error {
	var tmp KVListEntryInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KVListEntry) Bytes() []byte { return nil }

type ChunkNoncePayload struct {
	Id     lib.FileID
	Offset lib.Offset
	Final  bool
}
type ChunkNoncePayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.FileIDInternal__
	Offset  *lib.OffsetInternal__
	Final   *bool
}

func (c ChunkNoncePayloadInternal__) Import() ChunkNoncePayload {
	return ChunkNoncePayload{
		Id: (func(x *lib.FileIDInternal__) (ret lib.FileID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Id),
		Offset: (func(x *lib.OffsetInternal__) (ret lib.Offset) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Offset),
		Final: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Final),
	}
}
func (c ChunkNoncePayload) Export() *ChunkNoncePayloadInternal__ {
	return &ChunkNoncePayloadInternal__{
		Id:     c.Id.Export(),
		Offset: c.Offset.Export(),
		Final:  &c.Final,
	}
}
func (c *ChunkNoncePayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ChunkNoncePayload) Decode(dec rpc.Decoder) error {
	var tmp ChunkNoncePayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var ChunkNoncePayloadTypeUniqueID = rpc.TypeUniqueID(0xadba174b7e8dcc08)

func (c *ChunkNoncePayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return ChunkNoncePayloadTypeUniqueID
}
func (c *ChunkNoncePayload) Bytes() []byte { return nil }

var KVProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xddf3c319)

type ClientKVMkdirArg struct {
	Cfg  KVConfig
	Path lib.KVPath
}
type ClientKVMkdirArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Path    *lib.KVPathInternal__
}

func (c ClientKVMkdirArgInternal__) Import() ClientKVMkdirArg {
	return ClientKVMkdirArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Path: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Path),
	}
}
func (c ClientKVMkdirArg) Export() *ClientKVMkdirArgInternal__ {
	return &ClientKVMkdirArgInternal__{
		Cfg:  c.Cfg.Export(),
		Path: c.Path.Export(),
	}
}
func (c *ClientKVMkdirArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVMkdirArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVMkdirArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVMkdirArg) Bytes() []byte { return nil }

type ClientKVPutFirstArg struct {
	Cfg   KVConfig
	Path  lib.KVPath
	Chunk lib.ChunkPlaintext
	Final bool
}
type ClientKVPutFirstArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Path    *lib.KVPathInternal__
	Chunk   *lib.ChunkPlaintextInternal__
	Final   *bool
}

func (c ClientKVPutFirstArgInternal__) Import() ClientKVPutFirstArg {
	return ClientKVPutFirstArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Path: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Path),
		Chunk: (func(x *lib.ChunkPlaintextInternal__) (ret lib.ChunkPlaintext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Chunk),
		Final: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Final),
	}
}
func (c ClientKVPutFirstArg) Export() *ClientKVPutFirstArgInternal__ {
	return &ClientKVPutFirstArgInternal__{
		Cfg:   c.Cfg.Export(),
		Path:  c.Path.Export(),
		Chunk: c.Chunk.Export(),
		Final: &c.Final,
	}
}
func (c *ClientKVPutFirstArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVPutFirstArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVPutFirstArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVPutFirstArg) Bytes() []byte { return nil }

type ClientKVPutChunkArg struct {
	Cfg    KVConfig
	Id     lib.FileID
	Chunk  lib.ChunkPlaintext
	Offset lib.Offset
	Final  bool
}
type ClientKVPutChunkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Id      *lib.FileIDInternal__
	Chunk   *lib.ChunkPlaintextInternal__
	Offset  *lib.OffsetInternal__
	Final   *bool
}

func (c ClientKVPutChunkArgInternal__) Import() ClientKVPutChunkArg {
	return ClientKVPutChunkArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Id: (func(x *lib.FileIDInternal__) (ret lib.FileID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Id),
		Chunk: (func(x *lib.ChunkPlaintextInternal__) (ret lib.ChunkPlaintext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Chunk),
		Offset: (func(x *lib.OffsetInternal__) (ret lib.Offset) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Offset),
		Final: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Final),
	}
}
func (c ClientKVPutChunkArg) Export() *ClientKVPutChunkArgInternal__ {
	return &ClientKVPutChunkArgInternal__{
		Cfg:    c.Cfg.Export(),
		Id:     c.Id.Export(),
		Chunk:  c.Chunk.Export(),
		Offset: c.Offset.Export(),
		Final:  &c.Final,
	}
}
func (c *ClientKVPutChunkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVPutChunkArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVPutChunkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVPutChunkArg) Bytes() []byte { return nil }

type ClientKVGetFileArg struct {
	Cfg  KVConfig
	Path lib.KVPath
}
type ClientKVGetFileArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Path    *lib.KVPathInternal__
}

func (c ClientKVGetFileArgInternal__) Import() ClientKVGetFileArg {
	return ClientKVGetFileArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Path: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Path),
	}
}
func (c ClientKVGetFileArg) Export() *ClientKVGetFileArgInternal__ {
	return &ClientKVGetFileArgInternal__{
		Cfg:  c.Cfg.Export(),
		Path: c.Path.Export(),
	}
}
func (c *ClientKVGetFileArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVGetFileArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVGetFileArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVGetFileArg) Bytes() []byte { return nil }

type ClientKVGetFileChunkArg struct {
	Cfg    KVConfig
	Id     lib.FileID
	Offset lib.Offset
}
type ClientKVGetFileChunkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Id      *lib.FileIDInternal__
	Offset  *lib.OffsetInternal__
}

func (c ClientKVGetFileChunkArgInternal__) Import() ClientKVGetFileChunkArg {
	return ClientKVGetFileChunkArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Id: (func(x *lib.FileIDInternal__) (ret lib.FileID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Id),
		Offset: (func(x *lib.OffsetInternal__) (ret lib.Offset) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Offset),
	}
}
func (c ClientKVGetFileChunkArg) Export() *ClientKVGetFileChunkArgInternal__ {
	return &ClientKVGetFileChunkArgInternal__{
		Cfg:    c.Cfg.Export(),
		Id:     c.Id.Export(),
		Offset: c.Offset.Export(),
	}
}
func (c *ClientKVGetFileChunkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVGetFileChunkArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVGetFileChunkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVGetFileChunkArg) Bytes() []byte { return nil }

type ClientKVSymlinkArg struct {
	Cfg    KVConfig
	Path   lib.KVPath
	Target lib.KVPath
}
type ClientKVSymlinkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Path    *lib.KVPathInternal__
	Target  *lib.KVPathInternal__
}

func (c ClientKVSymlinkArgInternal__) Import() ClientKVSymlinkArg {
	return ClientKVSymlinkArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Path: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Path),
		Target: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Target),
	}
}
func (c ClientKVSymlinkArg) Export() *ClientKVSymlinkArgInternal__ {
	return &ClientKVSymlinkArgInternal__{
		Cfg:    c.Cfg.Export(),
		Path:   c.Path.Export(),
		Target: c.Target.Export(),
	}
}
func (c *ClientKVSymlinkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVSymlinkArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVSymlinkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVSymlinkArg) Bytes() []byte { return nil }

type ClientKVReadlinkArg struct {
	Cfg  KVConfig
	Path lib.KVPath
}
type ClientKVReadlinkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Path    *lib.KVPathInternal__
}

func (c ClientKVReadlinkArgInternal__) Import() ClientKVReadlinkArg {
	return ClientKVReadlinkArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Path: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Path),
	}
}
func (c ClientKVReadlinkArg) Export() *ClientKVReadlinkArgInternal__ {
	return &ClientKVReadlinkArgInternal__{
		Cfg:  c.Cfg.Export(),
		Path: c.Path.Export(),
	}
}
func (c *ClientKVReadlinkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVReadlinkArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVReadlinkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVReadlinkArg) Bytes() []byte { return nil }

type ClientKVMvArg struct {
	Cfg KVConfig
	Src lib.KVPath
	Dst lib.KVPath
}
type ClientKVMvArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Src     *lib.KVPathInternal__
	Dst     *lib.KVPathInternal__
}

func (c ClientKVMvArgInternal__) Import() ClientKVMvArg {
	return ClientKVMvArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Src: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Src),
		Dst: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Dst),
	}
}
func (c ClientKVMvArg) Export() *ClientKVMvArgInternal__ {
	return &ClientKVMvArgInternal__{
		Cfg: c.Cfg.Export(),
		Src: c.Src.Export(),
		Dst: c.Dst.Export(),
	}
}
func (c *ClientKVMvArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVMvArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVMvArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVMvArg) Bytes() []byte { return nil }

type ClientKVStatArg struct {
	Cfg  KVConfig
	Path lib.KVPath
}
type ClientKVStatArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Path    *lib.KVPathInternal__
}

func (c ClientKVStatArgInternal__) Import() ClientKVStatArg {
	return ClientKVStatArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Path: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Path),
	}
}
func (c ClientKVStatArg) Export() *ClientKVStatArgInternal__ {
	return &ClientKVStatArgInternal__{
		Cfg:  c.Cfg.Export(),
		Path: c.Path.Export(),
	}
}
func (c *ClientKVStatArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVStatArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVStatArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVStatArg) Bytes() []byte { return nil }

type ClientKVUnlinkArg struct {
	Cfg  KVConfig
	Path lib.KVPath
}
type ClientKVUnlinkArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Path    *lib.KVPathInternal__
}

func (c ClientKVUnlinkArgInternal__) Import() ClientKVUnlinkArg {
	return ClientKVUnlinkArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Path: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Path),
	}
}
func (c ClientKVUnlinkArg) Export() *ClientKVUnlinkArgInternal__ {
	return &ClientKVUnlinkArgInternal__{
		Cfg:  c.Cfg.Export(),
		Path: c.Path.Export(),
	}
}
func (c *ClientKVUnlinkArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVUnlinkArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVUnlinkArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVUnlinkArg) Bytes() []byte { return nil }

type ClientKVListArg struct {
	Cfg   KVConfig
	Path  lib.KVPath
	Nxt   lib.KVListPagination
	DirID *lib.DirID
	Num   uint64
}
type ClientKVListArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Path    *lib.KVPathInternal__
	Nxt     *lib.KVListPaginationInternal__
	DirID   *lib.DirIDInternal__
	Num     *uint64
}

func (c ClientKVListArgInternal__) Import() ClientKVListArg {
	return ClientKVListArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Path: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Path),
		Nxt: (func(x *lib.KVListPaginationInternal__) (ret lib.KVListPagination) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Nxt),
		DirID: (func(x *lib.DirIDInternal__) *lib.DirID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.DirIDInternal__) (ret lib.DirID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.DirID),
		Num: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(c.Num),
	}
}
func (c ClientKVListArg) Export() *ClientKVListArgInternal__ {
	return &ClientKVListArgInternal__{
		Cfg:  c.Cfg.Export(),
		Path: c.Path.Export(),
		Nxt:  c.Nxt.Export(),
		DirID: (func(x *lib.DirID) *lib.DirIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(c.DirID),
		Num: &c.Num,
	}
}
func (c *ClientKVListArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVListArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVListArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVListArg) Bytes() []byte { return nil }

type ClientKVRmArg struct {
	Cfg  KVConfig
	Path lib.KVPath
}
type ClientKVRmArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Path    *lib.KVPathInternal__
}

func (c ClientKVRmArgInternal__) Import() ClientKVRmArg {
	return ClientKVRmArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
		Path: (func(x *lib.KVPathInternal__) (ret lib.KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Path),
	}
}
func (c ClientKVRmArg) Export() *ClientKVRmArgInternal__ {
	return &ClientKVRmArgInternal__{
		Cfg:  c.Cfg.Export(),
		Path: c.Path.Export(),
	}
}
func (c *ClientKVRmArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVRmArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVRmArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVRmArg) Bytes() []byte { return nil }

type ClientKVUsageArg struct {
	Cfg KVConfig
}
type ClientKVUsageArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
}

func (c ClientKVUsageArgInternal__) Import() ClientKVUsageArg {
	return ClientKVUsageArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Cfg),
	}
}
func (c ClientKVUsageArg) Export() *ClientKVUsageArgInternal__ {
	return &ClientKVUsageArgInternal__{
		Cfg: c.Cfg.Export(),
	}
}
func (c *ClientKVUsageArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *ClientKVUsageArg) Decode(dec rpc.Decoder) error {
	var tmp ClientKVUsageArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *ClientKVUsageArg) Bytes() []byte { return nil }

type KVInterface interface {
	ClientKVMkdir(context.Context, ClientKVMkdirArg) (lib.DirID, error)
	ClientKVPutFirst(context.Context, ClientKVPutFirstArg) (lib.KVNodeID, error)
	ClientKVPutChunk(context.Context, ClientKVPutChunkArg) error
	ClientKVGetFile(context.Context, ClientKVGetFileArg) (GetFileRes, error)
	ClientKVGetFileChunk(context.Context, ClientKVGetFileChunkArg) (GetFileChunkRes, error)
	ClientKVSymlink(context.Context, ClientKVSymlinkArg) (lib.KVNodeID, error)
	ClientKVReadlink(context.Context, ClientKVReadlinkArg) (lib.KVPath, error)
	ClientKVMv(context.Context, ClientKVMvArg) error
	ClientKVStat(context.Context, ClientKVStatArg) (KVStat, error)
	ClientKVUnlink(context.Context, ClientKVUnlinkArg) error
	ClientKVList(context.Context, ClientKVListArg) (CliKVListRes, error)
	ClientKVRm(context.Context, ClientKVRmArg) error
	ClientKVUsage(context.Context, KVConfig) (lib.KVUsage, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error
	MakeResHeader() Header
}

func KVMakeGenericErrorWrapper(f KVErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type KVErrorUnwrapper func(lib.Status) error
type KVErrorWrapper func(error) lib.Status

type kVErrorUnwrapperAdapter struct {
	h KVErrorUnwrapper
}

func (k kVErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (k kVErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return k.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = kVErrorUnwrapperAdapter{}

type KVClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper KVErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c KVClient) ClientKVMkdir(ctx context.Context, arg ClientKVMkdirArg) (res lib.DirID, err error) {
	warg := &rpc.DataWrap[Header, *ClientKVMkdirArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.DirIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 0, "KV.clientKVMkdir"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVPutFirst(ctx context.Context, arg ClientKVPutFirstArg) (res lib.KVNodeID, err error) {
	warg := &rpc.DataWrap[Header, *ClientKVPutFirstArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.KVNodeIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 1, "KV.clientKVPutFirst"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVPutChunk(ctx context.Context, arg ClientKVPutChunkArg) (err error) {
	warg := &rpc.DataWrap[Header, *ClientKVPutChunkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 2, "KV.clientKVPutChunk"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVGetFile(ctx context.Context, arg ClientKVGetFileArg) (res GetFileRes, err error) {
	warg := &rpc.DataWrap[Header, *ClientKVGetFileArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, GetFileResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 3, "KV.clientKVGetFile"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVGetFileChunk(ctx context.Context, arg ClientKVGetFileChunkArg) (res GetFileChunkRes, err error) {
	warg := &rpc.DataWrap[Header, *ClientKVGetFileChunkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, GetFileChunkResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 4, "KV.clientKVGetFileChunk"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVSymlink(ctx context.Context, arg ClientKVSymlinkArg) (res lib.KVNodeID, err error) {
	warg := &rpc.DataWrap[Header, *ClientKVSymlinkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.KVNodeIDInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 5, "KV.clientKVSymlink"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVReadlink(ctx context.Context, arg ClientKVReadlinkArg) (res lib.KVPath, err error) {
	warg := &rpc.DataWrap[Header, *ClientKVReadlinkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.KVPathInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 6, "KV.clientKVReadlink"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVMv(ctx context.Context, arg ClientKVMvArg) (err error) {
	warg := &rpc.DataWrap[Header, *ClientKVMvArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 7, "KV.clientKVMv"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVStat(ctx context.Context, arg ClientKVStatArg) (res KVStat, err error) {
	warg := &rpc.DataWrap[Header, *ClientKVStatArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, KVStatInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 8, "KV.clientKVStat"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVUnlink(ctx context.Context, arg ClientKVUnlinkArg) (err error) {
	warg := &rpc.DataWrap[Header, *ClientKVUnlinkArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 9, "KV.clientKVUnlink"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVList(ctx context.Context, arg ClientKVListArg) (res CliKVListRes, err error) {
	warg := &rpc.DataWrap[Header, *ClientKVListArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, CliKVListResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 10, "KV.clientKVList"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVRm(ctx context.Context, arg ClientKVRmArg) (err error) {
	warg := &rpc.DataWrap[Header, *ClientKVRmArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 11, "KV.clientKVRm"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func (c KVClient) ClientKVUsage(ctx context.Context, cfg KVConfig) (res lib.KVUsage, err error) {
	arg := ClientKVUsageArg{
		Cfg: cfg,
	}
	warg := &rpc.DataWrap[Header, *ClientKVUsageArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.KVUsageInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(KVProtocolID, 12, "KV.clientKVUsage"), warg, &tmp, 0*time.Millisecond, kVErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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
func KVProtocol(i KVInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "KV",
		ID:   KVProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVMkdirArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVMkdirArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVMkdirArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientKVMkdir(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.DirIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVMkdir",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVPutFirstArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVPutFirstArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVPutFirstArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientKVPutFirst(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.KVNodeIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVPutFirst",
			},
			2: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVPutChunkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVPutChunkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVPutChunkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ClientKVPutChunk(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVPutChunk",
			},
			3: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVGetFileArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVGetFileArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVGetFileArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientKVGetFile(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *GetFileResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVGetFile",
			},
			4: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVGetFileChunkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVGetFileChunkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVGetFileChunkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientKVGetFileChunk(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *GetFileChunkResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVGetFileChunk",
			},
			5: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVSymlinkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVSymlinkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVSymlinkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientKVSymlink(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.KVNodeIDInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVSymlink",
			},
			6: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVReadlinkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVReadlinkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVReadlinkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientKVReadlink(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.KVPathInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVReadlink",
			},
			7: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVMvArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVMvArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVMvArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ClientKVMv(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVMv",
			},
			8: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVStatArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVStatArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVStatArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientKVStat(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *KVStatInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVStat",
			},
			9: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVUnlinkArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVUnlinkArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVUnlinkArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ClientKVUnlink(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVUnlink",
			},
			10: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVListArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVListArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVListArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientKVList(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *CliKVListResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVList",
			},
			11: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVRmArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVRmArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVRmArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.ClientKVRm(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVRm",
			},
			12: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *ClientKVUsageArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *ClientKVUsageArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *ClientKVUsageArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.ClientKVUsage(ctx, (typedArg.Import()).Cfg)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.KVUsageInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "clientKVUsage",
			},
		},
		WrapError: KVMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(SmallFileDataTypeUniqueID)
	rpc.AddUnique(SmallFileBoxPayloadTypeUniqueID)
	rpc.AddUnique(KVDirentNamePayloadTypeUniqueID)
	rpc.AddUnique(FileKeyBoxPayloadTypeUniqueID)
	rpc.AddUnique(ChunkNoncePayloadTypeUniqueID)
	rpc.AddUnique(KVProtocolID)
}
