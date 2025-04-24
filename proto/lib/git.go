// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/git.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type GitRepo string
type GitRepoInternal__ string

func (g GitRepo) Export() *GitRepoInternal__ {
	tmp := ((string)(g))
	return ((*GitRepoInternal__)(&tmp))
}

func (g GitRepoInternal__) Import() GitRepo {
	tmp := (string)(g)
	return GitRepo((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (g *GitRepo) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitRepo) Decode(dec rpc.Decoder) error {
	var tmp GitRepoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g GitRepo) Bytes() []byte {
	return nil
}

type GitRemoteRepoID struct {
	Host HostID
	Dir  DirID
}

type GitRemoteRepoIDInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Host    *HostIDInternal__
	Dir     *DirIDInternal__
}

func (g GitRemoteRepoIDInternal__) Import() GitRemoteRepoID {
	return GitRemoteRepoID{
		Host: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Host),
		Dir: (func(x *DirIDInternal__) (ret DirID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Dir),
	}
}

func (g GitRemoteRepoID) Export() *GitRemoteRepoIDInternal__ {
	return &GitRemoteRepoIDInternal__{
		Host: g.Host.Export(),
		Dir:  g.Dir.Export(),
	}
}

func (g *GitRemoteRepoID) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitRemoteRepoID) Decode(dec rpc.Decoder) error {
	var tmp GitRemoteRepoIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitRemoteRepoID) Bytes() []byte { return nil }

type GitProtoType int

const (
	GitProtoType_Foks GitProtoType = 1
)

var GitProtoTypeMap = map[string]GitProtoType{
	"Foks": 1,
}

var GitProtoTypeRevMap = map[GitProtoType]string{
	1: "Foks",
}

type GitProtoTypeInternal__ GitProtoType

func (g GitProtoTypeInternal__) Import() GitProtoType {
	return GitProtoType(g)
}

func (g GitProtoType) Export() *GitProtoTypeInternal__ {
	return ((*GitProtoTypeInternal__)(&g))
}

type GitURLString string
type GitURLStringInternal__ string

func (g GitURLString) Export() *GitURLStringInternal__ {
	tmp := ((string)(g))
	return ((*GitURLStringInternal__)(&tmp))
}

func (g GitURLStringInternal__) Import() GitURLString {
	tmp := (string)(g)
	return GitURLString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (g *GitURLString) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitURLString) Decode(dec rpc.Decoder) error {
	var tmp GitURLStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g GitURLString) Bytes() []byte {
	return nil
}

type GitRefBoxed struct {
	De  KVDirent
	Sfb SmallFileBox
}

type GitRefBoxedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	De      *KVDirentInternal__
	Sfb     *SmallFileBoxInternal__
}

func (g GitRefBoxedInternal__) Import() GitRefBoxed {
	return GitRefBoxed{
		De: (func(x *KVDirentInternal__) (ret KVDirent) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.De),
		Sfb: (func(x *SmallFileBoxInternal__) (ret SmallFileBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Sfb),
	}
}

func (g GitRefBoxed) Export() *GitRefBoxedInternal__ {
	return &GitRefBoxedInternal__{
		De:  g.De.Export(),
		Sfb: g.Sfb.Export(),
	}
}

func (g *GitRefBoxed) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitRefBoxed) Decode(dec rpc.Decoder) error {
	var tmp GitRefBoxedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitRefBoxed) Bytes() []byte { return nil }

type GitRef struct {
	Name  KVPath
	Value string
}

type GitRefInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name    *KVPathInternal__
	Value   *string
}

func (g GitRefInternal__) Import() GitRef {
	return GitRef{
		Name: (func(x *KVPathInternal__) (ret KVPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Name),
		Value: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(g.Value),
	}
}

func (g GitRef) Export() *GitRefInternal__ {
	return &GitRefInternal__{
		Name:  g.Name.Export(),
		Value: &g.Value,
	}
}

func (g *GitRef) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitRef) Decode(dec rpc.Decoder) error {
	var tmp GitRefInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitRef) Bytes() []byte { return nil }

type GitRefBoxedSet struct {
	DirVersion KVVersion
	Refs       []GitRefBoxed
}

type GitRefBoxedSetInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	DirVersion *KVVersionInternal__
	Refs       *[](*GitRefBoxedInternal__)
}

func (g GitRefBoxedSetInternal__) Import() GitRefBoxedSet {
	return GitRefBoxedSet{
		DirVersion: (func(x *KVVersionInternal__) (ret KVVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.DirVersion),
		Refs: (func(x *[](*GitRefBoxedInternal__)) (ret []GitRefBoxed) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]GitRefBoxed, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *GitRefBoxedInternal__) (ret GitRefBoxed) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Refs),
	}
}

func (g GitRefBoxedSet) Export() *GitRefBoxedSetInternal__ {
	return &GitRefBoxedSetInternal__{
		DirVersion: g.DirVersion.Export(),
		Refs: (func(x []GitRefBoxed) *[](*GitRefBoxedInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*GitRefBoxedInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Refs),
	}
}

func (g *GitRefBoxedSet) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitRefBoxedSet) Decode(dec rpc.Decoder) error {
	var tmp GitRefBoxedSetInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitRefBoxedSet) Bytes() []byte { return nil }

type GitURL struct {
	Proto GitProtoType
	Fqp   FQPartyParsed
	Repo  GitRepo
}

type GitURLInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Proto   *GitProtoTypeInternal__
	Fqp     *FQPartyParsedInternal__
	Repo    *GitRepoInternal__
}

func (g GitURLInternal__) Import() GitURL {
	return GitURL{
		Proto: (func(x *GitProtoTypeInternal__) (ret GitProtoType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Proto),
		Fqp: (func(x *FQPartyParsedInternal__) (ret FQPartyParsed) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Fqp),
		Repo: (func(x *GitRepoInternal__) (ret GitRepo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Repo),
	}
}

func (g GitURL) Export() *GitURLInternal__ {
	return &GitURLInternal__{
		Proto: g.Proto.Export(),
		Fqp:   g.Fqp.Export(),
		Repo:  g.Repo.Export(),
	}
}

func (g *GitURL) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitURL) Decode(dec rpc.Decoder) error {
	var tmp GitURLInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitURL) Bytes() []byte { return nil }
