// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/kex.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type KexSeqNo uint64
type KexSeqNoInternal__ uint64

func (k KexSeqNo) Export() *KexSeqNoInternal__ {
	tmp := ((uint64)(k))
	return ((*KexSeqNoInternal__)(&tmp))
}

func (k KexSeqNoInternal__) Import() KexSeqNo {
	tmp := (uint64)(k)
	return KexSeqNo((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KexSeqNo) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexSeqNo) Decode(dec rpc.Decoder) error {
	var tmp KexSeqNoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KexSeqNo) Bytes() []byte {
	return nil
}

type KexSecret [16]byte
type KexSecretInternal__ [16]byte

func (k KexSecret) Export() *KexSecretInternal__ {
	tmp := (([16]byte)(k))
	return ((*KexSecretInternal__)(&tmp))
}

func (k KexSecretInternal__) Import() KexSecret {
	tmp := ([16]byte)(k)
	return KexSecret((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KexSecret) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexSecret) Decode(dec rpc.Decoder) error {
	var tmp KexSecretInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

var KexSecretTypeUniqueID = rpc.TypeUniqueID(0xd11db788412b370b)

func (k *KexSecret) GetTypeUniqueID() rpc.TypeUniqueID {
	return KexSecretTypeUniqueID
}

func (k KexSecret) Bytes() []byte {
	return (k)[:]
}

type KexSessionID [32]byte
type KexSessionIDInternal__ [32]byte

func (k KexSessionID) Export() *KexSessionIDInternal__ {
	tmp := (([32]byte)(k))
	return ((*KexSessionIDInternal__)(&tmp))
}

func (k KexSessionIDInternal__) Import() KexSessionID {
	tmp := ([32]byte)(k)
	return KexSessionID((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KexSessionID) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexSessionID) Decode(dec rpc.Decoder) error {
	var tmp KexSessionIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KexSessionID) Bytes() []byte {
	return (k)[:]
}

type KexHESP []string
type KexHESPInternal__ [](string)

func (k KexHESP) Export() *KexHESPInternal__ {
	tmp := (([]string)(k))
	return ((*KexHESPInternal__)((func(x []string) *[](string) {
		if len(x) == 0 {
			return nil
		}
		ret := make([](string), len(x))
		copy(ret, x)
		return &ret
	})(tmp)))
}

func (k KexHESPInternal__) Import() KexHESP {
	tmp := ([](string))(k)
	return KexHESP((func(x *[](string)) (ret []string) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]string, len(*x))
		for k, v := range *x {
			ret[k] = (func(x *string) (ret string) {
				if x == nil {
					return ret
				}
				return *x
			})(&v)
		}
		return ret
	})(&tmp))
}

func (k *KexHESP) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KexHESP) Decode(dec rpc.Decoder) error {
	var tmp KexHESPInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KexHESP) Bytes() []byte {
	return nil
}

func init() {
	rpc.AddUnique(KexSecretTypeUniqueID)
}
