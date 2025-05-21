// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/test.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type TestLinkOuterV1 struct {
	Inner      []byte
	Signatures []Signature
}
type TestLinkOuterV1Internal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Inner      *[]byte
	Signatures *[](*SignatureInternal__)
}

func (t TestLinkOuterV1Internal__) Import() TestLinkOuterV1 {
	return TestLinkOuterV1{
		Inner: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(t.Inner),
		Signatures: (func(x *[](*SignatureInternal__)) (ret []Signature) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]Signature, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *SignatureInternal__) (ret Signature) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(t.Signatures),
	}
}
func (t TestLinkOuterV1) Export() *TestLinkOuterV1Internal__ {
	return &TestLinkOuterV1Internal__{
		Inner: &t.Inner,
		Signatures: (func(x []Signature) *[](*SignatureInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*SignatureInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(t.Signatures),
	}
}
func (t *TestLinkOuterV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TestLinkOuterV1) Decode(dec rpc.Decoder) error {
	var tmp TestLinkOuterV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TestLinkOuterV1TypeUniqueID = rpc.TypeUniqueID(0xb901b988ddc2552d)

func (t *TestLinkOuterV1) GetTypeUniqueID() rpc.TypeUniqueID {
	return TestLinkOuterV1TypeUniqueID
}
func (t *TestLinkOuterV1) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(TestLinkOuterV1TypeUniqueID)
}
