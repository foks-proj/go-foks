// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/names.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type NameUtf8 string
type NameUtf8Internal__ string

func (n NameUtf8) Export() *NameUtf8Internal__ {
	tmp := ((string)(n))
	return ((*NameUtf8Internal__)(&tmp))
}
func (n NameUtf8Internal__) Import() NameUtf8 {
	tmp := (string)(n)
	return NameUtf8((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (n *NameUtf8) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NameUtf8) Decode(dec rpc.Decoder) error {
	var tmp NameUtf8Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n NameUtf8) Bytes() []byte {
	return nil
}

type NameSeqno int64
type NameSeqnoInternal__ int64

func (n NameSeqno) Export() *NameSeqnoInternal__ {
	tmp := ((int64)(n))
	return ((*NameSeqnoInternal__)(&tmp))
}
func (n NameSeqnoInternal__) Import() NameSeqno {
	tmp := (int64)(n)
	return NameSeqno((func(x *int64) (ret int64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (n *NameSeqno) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NameSeqno) Decode(dec rpc.Decoder) error {
	var tmp NameSeqnoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n NameSeqno) Bytes() []byte {
	return nil
}

type NameBundle struct {
	Name     Name
	NameUtf8 NameUtf8
}
type NameBundleInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name     *NameInternal__
	NameUtf8 *NameUtf8Internal__
}

func (n NameBundleInternal__) Import() NameBundle {
	return NameBundle{
		Name: (func(x *NameInternal__) (ret Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Name),
		NameUtf8: (func(x *NameUtf8Internal__) (ret NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.NameUtf8),
	}
}
func (n NameBundle) Export() *NameBundleInternal__ {
	return &NameBundleInternal__{
		Name:     n.Name.Export(),
		NameUtf8: n.NameUtf8.Export(),
	}
}
func (n *NameBundle) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NameBundle) Decode(dec rpc.Decoder) error {
	var tmp NameBundleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NameBundle) Bytes() []byte { return nil }

type NameAndSeqnoBundle struct {
	B NameBundle
	S NameSeqno
}
type NameAndSeqnoBundleInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	B       *NameBundleInternal__
	S       *NameSeqnoInternal__
}

func (n NameAndSeqnoBundleInternal__) Import() NameAndSeqnoBundle {
	return NameAndSeqnoBundle{
		B: (func(x *NameBundleInternal__) (ret NameBundle) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.B),
		S: (func(x *NameSeqnoInternal__) (ret NameSeqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.S),
	}
}
func (n NameAndSeqnoBundle) Export() *NameAndSeqnoBundleInternal__ {
	return &NameAndSeqnoBundleInternal__{
		B: n.B.Export(),
		S: n.S.Export(),
	}
}
func (n *NameAndSeqnoBundle) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NameAndSeqnoBundle) Decode(dec rpc.Decoder) error {
	var tmp NameAndSeqnoBundleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NameAndSeqnoBundle) Bytes() []byte { return nil }
