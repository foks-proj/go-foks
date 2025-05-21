// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/token.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type ViewToken struct {
	IsSelf bool
	Token  PermissionToken
}
type ViewTokenInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	IsSelf  *bool
	Token   *PermissionTokenInternal__
}

func (v ViewTokenInternal__) Import() ViewToken {
	return ViewToken{
		IsSelf: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(v.IsSelf),
		Token: (func(x *PermissionTokenInternal__) (ret PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(v.Token),
	}
}
func (v ViewToken) Export() *ViewTokenInternal__ {
	return &ViewTokenInternal__{
		IsSelf: &v.IsSelf,
		Token:  v.Token.Export(),
	}
}
func (v *ViewToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(v.Export())
}

func (v *ViewToken) Decode(dec rpc.Decoder) error {
	var tmp ViewTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*v = tmp.Import()
	return nil
}

func (v *ViewToken) Bytes() []byte { return nil }
