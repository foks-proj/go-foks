// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/web.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type CSRFPayload struct {
	Uid   UID
	Etime Time
}
type CSRFPayloadInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid     *UIDInternal__
	Etime   *TimeInternal__
}

func (c CSRFPayloadInternal__) Import() CSRFPayload {
	return CSRFPayload{
		Uid: (func(x *UIDInternal__) (ret UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Uid),
		Etime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Etime),
	}
}
func (c CSRFPayload) Export() *CSRFPayloadInternal__ {
	return &CSRFPayloadInternal__{
		Uid:   c.Uid.Export(),
		Etime: c.Etime.Export(),
	}
}
func (c *CSRFPayload) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CSRFPayload) Decode(dec rpc.Decoder) error {
	var tmp CSRFPayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var CSRFPayloadTypeUniqueID = rpc.TypeUniqueID(0x88a926cac9fa88ee)

func (c *CSRFPayload) GetTypeUniqueID() rpc.TypeUniqueID {
	return CSRFPayloadTypeUniqueID
}
func (c *CSRFPayload) Bytes() []byte { return nil }

type CSRFTokenV1 struct {
	KeyID HMACKeyID
	Etime Time
	Hmac  HMAC
}
type CSRFTokenV1Internal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	KeyID   *HMACKeyIDInternal__
	Etime   *TimeInternal__
	Hmac    *HMACInternal__
}

func (c CSRFTokenV1Internal__) Import() CSRFTokenV1 {
	return CSRFTokenV1{
		KeyID: (func(x *HMACKeyIDInternal__) (ret HMACKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.KeyID),
		Etime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Etime),
		Hmac: (func(x *HMACInternal__) (ret HMAC) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Hmac),
	}
}
func (c CSRFTokenV1) Export() *CSRFTokenV1Internal__ {
	return &CSRFTokenV1Internal__{
		KeyID: c.KeyID.Export(),
		Etime: c.Etime.Export(),
		Hmac:  c.Hmac.Export(),
	}
}
func (c *CSRFTokenV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CSRFTokenV1) Decode(dec rpc.Decoder) error {
	var tmp CSRFTokenV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CSRFTokenV1) Bytes() []byte { return nil }

type CSRFTokenVersion int

const (
	CSRFTokenVersion_V1 CSRFTokenVersion = 1
)

var CSRFTokenVersionMap = map[string]CSRFTokenVersion{
	"V1": 1,
}
var CSRFTokenVersionRevMap = map[CSRFTokenVersion]string{
	1: "V1",
}

type CSRFTokenVersionInternal__ CSRFTokenVersion

func (c CSRFTokenVersionInternal__) Import() CSRFTokenVersion {
	return CSRFTokenVersion(c)
}
func (c CSRFTokenVersion) Export() *CSRFTokenVersionInternal__ {
	return ((*CSRFTokenVersionInternal__)(&c))
}

type CSRFToken struct {
	V     CSRFTokenVersion
	F_1__ *CSRFTokenV1 `json:"f1,omitempty"`
}
type CSRFTokenInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        CSRFTokenVersion
	Switch__ CSRFTokenInternalSwitch__
}
type CSRFTokenInternalSwitch__ struct {
	_struct struct{}               `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *CSRFTokenV1Internal__ `codec:"1"`
}

func (c CSRFToken) GetV() (ret CSRFTokenVersion, err error) {
	switch c.V {
	case CSRFTokenVersion_V1:
		if c.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return c.V, nil
}
func (c CSRFToken) V1() CSRFTokenV1 {
	if c.F_1__ == nil {
		panic("unexpected nil case; should have been checked")
	}
	if c.V != CSRFTokenVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", c.V))
	}
	return *c.F_1__
}
func NewCSRFTokenWithV1(v CSRFTokenV1) CSRFToken {
	return CSRFToken{
		V:     CSRFTokenVersion_V1,
		F_1__: &v,
	}
}
func (c CSRFTokenInternal__) Import() CSRFToken {
	return CSRFToken{
		V: c.V,
		F_1__: (func(x *CSRFTokenV1Internal__) *CSRFTokenV1 {
			if x == nil {
				return nil
			}
			tmp := (func(x *CSRFTokenV1Internal__) (ret CSRFTokenV1) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Switch__.F_1__),
	}
}
func (c CSRFToken) Export() *CSRFTokenInternal__ {
	return &CSRFTokenInternal__{
		V: c.V,
		Switch__: CSRFTokenInternalSwitch__{
			F_1__: (func(x *CSRFTokenV1) *CSRFTokenV1Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(c.F_1__),
		},
	}
}
func (c *CSRFToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CSRFToken) Decode(dec rpc.Decoder) error {
	var tmp CSRFTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CSRFToken) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(CSRFPayloadTypeUniqueID)
}
