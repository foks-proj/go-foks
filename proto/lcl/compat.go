// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lcl/compat.snowp

package lcl

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type HeaderVersion int

const (
	HeaderVersion_V1 HeaderVersion = 1
)

var HeaderVersionMap = map[string]HeaderVersion{
	"V1": 1,
}

var HeaderVersionRevMap = map[HeaderVersion]string{
	1: "V1",
}

type HeaderVersionInternal__ HeaderVersion

func (h HeaderVersionInternal__) Import() HeaderVersion {
	return HeaderVersion(h)
}

func (h HeaderVersion) Export() *HeaderVersionInternal__ {
	return ((*HeaderVersionInternal__)(&h))
}

type Header struct {
	V     HeaderVersion
	F_1__ *HeaderV1 `json:"f1,omitempty"`
}

type HeaderInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        HeaderVersion
	Switch__ HeaderInternalSwitch__
}

type HeaderInternalSwitch__ struct {
	_struct struct{}            `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *HeaderV1Internal__ `codec:"1"`
}

func (h Header) GetV() (ret HeaderVersion, err error) {
	switch h.V {
	case HeaderVersion_V1:
		if h.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return h.V, nil
}

func (h Header) V1() HeaderV1 {
	if h.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if h.V != HeaderVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", h.V))
	}
	return *h.F_1__
}

func NewHeaderWithV1(v HeaderV1) Header {
	return Header{
		V:     HeaderVersion_V1,
		F_1__: &v,
	}
}

func (h HeaderInternal__) Import() Header {
	return Header{
		V: h.V,
		F_1__: (func(x *HeaderV1Internal__) *HeaderV1 {
			if x == nil {
				return nil
			}
			tmp := (func(x *HeaderV1Internal__) (ret HeaderV1) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(h.Switch__.F_1__),
	}
}

func (h Header) Export() *HeaderInternal__ {
	return &HeaderInternal__{
		V: h.V,
		Switch__: HeaderInternalSwitch__{
			F_1__: (func(x *HeaderV1) *HeaderV1Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(h.F_1__),
		},
	}
}

func (h *Header) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *Header) Decode(dec rpc.Decoder) error {
	var tmp HeaderInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *Header) Bytes() []byte { return nil }

type SemVer struct {
	Major uint64
	Minor uint64
	Patch uint64
}

type SemVerInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Major   *uint64
	Minor   *uint64
	Patch   *uint64
}

func (s SemVerInternal__) Import() SemVer {
	return SemVer{
		Major: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Major),
		Minor: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Minor),
		Patch: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(s.Patch),
	}
}

func (s SemVer) Export() *SemVerInternal__ {
	return &SemVerInternal__{
		Major: &s.Major,
		Minor: &s.Minor,
		Patch: &s.Patch,
	}
}

func (s *SemVer) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SemVer) Decode(dec rpc.Decoder) error {
	var tmp SemVerInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SemVer) Bytes() []byte { return nil }

type HeaderV1 struct {
	Semver SemVer
}

type HeaderV1Internal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Semver  *SemVerInternal__
}

func (h HeaderV1Internal__) Import() HeaderV1 {
	return HeaderV1{
		Semver: (func(x *SemVerInternal__) (ret SemVer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Semver),
	}
}

func (h HeaderV1) Export() *HeaderV1Internal__ {
	return &HeaderV1Internal__{
		Semver: h.Semver.Export(),
	}
}

func (h *HeaderV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HeaderV1) Decode(dec rpc.Decoder) error {
	var tmp HeaderV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HeaderV1) Bytes() []byte { return nil }
