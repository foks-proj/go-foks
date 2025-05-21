// Auto-generated to Go types and interfaces using snowpc 0.0.4 (https://github.com/foks-proj/go-snowpack-compiler)
//  Input file:../../proto-src/lib/config.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type ViewershipMode int

const (
	ViewershipMode_Closed      ViewershipMode = 0
	ViewershipMode_OpenToAdmin ViewershipMode = 1
	ViewershipMode_OpenToAll   ViewershipMode = 2
)

var ViewershipModeMap = map[string]ViewershipMode{
	"Closed":      0,
	"OpenToAdmin": 1,
	"OpenToAll":   2,
}
var ViewershipModeRevMap = map[ViewershipMode]string{
	0: "Closed",
	1: "OpenToAdmin",
	2: "OpenToAll",
}

type ViewershipModeInternal__ ViewershipMode

func (v ViewershipModeInternal__) Import() ViewershipMode {
	return ViewershipMode(v)
}
func (v ViewershipMode) Export() *ViewershipModeInternal__ {
	return ((*ViewershipModeInternal__)(&v))
}

type HostType int

const (
	HostType_None            HostType = 0
	HostType_BigTop          HostType = 1
	HostType_VHostManagement HostType = 2
	HostType_VHost           HostType = 3
)

var HostTypeMap = map[string]HostType{
	"None":            0,
	"BigTop":          1,
	"VHostManagement": 2,
	"VHost":           3,
}
var HostTypeRevMap = map[HostType]string{
	0: "None",
	1: "BigTop",
	2: "VHostManagement",
	3: "VHost",
}

type HostTypeInternal__ HostType

func (h HostTypeInternal__) Import() HostType {
	return HostType(h)
}
func (h HostType) Export() *HostTypeInternal__ {
	return ((*HostTypeInternal__)(&h))
}

type HostViewership struct {
	User ViewershipMode
	Team ViewershipMode
}
type HostViewershipInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	User    *ViewershipModeInternal__
	Team    *ViewershipModeInternal__
}

func (h HostViewershipInternal__) Import() HostViewership {
	return HostViewership{
		User: (func(x *ViewershipModeInternal__) (ret ViewershipMode) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.User),
		Team: (func(x *ViewershipModeInternal__) (ret ViewershipMode) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Team),
	}
}
func (h HostViewership) Export() *HostViewershipInternal__ {
	return &HostViewershipInternal__{
		User: h.User.Export(),
		Team: h.Team.Export(),
	}
}
func (h *HostViewership) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostViewership) Decode(dec rpc.Decoder) error {
	var tmp HostViewershipInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostViewership) Bytes() []byte { return nil }

type Metering struct {
	Users        bool
	VHosts       bool
	PerVHostDisk bool
}
type MeteringInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Users        *bool
	VHosts       *bool
	PerVHostDisk *bool
}

func (m MeteringInternal__) Import() Metering {
	return Metering{
		Users: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Users),
		VHosts: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(m.VHosts),
		PerVHostDisk: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(m.PerVHostDisk),
	}
}
func (m Metering) Export() *MeteringInternal__ {
	return &MeteringInternal__{
		Users:        &m.Users,
		VHosts:       &m.VHosts,
		PerVHostDisk: &m.PerVHostDisk,
	}
}
func (m *Metering) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *Metering) Decode(dec rpc.Decoder) error {
	var tmp MeteringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *Metering) Bytes() []byte { return nil }

type HostConfig struct {
	Metering   Metering
	Viewership HostViewership
	Typ        HostType
}
type HostConfigInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Metering   *MeteringInternal__
	Viewership *HostViewershipInternal__
	Typ        *HostTypeInternal__
}

func (h HostConfigInternal__) Import() HostConfig {
	return HostConfig{
		Metering: (func(x *MeteringInternal__) (ret Metering) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Metering),
		Viewership: (func(x *HostViewershipInternal__) (ret HostViewership) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Viewership),
		Typ: (func(x *HostTypeInternal__) (ret HostType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Typ),
	}
}
func (h HostConfig) Export() *HostConfigInternal__ {
	return &HostConfigInternal__{
		Metering:   h.Metering.Export(),
		Viewership: h.Viewership.Export(),
		Typ:        h.Typ.Export(),
	}
}
func (h *HostConfig) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostConfig) Decode(dec rpc.Decoder) error {
	var tmp HostConfigInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HostConfig) Bytes() []byte { return nil }
