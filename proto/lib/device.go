// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/device.snowp

package lib

import (
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type DeviceStatus int

const (
	DeviceStatus_ACTIVE  DeviceStatus = 0
	DeviceStatus_REVOKED DeviceStatus = 1
)

var DeviceStatusMap = map[string]DeviceStatus{
	"ACTIVE":  0,
	"REVOKED": 1,
}

var DeviceStatusRevMap = map[DeviceStatus]string{
	0: "ACTIVE",
	1: "REVOKED",
}

type DeviceStatusInternal__ DeviceStatus

func (d DeviceStatusInternal__) Import() DeviceStatus {
	return DeviceStatus(d)
}

func (d DeviceStatus) Export() *DeviceStatusInternal__ {
	return ((*DeviceStatusInternal__)(&d))
}

type NormalizationVersion int

const (
	NormalizationVersion_V0 NormalizationVersion = 0
)

var NormalizationVersionMap = map[string]NormalizationVersion{
	"V0": 0,
}

var NormalizationVersionRevMap = map[NormalizationVersion]string{
	0: "V0",
}

type NormalizationVersionInternal__ NormalizationVersion

func (n NormalizationVersionInternal__) Import() NormalizationVersion {
	return NormalizationVersion(n)
}

func (n NormalizationVersion) Export() *NormalizationVersionInternal__ {
	return ((*NormalizationVersionInternal__)(&n))
}

type DeviceNameNormalized string
type DeviceNameNormalizedInternal__ string

func (d DeviceNameNormalized) Export() *DeviceNameNormalizedInternal__ {
	tmp := ((string)(d))
	return ((*DeviceNameNormalizedInternal__)(&tmp))
}

func (d DeviceNameNormalizedInternal__) Import() DeviceNameNormalized {
	tmp := (string)(d)
	return DeviceNameNormalized((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DeviceNameNormalized) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceNameNormalized) Decode(dec rpc.Decoder) error {
	var tmp DeviceNameNormalizedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DeviceNameNormalized) Bytes() []byte {
	return nil
}

type DeviceName string
type DeviceNameInternal__ string

func (d DeviceName) Export() *DeviceNameInternal__ {
	tmp := ((string)(d))
	return ((*DeviceNameInternal__)(&tmp))
}

func (d DeviceNameInternal__) Import() DeviceName {
	tmp := (string)(d)
	return DeviceName((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DeviceName) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceName) Decode(dec rpc.Decoder) error {
	var tmp DeviceNameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DeviceName) Bytes() []byte {
	return nil
}

type DeviceSerial uint64
type DeviceSerialInternal__ uint64

func (d DeviceSerial) Export() *DeviceSerialInternal__ {
	tmp := ((uint64)(d))
	return ((*DeviceSerialInternal__)(&tmp))
}

func (d DeviceSerialInternal__) Import() DeviceSerial {
	tmp := (uint64)(d)
	return DeviceSerial((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DeviceSerial) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceSerial) Decode(dec rpc.Decoder) error {
	var tmp DeviceSerialInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DeviceSerial) Bytes() []byte {
	return nil
}

type DeviceLabel struct {
	DeviceType DeviceType
	Name       DeviceNameNormalized
	Serial     DeviceSerial
}

type DeviceLabelInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	DeviceType *DeviceTypeInternal__
	Name       *DeviceNameNormalizedInternal__
	Serial     *DeviceSerialInternal__
}

func (d DeviceLabelInternal__) Import() DeviceLabel {
	return DeviceLabel{
		DeviceType: (func(x *DeviceTypeInternal__) (ret DeviceType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.DeviceType),
		Name: (func(x *DeviceNameNormalizedInternal__) (ret DeviceNameNormalized) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Name),
		Serial: (func(x *DeviceSerialInternal__) (ret DeviceSerial) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Serial),
	}
}

func (d DeviceLabel) Export() *DeviceLabelInternal__ {
	return &DeviceLabelInternal__{
		DeviceType: d.DeviceType.Export(),
		Name:       d.Name.Export(),
		Serial:     d.Serial.Export(),
	}
}

func (d *DeviceLabel) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceLabel) Decode(dec rpc.Decoder) error {
	var tmp DeviceLabelInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

var DeviceLabelTypeUniqueID = rpc.TypeUniqueID(0x9650227205486122)

func (d *DeviceLabel) GetTypeUniqueID() rpc.TypeUniqueID {
	return DeviceLabelTypeUniqueID
}

func (d *DeviceLabel) Bytes() []byte { return nil }

type DeviceNameNormalizationPreimage struct {
	Nv   NormalizationVersion
	Name DeviceName
}

type DeviceNameNormalizationPreimageInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Nv      *NormalizationVersionInternal__
	Name    *DeviceNameInternal__
}

func (d DeviceNameNormalizationPreimageInternal__) Import() DeviceNameNormalizationPreimage {
	return DeviceNameNormalizationPreimage{
		Nv: (func(x *NormalizationVersionInternal__) (ret NormalizationVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Nv),
		Name: (func(x *DeviceNameInternal__) (ret DeviceName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Name),
	}
}

func (d DeviceNameNormalizationPreimage) Export() *DeviceNameNormalizationPreimageInternal__ {
	return &DeviceNameNormalizationPreimageInternal__{
		Nv:   d.Nv.Export(),
		Name: d.Name.Export(),
	}
}

func (d *DeviceNameNormalizationPreimage) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceNameNormalizationPreimage) Decode(dec rpc.Decoder) error {
	var tmp DeviceNameNormalizationPreimageInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DeviceNameNormalizationPreimage) Bytes() []byte { return nil }

type DeviceLabelAndName struct {
	Label DeviceLabel
	Nv    NormalizationVersion
	Name  DeviceName
}

type DeviceLabelAndNameInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Label   *DeviceLabelInternal__
	Nv      *NormalizationVersionInternal__
	Name    *DeviceNameInternal__
}

func (d DeviceLabelAndNameInternal__) Import() DeviceLabelAndName {
	return DeviceLabelAndName{
		Label: (func(x *DeviceLabelInternal__) (ret DeviceLabel) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Label),
		Nv: (func(x *NormalizationVersionInternal__) (ret NormalizationVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Nv),
		Name: (func(x *DeviceNameInternal__) (ret DeviceName) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Name),
	}
}

func (d DeviceLabelAndName) Export() *DeviceLabelAndNameInternal__ {
	return &DeviceLabelAndNameInternal__{
		Label: d.Label.Export(),
		Nv:    d.Nv.Export(),
		Name:  d.Name.Export(),
	}
}

func (d *DeviceLabelAndName) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceLabelAndName) Decode(dec rpc.Decoder) error {
	var tmp DeviceLabelAndNameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DeviceLabelAndName) Bytes() []byte { return nil }

type ProvisionInfo struct {
	Signer EntityID
	Chain  BaseChainer
	Leaf   MerkleLeaf
}

type ProvisionInfoInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Signer  *EntityIDInternal__
	Chain   *BaseChainerInternal__
	Leaf    *MerkleLeafInternal__
}

func (p ProvisionInfoInternal__) Import() ProvisionInfo {
	return ProvisionInfo{
		Signer: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Signer),
		Chain: (func(x *BaseChainerInternal__) (ret BaseChainer) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Chain),
		Leaf: (func(x *MerkleLeafInternal__) (ret MerkleLeaf) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Leaf),
	}
}

func (p ProvisionInfo) Export() *ProvisionInfoInternal__ {
	return &ProvisionInfoInternal__{
		Signer: p.Signer.Export(),
		Chain:  p.Chain.Export(),
		Leaf:   p.Leaf.Export(),
	}
}

func (p *ProvisionInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ProvisionInfo) Decode(dec rpc.Decoder) error {
	var tmp ProvisionInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *ProvisionInfo) Bytes() []byte { return nil }

type DeviceInfo struct {
	Status      DeviceStatus
	Dn          *DeviceLabelAndName
	Key         MemberRole
	Ctime       Time
	Provisioned ProvisionInfo
	Revoked     *RevokeInfo
}

type DeviceInfoInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Status      *DeviceStatusInternal__
	Dn          *DeviceLabelAndNameInternal__
	Key         *MemberRoleInternal__
	Ctime       *TimeInternal__
	Provisioned *ProvisionInfoInternal__
	Revoked     *RevokeInfoInternal__
}

func (d DeviceInfoInternal__) Import() DeviceInfo {
	return DeviceInfo{
		Status: (func(x *DeviceStatusInternal__) (ret DeviceStatus) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Status),
		Dn: (func(x *DeviceLabelAndNameInternal__) *DeviceLabelAndName {
			if x == nil {
				return nil
			}
			tmp := (func(x *DeviceLabelAndNameInternal__) (ret DeviceLabelAndName) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(d.Dn),
		Key: (func(x *MemberRoleInternal__) (ret MemberRole) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Key),
		Ctime: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Ctime),
		Provisioned: (func(x *ProvisionInfoInternal__) (ret ProvisionInfo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(d.Provisioned),
		Revoked: (func(x *RevokeInfoInternal__) *RevokeInfo {
			if x == nil {
				return nil
			}
			tmp := (func(x *RevokeInfoInternal__) (ret RevokeInfo) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(d.Revoked),
	}
}

func (d DeviceInfo) Export() *DeviceInfoInternal__ {
	return &DeviceInfoInternal__{
		Status: d.Status.Export(),
		Dn: (func(x *DeviceLabelAndName) *DeviceLabelAndNameInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(d.Dn),
		Key:         d.Key.Export(),
		Ctime:       d.Ctime.Export(),
		Provisioned: d.Provisioned.Export(),
		Revoked: (func(x *RevokeInfo) *RevokeInfoInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(d.Revoked),
	}
}

func (d *DeviceInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceInfo) Decode(dec rpc.Decoder) error {
	var tmp DeviceInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DeviceInfo) Bytes() []byte { return nil }

type DeviceNagInfo struct {
	NumDevices uint64
	Cleared    bool
}

type DeviceNagInfoInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	NumDevices *uint64
	Cleared    *bool
}

func (d DeviceNagInfoInternal__) Import() DeviceNagInfo {
	return DeviceNagInfo{
		NumDevices: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(d.NumDevices),
		Cleared: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(d.Cleared),
	}
}

func (d DeviceNagInfo) Export() *DeviceNagInfoInternal__ {
	return &DeviceNagInfoInternal__{
		NumDevices: &d.NumDevices,
		Cleared:    &d.Cleared,
	}
}

func (d *DeviceNagInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceNagInfo) Decode(dec rpc.Decoder) error {
	var tmp DeviceNagInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DeviceNagInfo) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(DeviceLabelTypeUniqueID)
}
