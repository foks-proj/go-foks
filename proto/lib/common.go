// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lib/common.snowp

package lib

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type EntityID []byte
type EntityIDInternal__ []byte

func (e EntityID) Export() *EntityIDInternal__ {
	tmp := (([]byte)(e))
	return ((*EntityIDInternal__)(&tmp))
}

func (e EntityIDInternal__) Import() EntityID {
	tmp := ([]byte)(e)
	return EntityID((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *EntityID) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *EntityID) Decode(dec rpc.Decoder) error {
	var tmp EntityIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e EntityID) Bytes() []byte {
	return (e)[:]
}

type EntityID33 [33]byte
type EntityID33Internal__ [33]byte

func (e EntityID33) Export() *EntityID33Internal__ {
	tmp := (([33]byte)(e))
	return ((*EntityID33Internal__)(&tmp))
}

func (e EntityID33Internal__) Import() EntityID33 {
	tmp := ([33]byte)(e)
	return EntityID33((func(x *[33]byte) (ret [33]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *EntityID33) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *EntityID33) Decode(dec rpc.Decoder) error {
	var tmp EntityID33Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e EntityID33) Bytes() []byte {
	return (e)[:]
}

type EntityID34 [34]byte
type EntityID34Internal__ [34]byte

func (e EntityID34) Export() *EntityID34Internal__ {
	tmp := (([34]byte)(e))
	return ((*EntityID34Internal__)(&tmp))
}

func (e EntityID34Internal__) Import() EntityID34 {
	tmp := ([34]byte)(e)
	return EntityID34((func(x *[34]byte) (ret [34]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *EntityID34) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *EntityID34) Decode(dec rpc.Decoder) error {
	var tmp EntityID34Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e EntityID34) Bytes() []byte {
	return (e)[:]
}

type UID EntityID33
type UIDInternal__ EntityID33Internal__

func (u UID) Export() *UIDInternal__ {
	tmp := ((EntityID33)(u))
	return ((*UIDInternal__)(tmp.Export()))
}

func (u UIDInternal__) Import() UID {
	tmp := (EntityID33Internal__)(u)
	return UID((func(x *EntityID33Internal__) (ret EntityID33) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (u *UID) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UID) Decode(dec rpc.Decoder) error {
	var tmp UIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u UID) Bytes() []byte {
	return ((EntityID33)(u)).Bytes()
}

type TeamID EntityID33
type TeamIDInternal__ EntityID33Internal__

func (t TeamID) Export() *TeamIDInternal__ {
	tmp := ((EntityID33)(t))
	return ((*TeamIDInternal__)(tmp.Export()))
}

func (t TeamIDInternal__) Import() TeamID {
	tmp := (EntityID33Internal__)(t)
	return TeamID((func(x *EntityID33Internal__) (ret EntityID33) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (t *TeamID) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamID) Decode(dec rpc.Decoder) error {
	var tmp TeamIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TeamID) Bytes() []byte {
	return ((EntityID33)(t)).Bytes()
}

type DeviceID EntityID
type DeviceIDInternal__ EntityIDInternal__

func (d DeviceID) Export() *DeviceIDInternal__ {
	tmp := ((EntityID)(d))
	return ((*DeviceIDInternal__)(tmp.Export()))
}

func (d DeviceIDInternal__) Import() DeviceID {
	tmp := (EntityIDInternal__)(d)
	return DeviceID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (d *DeviceID) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DeviceID) Decode(dec rpc.Decoder) error {
	var tmp DeviceIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DeviceID) Bytes() []byte {
	return ((EntityID)(d)).Bytes()
}

type X509CertID EntityID
type X509CertIDInternal__ EntityIDInternal__

func (x X509CertID) Export() *X509CertIDInternal__ {
	tmp := ((EntityID)(x))
	return ((*X509CertIDInternal__)(tmp.Export()))
}

func (x X509CertIDInternal__) Import() X509CertID {
	tmp := (EntityIDInternal__)(x)
	return X509CertID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (x *X509CertID) Encode(enc rpc.Encoder) error {
	return enc.Encode(x.Export())
}

func (x *X509CertID) Decode(dec rpc.Decoder) error {
	var tmp X509CertIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*x = tmp.Import()
	return nil
}

func (x X509CertID) Bytes() []byte {
	return ((EntityID)(x)).Bytes()
}

type LocationVRFID EntityID
type LocationVRFIDInternal__ EntityIDInternal__

func (l LocationVRFID) Export() *LocationVRFIDInternal__ {
	tmp := ((EntityID)(l))
	return ((*LocationVRFIDInternal__)(tmp.Export()))
}

func (l LocationVRFIDInternal__) Import() LocationVRFID {
	tmp := (EntityIDInternal__)(l)
	return LocationVRFID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (l *LocationVRFID) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LocationVRFID) Decode(dec rpc.Decoder) error {
	var tmp LocationVRFIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l LocationVRFID) Bytes() []byte {
	return ((EntityID)(l)).Bytes()
}

type ServiceID EntityID
type ServiceIDInternal__ EntityIDInternal__

func (s ServiceID) Export() *ServiceIDInternal__ {
	tmp := ((EntityID)(s))
	return ((*ServiceIDInternal__)(tmp.Export()))
}

func (s ServiceIDInternal__) Import() ServiceID {
	tmp := (EntityIDInternal__)(s)
	return ServiceID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (s *ServiceID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *ServiceID) Decode(dec rpc.Decoder) error {
	var tmp ServiceIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s ServiceID) Bytes() []byte {
	return ((EntityID)(s)).Bytes()
}

type YubiID EntityID
type YubiIDInternal__ EntityIDInternal__

func (y YubiID) Export() *YubiIDInternal__ {
	tmp := ((EntityID)(y))
	return ((*YubiIDInternal__)(tmp.Export()))
}

func (y YubiIDInternal__) Import() YubiID {
	tmp := (EntityIDInternal__)(y)
	return YubiID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (y *YubiID) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiID) Decode(dec rpc.Decoder) error {
	var tmp YubiIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y YubiID) Bytes() []byte {
	return ((EntityID)(y)).Bytes()
}

type NameEntityID EntityID33
type NameEntityIDInternal__ EntityID33Internal__

func (n NameEntityID) Export() *NameEntityIDInternal__ {
	tmp := ((EntityID33)(n))
	return ((*NameEntityIDInternal__)(tmp.Export()))
}

func (n NameEntityIDInternal__) Import() NameEntityID {
	tmp := (EntityID33Internal__)(n)
	return NameEntityID((func(x *EntityID33Internal__) (ret EntityID33) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (n *NameEntityID) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NameEntityID) Decode(dec rpc.Decoder) error {
	var tmp NameEntityIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n NameEntityID) Bytes() []byte {
	return ((EntityID33)(n)).Bytes()
}

type HostMerkleSignerID EntityID
type HostMerkleSignerIDInternal__ EntityIDInternal__

func (h HostMerkleSignerID) Export() *HostMerkleSignerIDInternal__ {
	tmp := ((EntityID)(h))
	return ((*HostMerkleSignerIDInternal__)(tmp.Export()))
}

func (h HostMerkleSignerIDInternal__) Import() HostMerkleSignerID {
	tmp := (EntityIDInternal__)(h)
	return HostMerkleSignerID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (h *HostMerkleSignerID) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostMerkleSignerID) Decode(dec rpc.Decoder) error {
	var tmp HostMerkleSignerIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h HostMerkleSignerID) Bytes() []byte {
	return ((EntityID)(h)).Bytes()
}

type HostTLSCAID EntityID33
type HostTLSCAIDInternal__ EntityID33Internal__

func (h HostTLSCAID) Export() *HostTLSCAIDInternal__ {
	tmp := ((EntityID33)(h))
	return ((*HostTLSCAIDInternal__)(tmp.Export()))
}

func (h HostTLSCAIDInternal__) Import() HostTLSCAID {
	tmp := (EntityID33Internal__)(h)
	return HostTLSCAID((func(x *EntityID33Internal__) (ret EntityID33) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (h *HostTLSCAID) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostTLSCAID) Decode(dec rpc.Decoder) error {
	var tmp HostTLSCAIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h HostTLSCAID) Bytes() []byte {
	return ((EntityID33)(h)).Bytes()
}

type HostMetadataSignerID EntityID
type HostMetadataSignerIDInternal__ EntityIDInternal__

func (h HostMetadataSignerID) Export() *HostMetadataSignerIDInternal__ {
	tmp := ((EntityID)(h))
	return ((*HostMetadataSignerIDInternal__)(tmp.Export()))
}

func (h HostMetadataSignerIDInternal__) Import() HostMetadataSignerID {
	tmp := (EntityIDInternal__)(h)
	return HostMetadataSignerID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (h *HostMetadataSignerID) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostMetadataSignerID) Decode(dec rpc.Decoder) error {
	var tmp HostMetadataSignerIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h HostMetadataSignerID) Bytes() []byte {
	return ((EntityID)(h)).Bytes()
}

type SubkeyID EntityID
type SubkeyIDInternal__ EntityIDInternal__

func (s SubkeyID) Export() *SubkeyIDInternal__ {
	tmp := ((EntityID)(s))
	return ((*SubkeyIDInternal__)(tmp.Export()))
}

func (s SubkeyIDInternal__) Import() SubkeyID {
	tmp := (EntityIDInternal__)(s)
	return SubkeyID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (s *SubkeyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SubkeyID) Decode(dec rpc.Decoder) error {
	var tmp SubkeyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SubkeyID) Bytes() []byte {
	return ((EntityID)(s)).Bytes()
}

type PUKVerifyID EntityID
type PUKVerifyIDInternal__ EntityIDInternal__

func (p PUKVerifyID) Export() *PUKVerifyIDInternal__ {
	tmp := ((EntityID)(p))
	return ((*PUKVerifyIDInternal__)(tmp.Export()))
}

func (p PUKVerifyIDInternal__) Import() PUKVerifyID {
	tmp := (EntityIDInternal__)(p)
	return PUKVerifyID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (p *PUKVerifyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PUKVerifyID) Decode(dec rpc.Decoder) error {
	var tmp PUKVerifyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PUKVerifyID) Bytes() []byte {
	return ((EntityID)(p)).Bytes()
}

type PTKVerifyID EntityID
type PTKVerifyIDInternal__ EntityIDInternal__

func (p PTKVerifyID) Export() *PTKVerifyIDInternal__ {
	tmp := ((EntityID)(p))
	return ((*PTKVerifyIDInternal__)(tmp.Export()))
}

func (p PTKVerifyIDInternal__) Import() PTKVerifyID {
	tmp := (EntityIDInternal__)(p)
	return PTKVerifyID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (p *PTKVerifyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PTKVerifyID) Decode(dec rpc.Decoder) error {
	var tmp PTKVerifyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PTKVerifyID) Bytes() []byte {
	return ((EntityID)(p)).Bytes()
}

type BackupKeyID EntityID
type BackupKeyIDInternal__ EntityIDInternal__

func (b BackupKeyID) Export() *BackupKeyIDInternal__ {
	tmp := ((EntityID)(b))
	return ((*BackupKeyIDInternal__)(tmp.Export()))
}

func (b BackupKeyIDInternal__) Import() BackupKeyID {
	tmp := (EntityIDInternal__)(b)
	return BackupKeyID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (b *BackupKeyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BackupKeyID) Decode(dec rpc.Decoder) error {
	var tmp BackupKeyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b BackupKeyID) Bytes() []byte {
	return ((EntityID)(b)).Bytes()
}

type PassphraseKeyID EntityID
type PassphraseKeyIDInternal__ EntityIDInternal__

func (p PassphraseKeyID) Export() *PassphraseKeyIDInternal__ {
	tmp := ((EntityID)(p))
	return ((*PassphraseKeyIDInternal__)(tmp.Export()))
}

func (p PassphraseKeyIDInternal__) Import() PassphraseKeyID {
	tmp := (EntityIDInternal__)(p)
	return PassphraseKeyID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (p *PassphraseKeyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PassphraseKeyID) Decode(dec rpc.Decoder) error {
	var tmp PassphraseKeyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PassphraseKeyID) Bytes() []byte {
	return ((EntityID)(p)).Bytes()
}

type PKIXCertID EntityID
type PKIXCertIDInternal__ EntityIDInternal__

func (p PKIXCertID) Export() *PKIXCertIDInternal__ {
	tmp := ((EntityID)(p))
	return ((*PKIXCertIDInternal__)(tmp.Export()))
}

func (p PKIXCertIDInternal__) Import() PKIXCertID {
	tmp := (EntityIDInternal__)(p)
	return PKIXCertID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (p *PKIXCertID) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PKIXCertID) Decode(dec rpc.Decoder) error {
	var tmp PKIXCertIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PKIXCertID) Bytes() []byte {
	return ((EntityID)(p)).Bytes()
}

type HostID EntityID33
type HostIDInternal__ EntityID33Internal__

func (h HostID) Export() *HostIDInternal__ {
	tmp := ((EntityID33)(h))
	return ((*HostIDInternal__)(tmp.Export()))
}

func (h HostIDInternal__) Import() HostID {
	tmp := (EntityID33Internal__)(h)
	return HostID((func(x *EntityID33Internal__) (ret EntityID33) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (h *HostID) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostID) Decode(dec rpc.Decoder) error {
	var tmp HostIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

var HostIDTypeUniqueID = rpc.TypeUniqueID(0xa2f3bf71638e062d)

func (h *HostID) GetTypeUniqueID() rpc.TypeUniqueID {
	return HostIDTypeUniqueID
}

func (h HostID) Bytes() []byte {
	return ((EntityID33)(h)).Bytes()
}

type FixedEntityID EntityID34
type FixedEntityIDInternal__ EntityID34Internal__

func (f FixedEntityID) Export() *FixedEntityIDInternal__ {
	tmp := ((EntityID34)(f))
	return ((*FixedEntityIDInternal__)(tmp.Export()))
}

func (f FixedEntityIDInternal__) Import() FixedEntityID {
	tmp := (EntityID34Internal__)(f)
	return FixedEntityID((func(x *EntityID34Internal__) (ret EntityID34) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (f *FixedEntityID) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FixedEntityID) Decode(dec rpc.Decoder) error {
	var tmp FixedEntityIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f FixedEntityID) Bytes() []byte {
	return ((EntityID34)(f)).Bytes()
}

type PartyID EntityID
type PartyIDInternal__ EntityIDInternal__

func (p PartyID) Export() *PartyIDInternal__ {
	tmp := ((EntityID)(p))
	return ((*PartyIDInternal__)(tmp.Export()))
}

func (p PartyIDInternal__) Import() PartyID {
	tmp := (EntityIDInternal__)(p)
	return PartyID((func(x *EntityIDInternal__) (ret EntityID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (p *PartyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PartyID) Decode(dec rpc.Decoder) error {
	var tmp PartyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PartyID) Bytes() []byte {
	return ((EntityID)(p)).Bytes()
}

type FixedPartyID EntityID33
type FixedPartyIDInternal__ EntityID33Internal__

func (f FixedPartyID) Export() *FixedPartyIDInternal__ {
	tmp := ((EntityID33)(f))
	return ((*FixedPartyIDInternal__)(tmp.Export()))
}

func (f FixedPartyIDInternal__) Import() FixedPartyID {
	tmp := (EntityID33Internal__)(f)
	return FixedPartyID((func(x *EntityID33Internal__) (ret EntityID33) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (f *FixedPartyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FixedPartyID) Decode(dec rpc.Decoder) error {
	var tmp FixedPartyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f FixedPartyID) Bytes() []byte {
	return ((EntityID33)(f)).Bytes()
}

type EntityIDString string
type EntityIDStringInternal__ string

func (e EntityIDString) Export() *EntityIDStringInternal__ {
	tmp := ((string)(e))
	return ((*EntityIDStringInternal__)(&tmp))
}

func (e EntityIDStringInternal__) Import() EntityIDString {
	tmp := (string)(e)
	return EntityIDString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *EntityIDString) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *EntityIDString) Decode(dec rpc.Decoder) error {
	var tmp EntityIDStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e EntityIDString) Bytes() []byte {
	return nil
}

type EntityType int

const (
	EntityType_User               EntityType = 1
	EntityType_Host               EntityType = 2
	EntityType_Team               EntityType = 3
	EntityType_Device             EntityType = 4
	EntityType_X509Cert           EntityType = 5
	EntityType_LocationVRF        EntityType = 6
	EntityType_Service            EntityType = 7
	EntityType_Yubi               EntityType = 8
	EntityType_Name               EntityType = 9
	EntityType_HostMerkleSigner   EntityType = 10
	EntityType_HostTLSCA          EntityType = 11
	EntityType_HostMetadataSigner EntityType = 12
	EntityType_Subkey             EntityType = 13
	EntityType_PUKVerify          EntityType = 14
	EntityType_PTKVerify          EntityType = 15
	EntityType_BackupKey          EntityType = 16
	EntityType_PassphraseKey      EntityType = 17
	EntityType_PKIXCert           EntityType = 18
)

var EntityTypeMap = map[string]EntityType{
	"User":               1,
	"Host":               2,
	"Team":               3,
	"Device":             4,
	"X509Cert":           5,
	"LocationVRF":        6,
	"Service":            7,
	"Yubi":               8,
	"Name":               9,
	"HostMerkleSigner":   10,
	"HostTLSCA":          11,
	"HostMetadataSigner": 12,
	"Subkey":             13,
	"PUKVerify":          14,
	"PTKVerify":          15,
	"BackupKey":          16,
	"PassphraseKey":      17,
	"PKIXCert":           18,
}

var EntityTypeRevMap = map[EntityType]string{
	1:  "User",
	2:  "Host",
	3:  "Team",
	4:  "Device",
	5:  "X509Cert",
	6:  "LocationVRF",
	7:  "Service",
	8:  "Yubi",
	9:  "Name",
	10: "HostMerkleSigner",
	11: "HostTLSCA",
	12: "HostMetadataSigner",
	13: "Subkey",
	14: "PUKVerify",
	15: "PTKVerify",
	16: "BackupKey",
	17: "PassphraseKey",
	18: "PKIXCert",
}

type EntityTypeInternal__ EntityType

func (e EntityTypeInternal__) Import() EntityType {
	return EntityType(e)
}

func (e EntityType) Export() *EntityTypeInternal__ {
	return ((*EntityTypeInternal__)(&e))
}

type DHType int

const (
	DHType_Curve25519 DHType = 1
	DHType_P256       DHType = 2
)

var DHTypeMap = map[string]DHType{
	"Curve25519": 1,
	"P256":       2,
}

var DHTypeRevMap = map[DHType]string{
	1: "Curve25519",
	2: "P256",
}

type DHTypeInternal__ DHType

func (d DHTypeInternal__) Import() DHType {
	return DHType(d)
}

func (d DHType) Export() *DHTypeInternal__ {
	return ((*DHTypeInternal__)(&d))
}

type DHSharedKey []byte
type DHSharedKeyInternal__ []byte

func (d DHSharedKey) Export() *DHSharedKeyInternal__ {
	tmp := (([]byte)(d))
	return ((*DHSharedKeyInternal__)(&tmp))
}

func (d DHSharedKeyInternal__) Import() DHSharedKey {
	tmp := ([]byte)(d)
	return DHSharedKey((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DHSharedKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DHSharedKey) Decode(dec rpc.Decoder) error {
	var tmp DHSharedKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DHSharedKey) Bytes() []byte {
	return (d)[:]
}

type DHPublicKey struct {
	T     DHType
	F_0__ *Curve25519PublicKey      `json:"f0,omitempty"`
	F_1__ *ECDSACompressedPublicKey `json:"f1,omitempty"`
}

type DHPublicKeyInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        DHType
	Switch__ DHPublicKeyInternalSwitch__
}

type DHPublicKeyInternalSwitch__ struct {
	_struct struct{}                            `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *Curve25519PublicKeyInternal__      `codec:"0"`
	F_1__   *ECDSACompressedPublicKeyInternal__ `codec:"1"`
}

func (d DHPublicKey) GetT() (ret DHType, err error) {
	switch d.T {
	case DHType_Curve25519:
		if d.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case DHType_P256:
		if d.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return d.T, nil
}

func (d DHPublicKey) Curve25519() Curve25519PublicKey {
	if d.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if d.T != DHType_Curve25519 {
		panic(fmt.Sprintf("unexpected switch value (%v) when Curve25519 is called", d.T))
	}
	return *d.F_0__
}

func (d DHPublicKey) P256() ECDSACompressedPublicKey {
	if d.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if d.T != DHType_P256 {
		panic(fmt.Sprintf("unexpected switch value (%v) when P256 is called", d.T))
	}
	return *d.F_1__
}

func NewDHPublicKeyWithCurve25519(v Curve25519PublicKey) DHPublicKey {
	return DHPublicKey{
		T:     DHType_Curve25519,
		F_0__: &v,
	}
}

func NewDHPublicKeyWithP256(v ECDSACompressedPublicKey) DHPublicKey {
	return DHPublicKey{
		T:     DHType_P256,
		F_1__: &v,
	}
}

func (d DHPublicKeyInternal__) Import() DHPublicKey {
	return DHPublicKey{
		T: d.T,
		F_0__: (func(x *Curve25519PublicKeyInternal__) *Curve25519PublicKey {
			if x == nil {
				return nil
			}
			tmp := (func(x *Curve25519PublicKeyInternal__) (ret Curve25519PublicKey) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(d.Switch__.F_0__),
		F_1__: (func(x *ECDSACompressedPublicKeyInternal__) *ECDSACompressedPublicKey {
			if x == nil {
				return nil
			}
			tmp := (func(x *ECDSACompressedPublicKeyInternal__) (ret ECDSACompressedPublicKey) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(d.Switch__.F_1__),
	}
}

func (d DHPublicKey) Export() *DHPublicKeyInternal__ {
	return &DHPublicKeyInternal__{
		T: d.T,
		Switch__: DHPublicKeyInternalSwitch__{
			F_0__: (func(x *Curve25519PublicKey) *Curve25519PublicKeyInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(d.F_0__),
			F_1__: (func(x *ECDSACompressedPublicKey) *ECDSACompressedPublicKeyInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(d.F_1__),
		},
	}
}

func (d *DHPublicKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DHPublicKey) Decode(dec rpc.Decoder) error {
	var tmp DHPublicKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *DHPublicKey) Bytes() []byte { return nil }

type ID16 [17]byte
type ID16Internal__ [17]byte

func (i ID16) Export() *ID16Internal__ {
	tmp := (([17]byte)(i))
	return ((*ID16Internal__)(&tmp))
}

func (i ID16Internal__) Import() ID16 {
	tmp := ([17]byte)(i)
	return ID16((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (i *ID16) Encode(enc rpc.Encoder) error {
	return enc.Encode(i.Export())
}

func (i *ID16) Decode(dec rpc.Decoder) error {
	var tmp ID16Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*i = tmp.Import()
	return nil
}

func (i ID16) Bytes() []byte {
	return (i)[:]
}

type PlanID [17]byte
type PlanIDInternal__ [17]byte

func (p PlanID) Export() *PlanIDInternal__ {
	tmp := (([17]byte)(p))
	return ((*PlanIDInternal__)(&tmp))
}

func (p PlanIDInternal__) Import() PlanID {
	tmp := ([17]byte)(p)
	return PlanID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *PlanID) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PlanID) Decode(dec rpc.Decoder) error {
	var tmp PlanIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PlanID) Bytes() []byte {
	return (p)[:]
}

type PriceID [17]byte
type PriceIDInternal__ [17]byte

func (p PriceID) Export() *PriceIDInternal__ {
	tmp := (([17]byte)(p))
	return ((*PriceIDInternal__)(&tmp))
}

func (p PriceIDInternal__) Import() PriceID {
	tmp := ([17]byte)(p)
	return PriceID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *PriceID) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PriceID) Decode(dec rpc.Decoder) error {
	var tmp PriceIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PriceID) Bytes() []byte {
	return (p)[:]
}

type CancelID [17]byte
type CancelIDInternal__ [17]byte

func (c CancelID) Export() *CancelIDInternal__ {
	tmp := (([17]byte)(c))
	return ((*CancelIDInternal__)(&tmp))
}

func (c CancelIDInternal__) Import() CancelID {
	tmp := ([17]byte)(c)
	return CancelID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *CancelID) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CancelID) Decode(dec rpc.Decoder) error {
	var tmp CancelIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c CancelID) Bytes() []byte {
	return (c)[:]
}

type VHostID [17]byte
type VHostIDInternal__ [17]byte

func (v VHostID) Export() *VHostIDInternal__ {
	tmp := (([17]byte)(v))
	return ((*VHostIDInternal__)(&tmp))
}

func (v VHostIDInternal__) Import() VHostID {
	tmp := ([17]byte)(v)
	return VHostID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (v *VHostID) Encode(enc rpc.Encoder) error {
	return enc.Encode(v.Export())
}

func (v *VHostID) Decode(dec rpc.Decoder) error {
	var tmp VHostIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*v = tmp.Import()
	return nil
}

func (v VHostID) Bytes() []byte {
	return (v)[:]
}

type TeamRSVP [17]byte
type TeamRSVPInternal__ [17]byte

func (t TeamRSVP) Export() *TeamRSVPInternal__ {
	tmp := (([17]byte)(t))
	return ((*TeamRSVPInternal__)(&tmp))
}

func (t TeamRSVPInternal__) Import() TeamRSVP {
	tmp := ([17]byte)(t)
	return TeamRSVP((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamRSVP) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRSVP) Decode(dec rpc.Decoder) error {
	var tmp TeamRSVPInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TeamRSVP) Bytes() []byte {
	return (t)[:]
}

type TeamRSVPLocal [17]byte
type TeamRSVPLocalInternal__ [17]byte

func (t TeamRSVPLocal) Export() *TeamRSVPLocalInternal__ {
	tmp := (([17]byte)(t))
	return ((*TeamRSVPLocalInternal__)(&tmp))
}

func (t TeamRSVPLocalInternal__) Import() TeamRSVPLocal {
	tmp := ([17]byte)(t)
	return TeamRSVPLocal((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamRSVPLocal) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRSVPLocal) Decode(dec rpc.Decoder) error {
	var tmp TeamRSVPLocalInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TeamRSVPLocal) Bytes() []byte {
	return (t)[:]
}

type TeamRSVPRemote [17]byte
type TeamRSVPRemoteInternal__ [17]byte

func (t TeamRSVPRemote) Export() *TeamRSVPRemoteInternal__ {
	tmp := (([17]byte)(t))
	return ((*TeamRSVPRemoteInternal__)(&tmp))
}

func (t TeamRSVPRemoteInternal__) Import() TeamRSVPRemote {
	tmp := ([17]byte)(t)
	return TeamRSVPRemote((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamRSVPRemote) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRSVPRemote) Decode(dec rpc.Decoder) error {
	var tmp TeamRSVPRemoteInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TeamRSVPRemote) Bytes() []byte {
	return (t)[:]
}

type LocalInstanceID [17]byte
type LocalInstanceIDInternal__ [17]byte

func (l LocalInstanceID) Export() *LocalInstanceIDInternal__ {
	tmp := (([17]byte)(l))
	return ((*LocalInstanceIDInternal__)(&tmp))
}

func (l LocalInstanceIDInternal__) Import() LocalInstanceID {
	tmp := ([17]byte)(l)
	return LocalInstanceID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (l *LocalInstanceID) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LocalInstanceID) Decode(dec rpc.Decoder) error {
	var tmp LocalInstanceIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l LocalInstanceID) Bytes() []byte {
	return (l)[:]
}

type PermissionToken [17]byte
type PermissionTokenInternal__ [17]byte

func (p PermissionToken) Export() *PermissionTokenInternal__ {
	tmp := (([17]byte)(p))
	return ((*PermissionTokenInternal__)(&tmp))
}

func (p PermissionTokenInternal__) Import() PermissionToken {
	tmp := ([17]byte)(p)
	return PermissionToken((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *PermissionToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PermissionToken) Decode(dec rpc.Decoder) error {
	var tmp PermissionTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PermissionToken) Bytes() []byte {
	return (p)[:]
}

type ReservationToken [17]byte
type ReservationTokenInternal__ [17]byte

func (r ReservationToken) Export() *ReservationTokenInternal__ {
	tmp := (([17]byte)(r))
	return ((*ReservationTokenInternal__)(&tmp))
}

func (r ReservationTokenInternal__) Import() ReservationToken {
	tmp := ([17]byte)(r)
	return ReservationToken((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *ReservationToken) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *ReservationToken) Decode(dec rpc.Decoder) error {
	var tmp ReservationTokenInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r ReservationToken) Bytes() []byte {
	return (r)[:]
}

type AutocertID [17]byte
type AutocertIDInternal__ [17]byte

func (a AutocertID) Export() *AutocertIDInternal__ {
	tmp := (([17]byte)(a))
	return ((*AutocertIDInternal__)(&tmp))
}

func (a AutocertIDInternal__) Import() AutocertID {
	tmp := ([17]byte)(a)
	return AutocertID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (a *AutocertID) Encode(enc rpc.Encoder) error {
	return enc.Encode(a.Export())
}

func (a *AutocertID) Decode(dec rpc.Decoder) error {
	var tmp AutocertIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*a = tmp.Import()
	return nil
}

func (a AutocertID) Bytes() []byte {
	return (a)[:]
}

type OAuth2SessionID [17]byte
type OAuth2SessionIDInternal__ [17]byte

func (o OAuth2SessionID) Export() *OAuth2SessionIDInternal__ {
	tmp := (([17]byte)(o))
	return ((*OAuth2SessionIDInternal__)(&tmp))
}

func (o OAuth2SessionIDInternal__) Import() OAuth2SessionID {
	tmp := ([17]byte)(o)
	return OAuth2SessionID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2SessionID) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2SessionID) Decode(dec rpc.Decoder) error {
	var tmp OAuth2SessionIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2SessionID) Bytes() []byte {
	return (o)[:]
}

type SSOConfigID [17]byte
type SSOConfigIDInternal__ [17]byte

func (s SSOConfigID) Export() *SSOConfigIDInternal__ {
	tmp := (([17]byte)(s))
	return ((*SSOConfigIDInternal__)(&tmp))
}

func (s SSOConfigIDInternal__) Import() SSOConfigID {
	tmp := ([17]byte)(s)
	return SSOConfigID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SSOConfigID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SSOConfigID) Decode(dec rpc.Decoder) error {
	var tmp SSOConfigIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SSOConfigID) Bytes() []byte {
	return (s)[:]
}

type CKSKeyID [17]byte
type CKSKeyIDInternal__ [17]byte

func (c CKSKeyID) Export() *CKSKeyIDInternal__ {
	tmp := (([17]byte)(c))
	return ((*CKSKeyIDInternal__)(&tmp))
}

func (c CKSKeyIDInternal__) Import() CKSKeyID {
	tmp := ([17]byte)(c)
	return CKSKeyID((func(x *[17]byte) (ret [17]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *CKSKeyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CKSKeyID) Decode(dec rpc.Decoder) error {
	var tmp CKSKeyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c CKSKeyID) Bytes() []byte {
	return (c)[:]
}

type ID16Type int

const (
	ID16Type_Plan             ID16Type = 61
	ID16Type_Cancel           ID16Type = 60
	ID16Type_Price            ID16Type = 59
	ID16Type_VHost            ID16Type = 58
	ID16Type_TeamRSVPLocal    ID16Type = 57
	ID16Type_TeamRSVPRemote   ID16Type = 56
	ID16Type_LocalInstance    ID16Type = 55
	ID16Type_PermissionToken  ID16Type = 54
	ID16Type_ReservationToken ID16Type = 53
	ID16Type_Autocert         ID16Type = 52
	ID16Type_OAuth2Session    ID16Type = 51
	ID16Type_SSOConfig        ID16Type = 50
	ID16Type_CKSKey           ID16Type = 49
	ID16Type_MaxEntityType    ID16Type = 48
)

var ID16TypeMap = map[string]ID16Type{
	"Plan":             61,
	"Cancel":           60,
	"Price":            59,
	"VHost":            58,
	"TeamRSVPLocal":    57,
	"TeamRSVPRemote":   56,
	"LocalInstance":    55,
	"PermissionToken":  54,
	"ReservationToken": 53,
	"Autocert":         52,
	"OAuth2Session":    51,
	"SSOConfig":        50,
	"CKSKey":           49,
	"MaxEntityType":    48,
}

var ID16TypeRevMap = map[ID16Type]string{
	61: "Plan",
	60: "Cancel",
	59: "Price",
	58: "VHost",
	57: "TeamRSVPLocal",
	56: "TeamRSVPRemote",
	55: "LocalInstance",
	54: "PermissionToken",
	53: "ReservationToken",
	52: "Autocert",
	51: "OAuth2Session",
	50: "SSOConfig",
	49: "CKSKey",
	48: "MaxEntityType",
}

type ID16TypeInternal__ ID16Type

func (i ID16TypeInternal__) Import() ID16Type {
	return ID16Type(i)
}

func (i ID16Type) Export() *ID16TypeInternal__ {
	return ((*ID16TypeInternal__)(&i))
}

type ID16String string
type ID16StringInternal__ string

func (i ID16String) Export() *ID16StringInternal__ {
	tmp := ((string)(i))
	return ((*ID16StringInternal__)(&tmp))
}

func (i ID16StringInternal__) Import() ID16String {
	tmp := (string)(i)
	return ID16String((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (i *ID16String) Encode(enc rpc.Encoder) error {
	return enc.Encode(i.Export())
}

func (i *ID16String) Decode(dec rpc.Decoder) error {
	var tmp ID16StringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*i = tmp.Import()
	return nil
}

func (i ID16String) Bytes() []byte {
	return nil
}

type TeamRSVPString string
type TeamRSVPStringInternal__ string

func (t TeamRSVPString) Export() *TeamRSVPStringInternal__ {
	tmp := ((string)(t))
	return ((*TeamRSVPStringInternal__)(&tmp))
}

func (t TeamRSVPStringInternal__) Import() TeamRSVPString {
	tmp := (string)(t)
	return TeamRSVPString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamRSVPString) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamRSVPString) Decode(dec rpc.Decoder) error {
	var tmp TeamRSVPStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TeamRSVPString) Bytes() []byte {
	return nil
}

type OAuth2SessionIDString string
type OAuth2SessionIDStringInternal__ string

func (o OAuth2SessionIDString) Export() *OAuth2SessionIDStringInternal__ {
	tmp := ((string)(o))
	return ((*OAuth2SessionIDStringInternal__)(&tmp))
}

func (o OAuth2SessionIDStringInternal__) Import() OAuth2SessionIDString {
	tmp := (string)(o)
	return OAuth2SessionIDString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (o *OAuth2SessionIDString) Encode(enc rpc.Encoder) error {
	return enc.Encode(o.Export())
}

func (o *OAuth2SessionIDString) Decode(dec rpc.Decoder) error {
	var tmp OAuth2SessionIDStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*o = tmp.Import()
	return nil
}

func (o OAuth2SessionIDString) Bytes() []byte {
	return nil
}

type Time uint64
type TimeInternal__ uint64

func (t Time) Export() *TimeInternal__ {
	tmp := ((uint64)(t))
	return ((*TimeInternal__)(&tmp))
}

func (t TimeInternal__) Import() Time {
	tmp := (uint64)(t)
	return Time((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *Time) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *Time) Decode(dec rpc.Decoder) error {
	var tmp TimeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t Time) Bytes() []byte {
	return nil
}

type TimeMicro uint64
type TimeMicroInternal__ uint64

func (t TimeMicro) Export() *TimeMicroInternal__ {
	tmp := ((uint64)(t))
	return ((*TimeMicroInternal__)(&tmp))
}

func (t TimeMicroInternal__) Import() TimeMicro {
	tmp := (uint64)(t)
	return TimeMicro((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TimeMicro) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TimeMicro) Decode(dec rpc.Decoder) error {
	var tmp TimeMicroInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TimeMicro) Bytes() []byte {
	return nil
}

type DurationSecs int64
type DurationSecsInternal__ int64

func (d DurationSecs) Export() *DurationSecsInternal__ {
	tmp := ((int64)(d))
	return ((*DurationSecsInternal__)(&tmp))
}

func (d DurationSecsInternal__) Import() DurationSecs {
	tmp := (int64)(d)
	return DurationSecs((func(x *int64) (ret int64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DurationSecs) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DurationSecs) Decode(dec rpc.Decoder) error {
	var tmp DurationSecsInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DurationSecs) Bytes() []byte {
	return nil
}

type DurationMilli uint64
type DurationMilliInternal__ uint64

func (d DurationMilli) Export() *DurationMilliInternal__ {
	tmp := ((uint64)(d))
	return ((*DurationMilliInternal__)(&tmp))
}

func (d DurationMilliInternal__) Import() DurationMilli {
	tmp := (uint64)(d)
	return DurationMilli((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DurationMilli) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DurationMilli) Decode(dec rpc.Decoder) error {
	var tmp DurationMilliInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DurationMilli) Bytes() []byte {
	return nil
}

type FQUser struct {
	Uid    UID
	HostID HostID
}

type FQUserInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Uid     *UIDInternal__
	HostID  *HostIDInternal__
}

func (f FQUserInternal__) Import() FQUser {
	return FQUser{
		Uid: (func(x *UIDInternal__) (ret UID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Uid),
		HostID: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.HostID),
	}
}

func (f FQUser) Export() *FQUserInternal__ {
	return &FQUserInternal__{
		Uid:    f.Uid.Export(),
		HostID: f.HostID.Export(),
	}
}

func (f *FQUser) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQUser) Decode(dec rpc.Decoder) error {
	var tmp FQUserInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

var FQUserTypeUniqueID = rpc.TypeUniqueID(0x98c90258bf748a2f)

func (f *FQUser) GetTypeUniqueID() rpc.TypeUniqueID {
	return FQUserTypeUniqueID
}

func (f *FQUser) Bytes() []byte { return nil }

type FQUserAndRole struct {
	Fqu  FQUser
	Role Role
}

type FQUserAndRoleInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu     *FQUserInternal__
	Role    *RoleInternal__
}

func (f FQUserAndRoleInternal__) Import() FQUserAndRole {
	return FQUserAndRole{
		Fqu: (func(x *FQUserInternal__) (ret FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Fqu),
		Role: (func(x *RoleInternal__) (ret Role) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Role),
	}
}

func (f FQUserAndRole) Export() *FQUserAndRoleInternal__ {
	return &FQUserAndRoleInternal__{
		Fqu:  f.Fqu.Export(),
		Role: f.Role.Export(),
	}
}

func (f *FQUserAndRole) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQUserAndRole) Decode(dec rpc.Decoder) error {
	var tmp FQUserAndRoleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

var FQUserAndRoleTypeUniqueID = rpc.TypeUniqueID(0xe411cca2d702d96b)

func (f *FQUserAndRole) GetTypeUniqueID() rpc.TypeUniqueID {
	return FQUserAndRoleTypeUniqueID
}

func (f *FQUserAndRole) Bytes() []byte { return nil }

type FQUserAndRoleString string
type FQUserAndRoleStringInternal__ string

func (f FQUserAndRoleString) Export() *FQUserAndRoleStringInternal__ {
	tmp := ((string)(f))
	return ((*FQUserAndRoleStringInternal__)(&tmp))
}

func (f FQUserAndRoleStringInternal__) Import() FQUserAndRoleString {
	tmp := (string)(f)
	return FQUserAndRoleString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (f *FQUserAndRoleString) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQUserAndRoleString) Decode(dec rpc.Decoder) error {
	var tmp FQUserAndRoleStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f FQUserAndRoleString) Bytes() []byte {
	return nil
}

type SubjectKeyID struct {
	Fqu     FQUser
	KeyType EntityType
}

type SubjectKeyIDInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqu     *FQUserInternal__
	KeyType *EntityTypeInternal__
}

func (s SubjectKeyIDInternal__) Import() SubjectKeyID {
	return SubjectKeyID{
		Fqu: (func(x *FQUserInternal__) (ret FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Fqu),
		KeyType: (func(x *EntityTypeInternal__) (ret EntityType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.KeyType),
	}
}

func (s SubjectKeyID) Export() *SubjectKeyIDInternal__ {
	return &SubjectKeyIDInternal__{
		Fqu:     s.Fqu.Export(),
		KeyType: s.KeyType.Export(),
	}
}

func (s *SubjectKeyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SubjectKeyID) Decode(dec rpc.Decoder) error {
	var tmp SubjectKeyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SubjectKeyID) Bytes() []byte { return nil }

type Ed25519PublicKey [32]byte
type Ed25519PublicKeyInternal__ [32]byte

func (e Ed25519PublicKey) Export() *Ed25519PublicKeyInternal__ {
	tmp := (([32]byte)(e))
	return ((*Ed25519PublicKeyInternal__)(&tmp))
}

func (e Ed25519PublicKeyInternal__) Import() Ed25519PublicKey {
	tmp := ([32]byte)(e)
	return Ed25519PublicKey((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *Ed25519PublicKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *Ed25519PublicKey) Decode(dec rpc.Decoder) error {
	var tmp Ed25519PublicKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e Ed25519PublicKey) Bytes() []byte {
	return (e)[:]
}

type Ed25519Signature [64]byte
type Ed25519SignatureInternal__ [64]byte

func (e Ed25519Signature) Export() *Ed25519SignatureInternal__ {
	tmp := (([64]byte)(e))
	return ((*Ed25519SignatureInternal__)(&tmp))
}

func (e Ed25519SignatureInternal__) Import() Ed25519Signature {
	tmp := ([64]byte)(e)
	return Ed25519Signature((func(x *[64]byte) (ret [64]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *Ed25519Signature) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *Ed25519Signature) Decode(dec rpc.Decoder) error {
	var tmp Ed25519SignatureInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e Ed25519Signature) Bytes() []byte {
	return (e)[:]
}

type Curve25519PublicKey [32]byte
type Curve25519PublicKeyInternal__ [32]byte

func (c Curve25519PublicKey) Export() *Curve25519PublicKeyInternal__ {
	tmp := (([32]byte)(c))
	return ((*Curve25519PublicKeyInternal__)(&tmp))
}

func (c Curve25519PublicKeyInternal__) Import() Curve25519PublicKey {
	tmp := ([32]byte)(c)
	return Curve25519PublicKey((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *Curve25519PublicKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *Curve25519PublicKey) Decode(dec rpc.Decoder) error {
	var tmp Curve25519PublicKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c Curve25519PublicKey) Bytes() []byte {
	return (c)[:]
}

type ECDSACompressedPublicKey []byte
type ECDSACompressedPublicKeyInternal__ []byte

func (e ECDSACompressedPublicKey) Export() *ECDSACompressedPublicKeyInternal__ {
	tmp := (([]byte)(e))
	return ((*ECDSACompressedPublicKeyInternal__)(&tmp))
}

func (e ECDSACompressedPublicKeyInternal__) Import() ECDSACompressedPublicKey {
	tmp := ([]byte)(e)
	return ECDSACompressedPublicKey((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *ECDSACompressedPublicKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *ECDSACompressedPublicKey) Decode(dec rpc.Decoder) error {
	var tmp ECDSACompressedPublicKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

var ECDSACompressedPublicKeyTypeUniqueID = rpc.TypeUniqueID(0xf3bcedcbd7b6754e)

func (e *ECDSACompressedPublicKey) GetTypeUniqueID() rpc.TypeUniqueID {
	return ECDSACompressedPublicKeyTypeUniqueID
}

func (e ECDSACompressedPublicKey) Bytes() []byte {
	return (e)[:]
}

type Ed25519SecretKey [32]byte
type Ed25519SecretKeyInternal__ [32]byte

func (e Ed25519SecretKey) Export() *Ed25519SecretKeyInternal__ {
	tmp := (([32]byte)(e))
	return ((*Ed25519SecretKeyInternal__)(&tmp))
}

func (e Ed25519SecretKeyInternal__) Import() Ed25519SecretKey {
	tmp := ([32]byte)(e)
	return Ed25519SecretKey((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *Ed25519SecretKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *Ed25519SecretKey) Decode(dec rpc.Decoder) error {
	var tmp Ed25519SecretKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e Ed25519SecretKey) Bytes() []byte {
	return (e)[:]
}

type SecretBoxKey [32]byte
type SecretBoxKeyInternal__ [32]byte

func (s SecretBoxKey) Export() *SecretBoxKeyInternal__ {
	tmp := (([32]byte)(s))
	return ((*SecretBoxKeyInternal__)(&tmp))
}

func (s SecretBoxKeyInternal__) Import() SecretBoxKey {
	tmp := ([32]byte)(s)
	return SecretBoxKey((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SecretBoxKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretBoxKey) Decode(dec rpc.Decoder) error {
	var tmp SecretBoxKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SecretBoxKey) Bytes() []byte {
	return (s)[:]
}

type Curve25519SecretKey [32]byte
type Curve25519SecretKeyInternal__ [32]byte

func (c Curve25519SecretKey) Export() *Curve25519SecretKeyInternal__ {
	tmp := (([32]byte)(c))
	return ((*Curve25519SecretKeyInternal__)(&tmp))
}

func (c Curve25519SecretKeyInternal__) Import() Curve25519SecretKey {
	tmp := ([32]byte)(c)
	return Curve25519SecretKey((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *Curve25519SecretKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *Curve25519SecretKey) Decode(dec rpc.Decoder) error {
	var tmp Curve25519SecretKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c Curve25519SecretKey) Bytes() []byte {
	return (c)[:]
}

type ECDSASignature []byte
type ECDSASignatureInternal__ []byte

func (e ECDSASignature) Export() *ECDSASignatureInternal__ {
	tmp := (([]byte)(e))
	return ((*ECDSASignatureInternal__)(&tmp))
}

func (e ECDSASignatureInternal__) Import() ECDSASignature {
	tmp := ([]byte)(e)
	return ECDSASignature((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (e *ECDSASignature) Encode(enc rpc.Encoder) error {
	return enc.Encode(e.Export())
}

func (e *ECDSASignature) Decode(dec rpc.Decoder) error {
	var tmp ECDSASignatureInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*e = tmp.Import()
	return nil
}

func (e ECDSASignature) Bytes() []byte {
	return (e)[:]
}

type HMACKey [32]byte
type HMACKeyInternal__ [32]byte

func (h HMACKey) Export() *HMACKeyInternal__ {
	tmp := (([32]byte)(h))
	return ((*HMACKeyInternal__)(&tmp))
}

func (h HMACKeyInternal__) Import() HMACKey {
	tmp := ([32]byte)(h)
	return HMACKey((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (h *HMACKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HMACKey) Decode(dec rpc.Decoder) error {
	var tmp HMACKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h HMACKey) Bytes() []byte {
	return (h)[:]
}

type TreeLocation [32]byte
type TreeLocationInternal__ [32]byte

func (t TreeLocation) Export() *TreeLocationInternal__ {
	tmp := (([32]byte)(t))
	return ((*TreeLocationInternal__)(&tmp))
}

func (t TreeLocationInternal__) Import() TreeLocation {
	tmp := ([32]byte)(t)
	return TreeLocation((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TreeLocation) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TreeLocation) Decode(dec rpc.Decoder) error {
	var tmp TreeLocationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TreeLocationTypeUniqueID = rpc.TypeUniqueID(0xaeffd88b6cd267d9)

func (t *TreeLocation) GetTypeUniqueID() rpc.TypeUniqueID {
	return TreeLocationTypeUniqueID
}

func (t TreeLocation) Bytes() []byte {
	return (t)[:]
}

type TreeLocationCommitment StdHash
type TreeLocationCommitmentInternal__ StdHashInternal__

func (t TreeLocationCommitment) Export() *TreeLocationCommitmentInternal__ {
	tmp := ((StdHash)(t))
	return ((*TreeLocationCommitmentInternal__)(tmp.Export()))
}

func (t TreeLocationCommitmentInternal__) Import() TreeLocationCommitment {
	tmp := (StdHashInternal__)(t)
	return TreeLocationCommitment((func(x *StdHashInternal__) (ret StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (t *TreeLocationCommitment) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TreeLocationCommitment) Decode(dec rpc.Decoder) error {
	var tmp TreeLocationCommitmentInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TreeLocationCommitmentTypeUniqueID = rpc.TypeUniqueID(0xfbb95b5b0b49d6e3)

func (t *TreeLocationCommitment) GetTypeUniqueID() rpc.TypeUniqueID {
	return TreeLocationCommitmentTypeUniqueID
}

func (t TreeLocationCommitment) Bytes() []byte {
	return ((StdHash)(t)).Bytes()
}

type LinkHash StdHash
type LinkHashInternal__ StdHashInternal__

func (l LinkHash) Export() *LinkHashInternal__ {
	tmp := ((StdHash)(l))
	return ((*LinkHashInternal__)(tmp.Export()))
}

func (l LinkHashInternal__) Import() LinkHash {
	tmp := (StdHashInternal__)(l)
	return LinkHash((func(x *StdHashInternal__) (ret StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (l *LinkHash) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LinkHash) Decode(dec rpc.Decoder) error {
	var tmp LinkHashInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l LinkHash) Bytes() []byte {
	return ((StdHash)(l)).Bytes()
}

type Passphrase string
type PassphraseInternal__ string

func (p Passphrase) Export() *PassphraseInternal__ {
	tmp := ((string)(p))
	return ((*PassphraseInternal__)(&tmp))
}

func (p PassphraseInternal__) Import() Passphrase {
	tmp := (string)(p)
	return Passphrase((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *Passphrase) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *Passphrase) Decode(dec rpc.Decoder) error {
	var tmp PassphraseInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p Passphrase) Bytes() []byte {
	return nil
}

type KemSharedKey []byte
type KemSharedKeyInternal__ []byte

func (k KemSharedKey) Export() *KemSharedKeyInternal__ {
	tmp := (([]byte)(k))
	return ((*KemSharedKeyInternal__)(&tmp))
}

func (k KemSharedKeyInternal__) Import() KemSharedKey {
	tmp := ([]byte)(k)
	return KemSharedKey((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KemSharedKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KemSharedKey) Decode(dec rpc.Decoder) error {
	var tmp KemSharedKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KemSharedKey) Bytes() []byte {
	return (k)[:]
}

type KemDecapKey []byte
type KemDecapKeyInternal__ []byte

func (k KemDecapKey) Export() *KemDecapKeyInternal__ {
	tmp := (([]byte)(k))
	return ((*KemDecapKeyInternal__)(&tmp))
}

func (k KemDecapKeyInternal__) Import() KemDecapKey {
	tmp := ([]byte)(k)
	return KemDecapKey((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KemDecapKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KemDecapKey) Decode(dec rpc.Decoder) error {
	var tmp KemDecapKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KemDecapKey) Bytes() []byte {
	return (k)[:]
}

type KemCiphertext []byte
type KemCiphertextInternal__ []byte

func (k KemCiphertext) Export() *KemCiphertextInternal__ {
	tmp := (([]byte)(k))
	return ((*KemCiphertextInternal__)(&tmp))
}

func (k KemCiphertextInternal__) Import() KemCiphertext {
	tmp := ([]byte)(k)
	return KemCiphertext((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KemCiphertext) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KemCiphertext) Decode(dec rpc.Decoder) error {
	var tmp KemCiphertextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KemCiphertext) Bytes() []byte {
	return (k)[:]
}

type KemSeed []byte
type KemSeedInternal__ []byte

func (k KemSeed) Export() *KemSeedInternal__ {
	tmp := (([]byte)(k))
	return ((*KemSeedInternal__)(&tmp))
}

func (k KemSeedInternal__) Import() KemSeed {
	tmp := ([]byte)(k)
	return KemSeed((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (k *KemSeed) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KemSeed) Decode(dec rpc.Decoder) error {
	var tmp KemSeedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k KemSeed) Bytes() []byte {
	return (k)[:]
}

type MlkemSeed [64]byte
type MlkemSeedInternal__ [64]byte

func (m MlkemSeed) Export() *MlkemSeedInternal__ {
	tmp := (([64]byte)(m))
	return ((*MlkemSeedInternal__)(&tmp))
}

func (m MlkemSeedInternal__) Import() MlkemSeed {
	tmp := ([64]byte)(m)
	return MlkemSeed((func(x *[64]byte) (ret [64]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (m *MlkemSeed) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MlkemSeed) Decode(dec rpc.Decoder) error {
	var tmp MlkemSeedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m MlkemSeed) Bytes() []byte {
	return (m)[:]
}

type KEMType int

const (
	KEMType_None     KEMType = 0
	KEMType_Mlkem768 KEMType = 1
)

var KEMTypeMap = map[string]KEMType{
	"None":     0,
	"Mlkem768": 1,
}

var KEMTypeRevMap = map[KEMType]string{
	0: "None",
	1: "Mlkem768",
}

type KEMTypeInternal__ KEMType

func (k KEMTypeInternal__) Import() KEMType {
	return KEMType(k)
}

func (k KEMType) Export() *KEMTypeInternal__ {
	return ((*KEMTypeInternal__)(&k))
}

type KemEncapKey struct {
	T     KEMType
	F_1__ *[]byte `json:"f1,omitempty"`
}

type KemEncapKeyInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        KEMType
	Switch__ KemEncapKeyInternalSwitch__
}

type KemEncapKeyInternalSwitch__ struct {
	_struct struct{} `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *[]byte  `codec:"1"`
}

func (k KemEncapKey) GetT() (ret KEMType, err error) {
	switch k.T {
	case KEMType_Mlkem768:
		if k.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return k.T, nil
}

func (k KemEncapKey) Mlkem768() []byte {
	if k.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if k.T != KEMType_Mlkem768 {
		panic(fmt.Sprintf("unexpected switch value (%v) when Mlkem768 is called", k.T))
	}
	return *k.F_1__
}

func NewKemEncapKeyWithMlkem768(v []byte) KemEncapKey {
	return KemEncapKey{
		T:     KEMType_Mlkem768,
		F_1__: &v,
	}
}

func (k KemEncapKeyInternal__) Import() KemEncapKey {
	return KemEncapKey{
		T:     k.T,
		F_1__: k.Switch__.F_1__,
	}
}

func (k KemEncapKey) Export() *KemEncapKeyInternal__ {
	return &KemEncapKeyInternal__{
		T: k.T,
		Switch__: KemEncapKeyInternalSwitch__{
			F_1__: k.F_1__,
		},
	}
}

func (k *KemEncapKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KemEncapKey) Decode(dec rpc.Decoder) error {
	var tmp KemEncapKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KemEncapKey) Bytes() []byte { return nil }

type StdHash [32]byte
type StdHashInternal__ [32]byte

func (s StdHash) Export() *StdHashInternal__ {
	tmp := (([32]byte)(s))
	return ((*StdHashInternal__)(&tmp))
}

func (s StdHashInternal__) Import() StdHash {
	tmp := ([32]byte)(s)
	return StdHash((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *StdHash) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StdHash) Decode(dec rpc.Decoder) error {
	var tmp StdHashInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s StdHash) Bytes() []byte {
	return (s)[:]
}

type RandomCommitmentKey [16]byte
type RandomCommitmentKeyInternal__ [16]byte

func (r RandomCommitmentKey) Export() *RandomCommitmentKeyInternal__ {
	tmp := (([16]byte)(r))
	return ((*RandomCommitmentKeyInternal__)(&tmp))
}

func (r RandomCommitmentKeyInternal__) Import() RandomCommitmentKey {
	tmp := ([16]byte)(r)
	return RandomCommitmentKey((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RandomCommitmentKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RandomCommitmentKey) Decode(dec rpc.Decoder) error {
	var tmp RandomCommitmentKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RandomCommitmentKey) Bytes() []byte {
	return (r)[:]
}

type HMAC [32]byte
type HMACInternal__ [32]byte

func (h HMAC) Export() *HMACInternal__ {
	tmp := (([32]byte)(h))
	return ((*HMACInternal__)(&tmp))
}

func (h HMACInternal__) Import() HMAC {
	tmp := ([32]byte)(h)
	return HMAC((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (h *HMAC) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HMAC) Decode(dec rpc.Decoder) error {
	var tmp HMACInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h HMAC) Bytes() []byte {
	return (h)[:]
}

type NaclCiphertext []byte
type NaclCiphertextInternal__ []byte

func (n NaclCiphertext) Export() *NaclCiphertextInternal__ {
	tmp := (([]byte)(n))
	return ((*NaclCiphertextInternal__)(&tmp))
}

func (n NaclCiphertextInternal__) Import() NaclCiphertext {
	tmp := ([]byte)(n)
	return NaclCiphertext((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (n *NaclCiphertext) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NaclCiphertext) Decode(dec rpc.Decoder) error {
	var tmp NaclCiphertextInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n NaclCiphertext) Bytes() []byte {
	return (n)[:]
}

type NaclNonce [16]byte
type NaclNonceInternal__ [16]byte

func (n NaclNonce) Export() *NaclNonceInternal__ {
	tmp := (([16]byte)(n))
	return ((*NaclNonceInternal__)(&tmp))
}

func (n NaclNonceInternal__) Import() NaclNonce {
	tmp := ([16]byte)(n)
	return NaclNonce((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (n *NaclNonce) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NaclNonce) Decode(dec rpc.Decoder) error {
	var tmp NaclNonceInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n NaclNonce) Bytes() []byte {
	return (n)[:]
}

type BoxType int

const (
	BoxType_NACL   BoxType = 0
	BoxType_YUBI   BoxType = 1
	BoxType_HYBRID BoxType = 2
)

var BoxTypeMap = map[string]BoxType{
	"NACL":   0,
	"YUBI":   1,
	"HYBRID": 2,
}

var BoxTypeRevMap = map[BoxType]string{
	0: "NACL",
	1: "YUBI",
	2: "HYBRID",
}

type BoxTypeInternal__ BoxType

func (b BoxTypeInternal__) Import() BoxType {
	return BoxType(b)
}

func (b BoxType) Export() *BoxTypeInternal__ {
	return ((*BoxTypeInternal__)(&b))
}

type NaclSecretBox struct {
	Nonce      NaclNonce
	Ciphertext NaclCiphertext
}

type NaclSecretBoxInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Nonce      *NaclNonceInternal__
	Ciphertext *NaclCiphertextInternal__
}

func (n NaclSecretBoxInternal__) Import() NaclSecretBox {
	return NaclSecretBox{
		Nonce: (func(x *NaclNonceInternal__) (ret NaclNonce) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Nonce),
		Ciphertext: (func(x *NaclCiphertextInternal__) (ret NaclCiphertext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Ciphertext),
	}
}

func (n NaclSecretBox) Export() *NaclSecretBoxInternal__ {
	return &NaclSecretBoxInternal__{
		Nonce:      n.Nonce.Export(),
		Ciphertext: n.Ciphertext.Export(),
	}
}

func (n *NaclSecretBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NaclSecretBox) Decode(dec rpc.Decoder) error {
	var tmp NaclSecretBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NaclSecretBox) Bytes() []byte { return nil }

type SecretBox struct {
	T     BoxType
	F_0__ *NaclSecretBox `json:"f0,omitempty"`
}

type SecretBoxInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        BoxType
	Switch__ SecretBoxInternalSwitch__
}

type SecretBoxInternalSwitch__ struct {
	_struct struct{}                 `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *NaclSecretBoxInternal__ `codec:"0"`
}

func (s SecretBox) GetT() (ret BoxType, err error) {
	switch s.T {
	case BoxType_NACL:
		if s.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	}
	return s.T, nil
}

func (s SecretBox) Nacl() NaclSecretBox {
	if s.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.T != BoxType_NACL {
		panic(fmt.Sprintf("unexpected switch value (%v) when Nacl is called", s.T))
	}
	return *s.F_0__
}

func NewSecretBoxWithNacl(v NaclSecretBox) SecretBox {
	return SecretBox{
		T:     BoxType_NACL,
		F_0__: &v,
	}
}

func (s SecretBoxInternal__) Import() SecretBox {
	return SecretBox{
		T: s.T,
		F_0__: (func(x *NaclSecretBoxInternal__) *NaclSecretBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *NaclSecretBoxInternal__) (ret NaclSecretBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_0__),
	}
}

func (s SecretBox) Export() *SecretBoxInternal__ {
	return &SecretBoxInternal__{
		T: s.T,
		Switch__: SecretBoxInternalSwitch__{
			F_0__: (func(x *NaclSecretBox) *NaclSecretBoxInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_0__),
		},
	}
}

func (s *SecretBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretBox) Decode(dec rpc.Decoder) error {
	var tmp SecretBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SecretBox) Bytes() []byte { return nil }

type NaclBox struct {
	Pk         *Curve25519PublicKey
	Nonce      *NaclNonce
	Ciphertext NaclCiphertext
}

type NaclBoxInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Pk         *Curve25519PublicKeyInternal__
	Nonce      *NaclNonceInternal__
	Ciphertext *NaclCiphertextInternal__
}

func (n NaclBoxInternal__) Import() NaclBox {
	return NaclBox{
		Pk: (func(x *Curve25519PublicKeyInternal__) *Curve25519PublicKey {
			if x == nil {
				return nil
			}
			tmp := (func(x *Curve25519PublicKeyInternal__) (ret Curve25519PublicKey) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(n.Pk),
		Nonce: (func(x *NaclNonceInternal__) *NaclNonce {
			if x == nil {
				return nil
			}
			tmp := (func(x *NaclNonceInternal__) (ret NaclNonce) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(n.Nonce),
		Ciphertext: (func(x *NaclCiphertextInternal__) (ret NaclCiphertext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Ciphertext),
	}
}

func (n NaclBox) Export() *NaclBoxInternal__ {
	return &NaclBoxInternal__{
		Pk: (func(x *Curve25519PublicKey) *Curve25519PublicKeyInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(n.Pk),
		Nonce: (func(x *NaclNonce) *NaclNonceInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(n.Nonce),
		Ciphertext: n.Ciphertext.Export(),
	}
}

func (n *NaclBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NaclBox) Decode(dec rpc.Decoder) error {
	var tmp NaclBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NaclBox) Bytes() []byte { return nil }

type Box struct {
	T     BoxType
	F_0__ *NaclBox   `json:"f0,omitempty"`
	F_1__ *YubiBox   `json:"f1,omitempty"`
	F_2__ *BoxHybrid `json:"f2,omitempty"`
}

type BoxInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        BoxType
	Switch__ BoxInternalSwitch__
}

type BoxInternalSwitch__ struct {
	_struct struct{}             `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *NaclBoxInternal__   `codec:"0"`
	F_1__   *YubiBoxInternal__   `codec:"1"`
	F_2__   *BoxHybridInternal__ `codec:"2"`
}

func (b Box) GetT() (ret BoxType, err error) {
	switch b.T {
	case BoxType_NACL:
		if b.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case BoxType_YUBI:
		if b.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case BoxType_HYBRID:
		if b.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	}
	return b.T, nil
}

func (b Box) Nacl() NaclBox {
	if b.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if b.T != BoxType_NACL {
		panic(fmt.Sprintf("unexpected switch value (%v) when Nacl is called", b.T))
	}
	return *b.F_0__
}

func (b Box) Yubi() YubiBox {
	if b.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if b.T != BoxType_YUBI {
		panic(fmt.Sprintf("unexpected switch value (%v) when Yubi is called", b.T))
	}
	return *b.F_1__
}

func (b Box) Hybrid() BoxHybrid {
	if b.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if b.T != BoxType_HYBRID {
		panic(fmt.Sprintf("unexpected switch value (%v) when Hybrid is called", b.T))
	}
	return *b.F_2__
}

func NewBoxWithNacl(v NaclBox) Box {
	return Box{
		T:     BoxType_NACL,
		F_0__: &v,
	}
}

func NewBoxWithYubi(v YubiBox) Box {
	return Box{
		T:     BoxType_YUBI,
		F_1__: &v,
	}
}

func NewBoxWithHybrid(v BoxHybrid) Box {
	return Box{
		T:     BoxType_HYBRID,
		F_2__: &v,
	}
}

func (b BoxInternal__) Import() Box {
	return Box{
		T: b.T,
		F_0__: (func(x *NaclBoxInternal__) *NaclBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *NaclBoxInternal__) (ret NaclBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(b.Switch__.F_0__),
		F_1__: (func(x *YubiBoxInternal__) *YubiBox {
			if x == nil {
				return nil
			}
			tmp := (func(x *YubiBoxInternal__) (ret YubiBox) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(b.Switch__.F_1__),
		F_2__: (func(x *BoxHybridInternal__) *BoxHybrid {
			if x == nil {
				return nil
			}
			tmp := (func(x *BoxHybridInternal__) (ret BoxHybrid) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(b.Switch__.F_2__),
	}
}

func (b Box) Export() *BoxInternal__ {
	return &BoxInternal__{
		T: b.T,
		Switch__: BoxInternalSwitch__{
			F_0__: (func(x *NaclBox) *NaclBoxInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(b.F_0__),
			F_1__: (func(x *YubiBox) *YubiBoxInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(b.F_1__),
			F_2__: (func(x *BoxHybrid) *BoxHybridInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(b.F_2__),
		},
	}
}

func (b *Box) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *Box) Decode(dec rpc.Decoder) error {
	var tmp BoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

var BoxTypeUniqueID = rpc.TypeUniqueID(0xb83ffa8f8cfd2ee3)

func (b *Box) GetTypeUniqueID() rpc.TypeUniqueID {
	return BoxTypeUniqueID
}

func (b *Box) Bytes() []byte { return nil }

type SignatureType int

const (
	SignatureType_EDDSA SignatureType = 0
	SignatureType_ECDSA SignatureType = 1
)

var SignatureTypeMap = map[string]SignatureType{
	"EDDSA": 0,
	"ECDSA": 1,
}

var SignatureTypeRevMap = map[SignatureType]string{
	0: "EDDSA",
	1: "ECDSA",
}

type SignatureTypeInternal__ SignatureType

func (s SignatureTypeInternal__) Import() SignatureType {
	return SignatureType(s)
}

func (s SignatureType) Export() *SignatureTypeInternal__ {
	return ((*SignatureTypeInternal__)(&s))
}

type Signature struct {
	T     SignatureType
	F_0__ *Ed25519Signature `json:"f0,omitempty"`
	F_1__ *ECDSASignature   `json:"f1,omitempty"`
}

type SignatureInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        SignatureType
	Switch__ SignatureInternalSwitch__
}

type SignatureInternalSwitch__ struct {
	_struct struct{}                    `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *Ed25519SignatureInternal__ `codec:"0"`
	F_1__   *ECDSASignatureInternal__   `codec:"1"`
}

func (s Signature) GetT() (ret SignatureType, err error) {
	switch s.T {
	case SignatureType_EDDSA:
		if s.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case SignatureType_ECDSA:
		if s.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return s.T, nil
}

func (s Signature) Eddsa() Ed25519Signature {
	if s.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.T != SignatureType_EDDSA {
		panic(fmt.Sprintf("unexpected switch value (%v) when Eddsa is called", s.T))
	}
	return *s.F_0__
}

func (s Signature) Ecdsa() ECDSASignature {
	if s.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.T != SignatureType_ECDSA {
		panic(fmt.Sprintf("unexpected switch value (%v) when Ecdsa is called", s.T))
	}
	return *s.F_1__
}

func NewSignatureWithEddsa(v Ed25519Signature) Signature {
	return Signature{
		T:     SignatureType_EDDSA,
		F_0__: &v,
	}
}

func NewSignatureWithEcdsa(v ECDSASignature) Signature {
	return Signature{
		T:     SignatureType_ECDSA,
		F_1__: &v,
	}
}

func (s SignatureInternal__) Import() Signature {
	return Signature{
		T: s.T,
		F_0__: (func(x *Ed25519SignatureInternal__) *Ed25519Signature {
			if x == nil {
				return nil
			}
			tmp := (func(x *Ed25519SignatureInternal__) (ret Ed25519Signature) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_0__),
		F_1__: (func(x *ECDSASignatureInternal__) *ECDSASignature {
			if x == nil {
				return nil
			}
			tmp := (func(x *ECDSASignatureInternal__) (ret ECDSASignature) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_1__),
	}
}

func (s Signature) Export() *SignatureInternal__ {
	return &SignatureInternal__{
		T: s.T,
		Switch__: SignatureInternalSwitch__{
			F_0__: (func(x *Ed25519Signature) *Ed25519SignatureInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_0__),
			F_1__: (func(x *ECDSASignature) *ECDSASignatureInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_1__),
		},
	}
}

func (s *Signature) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *Signature) Decode(dec rpc.Decoder) error {
	var tmp SignatureInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *Signature) Bytes() []byte { return nil }

type TempDHKeySigTemplate struct {
	BoxSetId  BoxSetID
	TempDHKey TempDHKey
	Signer    FQEntity
}

type TempDHKeySigTemplateInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	BoxSetId  *BoxSetIDInternal__
	TempDHKey *TempDHKeyInternal__
	Signer    *FQEntityInternal__
}

func (t TempDHKeySigTemplateInternal__) Import() TempDHKeySigTemplate {
	return TempDHKeySigTemplate{
		BoxSetId: (func(x *BoxSetIDInternal__) (ret BoxSetID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.BoxSetId),
		TempDHKey: (func(x *TempDHKeyInternal__) (ret TempDHKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.TempDHKey),
		Signer: (func(x *FQEntityInternal__) (ret FQEntity) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Signer),
	}
}

func (t TempDHKeySigTemplate) Export() *TempDHKeySigTemplateInternal__ {
	return &TempDHKeySigTemplateInternal__{
		BoxSetId:  t.BoxSetId.Export(),
		TempDHKey: t.TempDHKey.Export(),
		Signer:    t.Signer.Export(),
	}
}

func (t *TempDHKeySigTemplate) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TempDHKeySigTemplate) Decode(dec rpc.Decoder) error {
	var tmp TempDHKeySigTemplateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

var TempDHKeySigTemplateTypeUniqueID = rpc.TypeUniqueID(0xd51b5d990285023e)

func (t *TempDHKeySigTemplate) GetTypeUniqueID() rpc.TypeUniqueID {
	return TempDHKeySigTemplateTypeUniqueID
}

func (t *TempDHKeySigTemplate) Bytes() []byte { return nil }

type TempDHKey struct {
	Key  DHPublicKey
	Time Time
}

type TempDHKeyInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Key     *DHPublicKeyInternal__
	Time    *TimeInternal__
}

func (t TempDHKeyInternal__) Import() TempDHKey {
	return TempDHKey{
		Key: (func(x *DHPublicKeyInternal__) (ret DHPublicKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Key),
		Time: (func(x *TimeInternal__) (ret Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Time),
	}
}

func (t TempDHKey) Export() *TempDHKeyInternal__ {
	return &TempDHKeyInternal__{
		Key:  t.Key.Export(),
		Time: t.Time.Export(),
	}
}

func (t *TempDHKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TempDHKey) Decode(dec rpc.Decoder) error {
	var tmp TempDHKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TempDHKey) Bytes() []byte { return nil }

type TempDHKeySigned struct {
	TempDHKey TempDHKey
	Sig       Signature
}

type TempDHKeySignedInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	TempDHKey *TempDHKeyInternal__
	Sig       *SignatureInternal__
}

func (t TempDHKeySignedInternal__) Import() TempDHKeySigned {
	return TempDHKeySigned{
		TempDHKey: (func(x *TempDHKeyInternal__) (ret TempDHKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.TempDHKey),
		Sig: (func(x *SignatureInternal__) (ret Signature) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(t.Sig),
	}
}

func (t TempDHKeySigned) Export() *TempDHKeySignedInternal__ {
	return &TempDHKeySignedInternal__{
		TempDHKey: t.TempDHKey.Export(),
		Sig:       t.Sig.Export(),
	}
}

func (t *TempDHKeySigned) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TempDHKeySigned) Decode(dec rpc.Decoder) error {
	var tmp TempDHKeySignedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t *TempDHKeySigned) Bytes() []byte { return nil }

type BoxSetID [16]byte
type BoxSetIDInternal__ [16]byte

func (b BoxSetID) Export() *BoxSetIDInternal__ {
	tmp := (([16]byte)(b))
	return ((*BoxSetIDInternal__)(&tmp))
}

func (b BoxSetIDInternal__) Import() BoxSetID {
	tmp := ([16]byte)(b)
	return BoxSetID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (b *BoxSetID) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BoxSetID) Decode(dec rpc.Decoder) error {
	var tmp BoxSetIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b BoxSetID) Bytes() []byte {
	return (b)[:]
}

type SignedBoxSet struct {
	Id              BoxSetID
	Boxes           []Box
	TempDHKeySigned *TempDHKeySigned
}

type SignedBoxSetInternal__ struct {
	_struct         struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id              *BoxSetIDInternal__
	Boxes           *[](*BoxInternal__)
	TempDHKeySigned *TempDHKeySignedInternal__
}

func (s SignedBoxSetInternal__) Import() SignedBoxSet {
	return SignedBoxSet{
		Id: (func(x *BoxSetIDInternal__) (ret BoxSetID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Id),
		Boxes: (func(x *[](*BoxInternal__)) (ret []Box) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]Box, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *BoxInternal__) (ret Box) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(s.Boxes),
		TempDHKeySigned: (func(x *TempDHKeySignedInternal__) *TempDHKeySigned {
			if x == nil {
				return nil
			}
			tmp := (func(x *TempDHKeySignedInternal__) (ret TempDHKeySigned) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.TempDHKeySigned),
	}
}

func (s SignedBoxSet) Export() *SignedBoxSetInternal__ {
	return &SignedBoxSetInternal__{
		Id: s.Id.Export(),
		Boxes: (func(x []Box) *[](*BoxInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*BoxInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(s.Boxes),
		TempDHKeySigned: (func(x *TempDHKeySigned) *TempDHKeySignedInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(s.TempDHKeySigned),
	}
}

func (s *SignedBoxSet) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SignedBoxSet) Decode(dec rpc.Decoder) error {
	var tmp SignedBoxSetInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SignedBoxSet) Bytes() []byte { return nil }

type YubiBox struct {
	Pk        *ECDSACompressedPublicKey
	SecretBox SecretBox
}

type YubiBoxInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Pk        *ECDSACompressedPublicKeyInternal__
	SecretBox *SecretBoxInternal__
}

func (y YubiBoxInternal__) Import() YubiBox {
	return YubiBox{
		Pk: (func(x *ECDSACompressedPublicKeyInternal__) *ECDSACompressedPublicKey {
			if x == nil {
				return nil
			}
			tmp := (func(x *ECDSACompressedPublicKeyInternal__) (ret ECDSACompressedPublicKey) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(y.Pk),
		SecretBox: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(y.SecretBox),
	}
}

func (y YubiBox) Export() *YubiBoxInternal__ {
	return &YubiBoxInternal__{
		Pk: (func(x *ECDSACompressedPublicKey) *ECDSACompressedPublicKeyInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(y.Pk),
		SecretBox: y.SecretBox.Export(),
	}
}

func (y *YubiBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(y.Export())
}

func (y *YubiBox) Decode(dec rpc.Decoder) error {
	var tmp YubiBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*y = tmp.Import()
	return nil
}

func (y *YubiBox) Bytes() []byte { return nil }

type KeySuite struct {
	Entity EntityID
	Hepk   HEPK
}

type KeySuiteInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Entity  *EntityIDInternal__
	Hepk    *HEPKInternal__
}

func (k KeySuiteInternal__) Import() KeySuite {
	return KeySuite{
		Entity: (func(x *EntityIDInternal__) (ret EntityID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Entity),
		Hepk: (func(x *HEPKInternal__) (ret HEPK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.Hepk),
	}
}

func (k KeySuite) Export() *KeySuiteInternal__ {
	return &KeySuiteInternal__{
		Entity: k.Entity.Export(),
		Hepk:   k.Hepk.Export(),
	}
}

func (k *KeySuite) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KeySuite) Decode(dec rpc.Decoder) error {
	var tmp KeySuiteInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KeySuite) Bytes() []byte { return nil }

type Hostname string
type HostnameInternal__ string

func (h Hostname) Export() *HostnameInternal__ {
	tmp := ((string)(h))
	return ((*HostnameInternal__)(&tmp))
}

func (h HostnameInternal__) Import() Hostname {
	tmp := (string)(h)
	return Hostname((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (h *Hostname) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *Hostname) Decode(dec rpc.Decoder) error {
	var tmp HostnameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h Hostname) Bytes() []byte {
	return nil
}

type BindAddr string
type BindAddrInternal__ string

func (b BindAddr) Export() *BindAddrInternal__ {
	tmp := ((string)(b))
	return ((*BindAddrInternal__)(&tmp))
}

func (b BindAddrInternal__) Import() BindAddr {
	tmp := (string)(b)
	return BindAddr((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (b *BindAddr) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BindAddr) Decode(dec rpc.Decoder) error {
	var tmp BindAddrInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b BindAddr) Bytes() []byte {
	return nil
}

type TCPAddr string
type TCPAddrInternal__ string

func (t TCPAddr) Export() *TCPAddrInternal__ {
	tmp := ((string)(t))
	return ((*TCPAddrInternal__)(&tmp))
}

func (t TCPAddrInternal__) Import() TCPAddr {
	tmp := (string)(t)
	return TCPAddr((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TCPAddr) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TCPAddr) Decode(dec rpc.Decoder) error {
	var tmp TCPAddrInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TCPAddr) Bytes() []byte {
	return nil
}

type Port uint64
type PortInternal__ uint64

func (p Port) Export() *PortInternal__ {
	tmp := ((uint64)(p))
	return ((*PortInternal__)(&tmp))
}

func (p PortInternal__) Import() Port {
	tmp := (uint64)(p)
	return Port((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *Port) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *Port) Decode(dec rpc.Decoder) error {
	var tmp PortInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p Port) Bytes() []byte {
	return nil
}

type ZoneID string
type ZoneIDInternal__ string

func (z ZoneID) Export() *ZoneIDInternal__ {
	tmp := ((string)(z))
	return ((*ZoneIDInternal__)(&tmp))
}

func (z ZoneIDInternal__) Import() ZoneID {
	tmp := (string)(z)
	return ZoneID((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (z *ZoneID) Encode(enc rpc.Encoder) error {
	return enc.Encode(z.Export())
}

func (z *ZoneID) Decode(dec rpc.Decoder) error {
	var tmp ZoneIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*z = tmp.Import()
	return nil
}

func (z ZoneID) Bytes() []byte {
	return nil
}

type ShortIDType int

const (
	ShortIDType_WaitList ShortIDType = 1
)

var ShortIDTypeMap = map[string]ShortIDType{
	"WaitList": 1,
}

var ShortIDTypeRevMap = map[ShortIDType]string{
	1: "WaitList",
}

type ShortIDTypeInternal__ ShortIDType

func (s ShortIDTypeInternal__) Import() ShortIDType {
	return ShortIDType(s)
}

func (s ShortIDType) Export() *ShortIDTypeInternal__ {
	return ((*ShortIDTypeInternal__)(&s))
}

type ShortID [13]byte
type ShortIDInternal__ [13]byte

func (s ShortID) Export() *ShortIDInternal__ {
	tmp := (([13]byte)(s))
	return ((*ShortIDInternal__)(&tmp))
}

func (s ShortIDInternal__) Import() ShortID {
	tmp := ([13]byte)(s)
	return ShortID((func(x *[13]byte) (ret [13]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *ShortID) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *ShortID) Decode(dec rpc.Decoder) error {
	var tmp ShortIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s ShortID) Bytes() []byte {
	return (s)[:]
}

type WaitListID ShortID
type WaitListIDInternal__ ShortIDInternal__

func (w WaitListID) Export() *WaitListIDInternal__ {
	tmp := ((ShortID)(w))
	return ((*WaitListIDInternal__)(tmp.Export()))
}

func (w WaitListIDInternal__) Import() WaitListID {
	tmp := (ShortIDInternal__)(w)
	return WaitListID((func(x *ShortIDInternal__) (ret ShortID) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (w *WaitListID) Encode(enc rpc.Encoder) error {
	return enc.Encode(w.Export())
}

func (w *WaitListID) Decode(dec rpc.Decoder) error {
	var tmp WaitListIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*w = tmp.Import()
	return nil
}

func (w WaitListID) Bytes() []byte {
	return ((ShortID)(w)).Bytes()
}

type ServerType int

const (
	ServerType_None          ServerType = 0
	ServerType_Reg           ServerType = 1
	ServerType_User          ServerType = 2
	ServerType_MerkleBuilder ServerType = 3
	ServerType_InternalCA    ServerType = 4
	ServerType_MerkleQuery   ServerType = 5
	ServerType_Queue         ServerType = 6
	ServerType_Tools         ServerType = 7
	ServerType_MerkleBatcher ServerType = 8
	ServerType_MerkleSigner  ServerType = 9
	ServerType_Probe         ServerType = 10
	ServerType_Beacon        ServerType = 11
	ServerType_KVStore       ServerType = 12
	ServerType_Quota         ServerType = 13
	ServerType_Autocert      ServerType = 15
	ServerType_Web           ServerType = 64
	ServerType_Test          ServerType = 101
)

var ServerTypeMap = map[string]ServerType{
	"None":          0,
	"Reg":           1,
	"User":          2,
	"MerkleBuilder": 3,
	"InternalCA":    4,
	"MerkleQuery":   5,
	"Queue":         6,
	"Tools":         7,
	"MerkleBatcher": 8,
	"MerkleSigner":  9,
	"Probe":         10,
	"Beacon":        11,
	"KVStore":       12,
	"Quota":         13,
	"Autocert":      15,
	"Web":           64,
	"Test":          101,
}

var ServerTypeRevMap = map[ServerType]string{
	0:   "None",
	1:   "Reg",
	2:   "User",
	3:   "MerkleBuilder",
	4:   "InternalCA",
	5:   "MerkleQuery",
	6:   "Queue",
	7:   "Tools",
	8:   "MerkleBatcher",
	9:   "MerkleSigner",
	10:  "Probe",
	11:  "Beacon",
	12:  "KVStore",
	13:  "Quota",
	15:  "Autocert",
	64:  "Web",
	101: "Test",
}

type ServerTypeInternal__ ServerType

func (s ServerTypeInternal__) Import() ServerType {
	return ServerType(s)
}

func (s ServerType) Export() *ServerTypeInternal__ {
	return ((*ServerTypeInternal__)(&s))
}

type FQUserString string
type FQUserStringInternal__ string

func (f FQUserString) Export() *FQUserStringInternal__ {
	tmp := ((string)(f))
	return ((*FQUserStringInternal__)(&tmp))
}

func (f FQUserStringInternal__) Import() FQUserString {
	tmp := (string)(f)
	return FQUserString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (f *FQUserString) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQUserString) Decode(dec rpc.Decoder) error {
	var tmp FQUserStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f FQUserString) Bytes() []byte {
	return nil
}

type FQTeamString string
type FQTeamStringInternal__ string

func (f FQTeamString) Export() *FQTeamStringInternal__ {
	tmp := ((string)(f))
	return ((*FQTeamStringInternal__)(&tmp))
}

func (f FQTeamStringInternal__) Import() FQTeamString {
	tmp := (string)(f)
	return FQTeamString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (f *FQTeamString) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQTeamString) Decode(dec rpc.Decoder) error {
	var tmp FQTeamStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f FQTeamString) Bytes() []byte {
	return nil
}

type FQPartyString string
type FQPartyStringInternal__ string

func (f FQPartyString) Export() *FQPartyStringInternal__ {
	tmp := ((string)(f))
	return ((*FQPartyStringInternal__)(&tmp))
}

func (f FQPartyStringInternal__) Import() FQPartyString {
	tmp := (string)(f)
	return FQPartyString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (f *FQPartyString) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQPartyString) Decode(dec rpc.Decoder) error {
	var tmp FQPartyStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f FQPartyString) Bytes() []byte {
	return nil
}

type HostString string
type HostStringInternal__ string

func (h HostString) Export() *HostStringInternal__ {
	tmp := ((string)(h))
	return ((*HostStringInternal__)(&tmp))
}

func (h HostStringInternal__) Import() HostString {
	tmp := (string)(h)
	return HostString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (h *HostString) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HostString) Decode(dec rpc.Decoder) error {
	var tmp HostStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h HostString) Bytes() []byte {
	return nil
}

type UserString string
type UserStringInternal__ string

func (u UserString) Export() *UserStringInternal__ {
	tmp := ((string)(u))
	return ((*UserStringInternal__)(&tmp))
}

func (u UserStringInternal__) Import() UserString {
	tmp := (string)(u)
	return UserString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (u *UserString) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *UserString) Decode(dec rpc.Decoder) error {
	var tmp UserStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u UserString) Bytes() []byte {
	return nil
}

type TeamString string
type TeamStringInternal__ string

func (t TeamString) Export() *TeamStringInternal__ {
	tmp := ((string)(t))
	return ((*TeamStringInternal__)(&tmp))
}

func (t TeamStringInternal__) Import() TeamString {
	tmp := (string)(t)
	return TeamString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (t *TeamString) Encode(enc rpc.Encoder) error {
	return enc.Encode(t.Export())
}

func (t *TeamString) Decode(dec rpc.Decoder) error {
	var tmp TeamStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*t = tmp.Import()
	return nil
}

func (t TeamString) Bytes() []byte {
	return nil
}

type PartyString string
type PartyStringInternal__ string

func (p PartyString) Export() *PartyStringInternal__ {
	tmp := ((string)(p))
	return ((*PartyStringInternal__)(&tmp))
}

func (p PartyStringInternal__) Import() PartyString {
	tmp := (string)(p)
	return PartyString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *PartyString) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PartyString) Decode(dec rpc.Decoder) error {
	var tmp PartyStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PartyString) Bytes() []byte {
	return nil
}

type RoleString string
type RoleStringInternal__ string

func (r RoleString) Export() *RoleStringInternal__ {
	tmp := ((string)(r))
	return ((*RoleStringInternal__)(&tmp))
}

func (r RoleStringInternal__) Import() RoleString {
	tmp := (string)(r)
	return RoleString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *RoleString) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RoleString) Decode(dec rpc.Decoder) error {
	var tmp RoleStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r RoleString) Bytes() []byte {
	return nil
}

type ParsedTeam struct {
	S     bool
	F_0__ *TeamID   `json:"f0,omitempty"`
	F_1__ *NameUtf8 `json:"f1,omitempty"`
}

type ParsedTeamInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	S        bool
	Switch__ ParsedTeamInternalSwitch__
}

type ParsedTeamInternalSwitch__ struct {
	_struct struct{}            `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *TeamIDInternal__   `codec:"0"`
	F_1__   *NameUtf8Internal__ `codec:"1"`
}

func (p ParsedTeam) GetS() (ret bool, err error) {
	switch p.S {
	case false:
		if p.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case true:
		if p.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return p.S, nil
}

func (p ParsedTeam) False() TeamID {
	if p.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if p.S {
		panic(fmt.Sprintf("unexpected switch value (%v) when False is called", p.S))
	}
	return *p.F_0__
}

func (p ParsedTeam) True() NameUtf8 {
	if p.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if !p.S {
		panic(fmt.Sprintf("unexpected switch value (%v) when True is called", p.S))
	}
	return *p.F_1__
}

func NewParsedTeamWithFalse(v TeamID) ParsedTeam {
	return ParsedTeam{
		S:     false,
		F_0__: &v,
	}
}

func NewParsedTeamWithTrue(v NameUtf8) ParsedTeam {
	return ParsedTeam{
		S:     true,
		F_1__: &v,
	}
}

func (p ParsedTeamInternal__) Import() ParsedTeam {
	return ParsedTeam{
		S: p.S,
		F_0__: (func(x *TeamIDInternal__) *TeamID {
			if x == nil {
				return nil
			}
			tmp := (func(x *TeamIDInternal__) (ret TeamID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Switch__.F_0__),
		F_1__: (func(x *NameUtf8Internal__) *NameUtf8 {
			if x == nil {
				return nil
			}
			tmp := (func(x *NameUtf8Internal__) (ret NameUtf8) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Switch__.F_1__),
	}
}

func (p ParsedTeam) Export() *ParsedTeamInternal__ {
	return &ParsedTeamInternal__{
		S: p.S,
		Switch__: ParsedTeamInternalSwitch__{
			F_0__: (func(x *TeamID) *TeamIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(p.F_0__),
			F_1__: (func(x *NameUtf8) *NameUtf8Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(p.F_1__),
		},
	}
}

func (p *ParsedTeam) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ParsedTeam) Decode(dec rpc.Decoder) error {
	var tmp ParsedTeamInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *ParsedTeam) Bytes() []byte { return nil }

type PartyName struct {
	Name   NameUtf8
	IsTeam bool
}

type PartyNameInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name    *NameUtf8Internal__
	IsTeam  *bool
}

func (p PartyNameInternal__) Import() PartyName {
	return PartyName{
		Name: (func(x *NameUtf8Internal__) (ret NameUtf8) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Name),
		IsTeam: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(p.IsTeam),
	}
}

func (p PartyName) Export() *PartyNameInternal__ {
	return &PartyNameInternal__{
		Name:   p.Name.Export(),
		IsTeam: &p.IsTeam,
	}
}

func (p *PartyName) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PartyName) Decode(dec rpc.Decoder) error {
	var tmp PartyNameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PartyName) Bytes() []byte { return nil }

type PartyType int

const (
	PartyType_User PartyType = 0
	PartyType_Team PartyType = 1
)

var PartyTypeMap = map[string]PartyType{
	"User": 0,
	"Team": 1,
}

var PartyTypeRevMap = map[PartyType]string{
	0: "User",
	1: "Team",
}

type PartyTypeInternal__ PartyType

func (p PartyTypeInternal__) Import() PartyType {
	return PartyType(p)
}

func (p PartyType) Export() *PartyTypeInternal__ {
	return ((*PartyTypeInternal__)(&p))
}

type ParsedParty struct {
	S     bool
	F_0__ *PartyID   `json:"f0,omitempty"`
	F_1__ *PartyName `json:"f1,omitempty"`
}

type ParsedPartyInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	S        bool
	Switch__ ParsedPartyInternalSwitch__
}

type ParsedPartyInternalSwitch__ struct {
	_struct struct{}             `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *PartyIDInternal__   `codec:"0"`
	F_1__   *PartyNameInternal__ `codec:"1"`
}

func (p ParsedParty) GetS() (ret bool, err error) {
	switch p.S {
	case false:
		if p.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case true:
		if p.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return p.S, nil
}

func (p ParsedParty) False() PartyID {
	if p.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if p.S {
		panic(fmt.Sprintf("unexpected switch value (%v) when False is called", p.S))
	}
	return *p.F_0__
}

func (p ParsedParty) True() PartyName {
	if p.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if !p.S {
		panic(fmt.Sprintf("unexpected switch value (%v) when True is called", p.S))
	}
	return *p.F_1__
}

func NewParsedPartyWithFalse(v PartyID) ParsedParty {
	return ParsedParty{
		S:     false,
		F_0__: &v,
	}
}

func NewParsedPartyWithTrue(v PartyName) ParsedParty {
	return ParsedParty{
		S:     true,
		F_1__: &v,
	}
}

func (p ParsedPartyInternal__) Import() ParsedParty {
	return ParsedParty{
		S: p.S,
		F_0__: (func(x *PartyIDInternal__) *PartyID {
			if x == nil {
				return nil
			}
			tmp := (func(x *PartyIDInternal__) (ret PartyID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Switch__.F_0__),
		F_1__: (func(x *PartyNameInternal__) *PartyName {
			if x == nil {
				return nil
			}
			tmp := (func(x *PartyNameInternal__) (ret PartyName) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Switch__.F_1__),
	}
}

func (p ParsedParty) Export() *ParsedPartyInternal__ {
	return &ParsedPartyInternal__{
		S: p.S,
		Switch__: ParsedPartyInternalSwitch__{
			F_0__: (func(x *PartyID) *PartyIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(p.F_0__),
			F_1__: (func(x *PartyName) *PartyNameInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(p.F_1__),
		},
	}
}

func (p *ParsedParty) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ParsedParty) Decode(dec rpc.Decoder) error {
	var tmp ParsedPartyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *ParsedParty) Bytes() []byte { return nil }

type ParsedUser struct {
	S     bool
	F_0__ *UID      `json:"f0,omitempty"`
	F_1__ *NameUtf8 `json:"f1,omitempty"`
}

type ParsedUserInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	S        bool
	Switch__ ParsedUserInternalSwitch__
}

type ParsedUserInternalSwitch__ struct {
	_struct struct{}            `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *UIDInternal__      `codec:"0"`
	F_1__   *NameUtf8Internal__ `codec:"1"`
}

func (p ParsedUser) GetS() (ret bool, err error) {
	switch p.S {
	case false:
		if p.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case true:
		if p.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return p.S, nil
}

func (p ParsedUser) False() UID {
	if p.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if p.S {
		panic(fmt.Sprintf("unexpected switch value (%v) when False is called", p.S))
	}
	return *p.F_0__
}

func (p ParsedUser) True() NameUtf8 {
	if p.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if !p.S {
		panic(fmt.Sprintf("unexpected switch value (%v) when True is called", p.S))
	}
	return *p.F_1__
}

func NewParsedUserWithFalse(v UID) ParsedUser {
	return ParsedUser{
		S:     false,
		F_0__: &v,
	}
}

func NewParsedUserWithTrue(v NameUtf8) ParsedUser {
	return ParsedUser{
		S:     true,
		F_1__: &v,
	}
}

func (p ParsedUserInternal__) Import() ParsedUser {
	return ParsedUser{
		S: p.S,
		F_0__: (func(x *UIDInternal__) *UID {
			if x == nil {
				return nil
			}
			tmp := (func(x *UIDInternal__) (ret UID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Switch__.F_0__),
		F_1__: (func(x *NameUtf8Internal__) *NameUtf8 {
			if x == nil {
				return nil
			}
			tmp := (func(x *NameUtf8Internal__) (ret NameUtf8) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Switch__.F_1__),
	}
}

func (p ParsedUser) Export() *ParsedUserInternal__ {
	return &ParsedUserInternal__{
		S: p.S,
		Switch__: ParsedUserInternalSwitch__{
			F_0__: (func(x *UID) *UIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(p.F_0__),
			F_1__: (func(x *NameUtf8) *NameUtf8Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(p.F_1__),
		},
	}
}

func (p *ParsedUser) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ParsedUser) Decode(dec rpc.Decoder) error {
	var tmp ParsedUserInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *ParsedUser) Bytes() []byte { return nil }

type ParsedHostname struct {
	S     bool
	F_0__ *HostID  `json:"f0,omitempty"`
	F_1__ *TCPAddr `json:"f1,omitempty"`
}

type ParsedHostnameInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	S        bool
	Switch__ ParsedHostnameInternalSwitch__
}

type ParsedHostnameInternalSwitch__ struct {
	_struct struct{}           `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *HostIDInternal__  `codec:"0"`
	F_1__   *TCPAddrInternal__ `codec:"1"`
}

func (p ParsedHostname) GetS() (ret bool, err error) {
	switch p.S {
	case false:
		if p.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case true:
		if p.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return p.S, nil
}

func (p ParsedHostname) False() HostID {
	if p.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if p.S {
		panic(fmt.Sprintf("unexpected switch value (%v) when False is called", p.S))
	}
	return *p.F_0__
}

func (p ParsedHostname) True() TCPAddr {
	if p.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if !p.S {
		panic(fmt.Sprintf("unexpected switch value (%v) when True is called", p.S))
	}
	return *p.F_1__
}

func NewParsedHostnameWithFalse(v HostID) ParsedHostname {
	return ParsedHostname{
		S:     false,
		F_0__: &v,
	}
}

func NewParsedHostnameWithTrue(v TCPAddr) ParsedHostname {
	return ParsedHostname{
		S:     true,
		F_1__: &v,
	}
}

func (p ParsedHostnameInternal__) Import() ParsedHostname {
	return ParsedHostname{
		S: p.S,
		F_0__: (func(x *HostIDInternal__) *HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *HostIDInternal__) (ret HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Switch__.F_0__),
		F_1__: (func(x *TCPAddrInternal__) *TCPAddr {
			if x == nil {
				return nil
			}
			tmp := (func(x *TCPAddrInternal__) (ret TCPAddr) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Switch__.F_1__),
	}
}

func (p ParsedHostname) Export() *ParsedHostnameInternal__ {
	return &ParsedHostnameInternal__{
		S: p.S,
		Switch__: ParsedHostnameInternalSwitch__{
			F_0__: (func(x *HostID) *HostIDInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(p.F_0__),
			F_1__: (func(x *TCPAddr) *TCPAddrInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(p.F_1__),
		},
	}
}

func (p *ParsedHostname) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ParsedHostname) Decode(dec rpc.Decoder) error {
	var tmp ParsedHostnameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *ParsedHostname) Bytes() []byte { return nil }

type FQUserParsed struct {
	User ParsedUser
	Host *ParsedHostname
}

type FQUserParsedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	User    *ParsedUserInternal__
	Host    *ParsedHostnameInternal__
}

func (f FQUserParsedInternal__) Import() FQUserParsed {
	return FQUserParsed{
		User: (func(x *ParsedUserInternal__) (ret ParsedUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.User),
		Host: (func(x *ParsedHostnameInternal__) *ParsedHostname {
			if x == nil {
				return nil
			}
			tmp := (func(x *ParsedHostnameInternal__) (ret ParsedHostname) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(f.Host),
	}
}

func (f FQUserParsed) Export() *FQUserParsedInternal__ {
	return &FQUserParsedInternal__{
		User: f.User.Export(),
		Host: (func(x *ParsedHostname) *ParsedHostnameInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(f.Host),
	}
}

func (f *FQUserParsed) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQUserParsed) Decode(dec rpc.Decoder) error {
	var tmp FQUserParsedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQUserParsed) Bytes() []byte { return nil }

type FQTeamParsed struct {
	Team ParsedTeam
	Host *ParsedHostname
}

type FQTeamParsedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Team    *ParsedTeamInternal__
	Host    *ParsedHostnameInternal__
}

func (f FQTeamParsedInternal__) Import() FQTeamParsed {
	return FQTeamParsed{
		Team: (func(x *ParsedTeamInternal__) (ret ParsedTeam) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Team),
		Host: (func(x *ParsedHostnameInternal__) *ParsedHostname {
			if x == nil {
				return nil
			}
			tmp := (func(x *ParsedHostnameInternal__) (ret ParsedHostname) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(f.Host),
	}
}

func (f FQTeamParsed) Export() *FQTeamParsedInternal__ {
	return &FQTeamParsedInternal__{
		Team: f.Team.Export(),
		Host: (func(x *ParsedHostname) *ParsedHostnameInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(f.Host),
	}
}

func (f *FQTeamParsed) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQTeamParsed) Decode(dec rpc.Decoder) error {
	var tmp FQTeamParsedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

var FQTeamParsedTypeUniqueID = rpc.TypeUniqueID(0xc3e7f63d5c536710)

func (f *FQTeamParsed) GetTypeUniqueID() rpc.TypeUniqueID {
	return FQTeamParsedTypeUniqueID
}

func (f *FQTeamParsed) Bytes() []byte { return nil }

type FQPartyParsed struct {
	Party ParsedParty
	Host  *ParsedHostname
}

type FQPartyParsedInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Party   *ParsedPartyInternal__
	Host    *ParsedHostnameInternal__
}

func (f FQPartyParsedInternal__) Import() FQPartyParsed {
	return FQPartyParsed{
		Party: (func(x *ParsedPartyInternal__) (ret ParsedParty) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Party),
		Host: (func(x *ParsedHostnameInternal__) *ParsedHostname {
			if x == nil {
				return nil
			}
			tmp := (func(x *ParsedHostnameInternal__) (ret ParsedHostname) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(f.Host),
	}
}

func (f FQPartyParsed) Export() *FQPartyParsedInternal__ {
	return &FQPartyParsedInternal__{
		Party: f.Party.Export(),
		Host: (func(x *ParsedHostname) *ParsedHostnameInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(f.Host),
	}
}

func (f *FQPartyParsed) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQPartyParsed) Decode(dec rpc.Decoder) error {
	var tmp FQPartyParsedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQPartyParsed) Bytes() []byte { return nil }

type HEPKv1 struct {
	Classical DHPublicKey
	Pqkem     KemEncapKey
}

type HEPKv1Internal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Classical *DHPublicKeyInternal__
	Pqkem     *KemEncapKeyInternal__
}

func (h HEPKv1Internal__) Import() HEPKv1 {
	return HEPKv1{
		Classical: (func(x *DHPublicKeyInternal__) (ret DHPublicKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Classical),
		Pqkem: (func(x *KemEncapKeyInternal__) (ret KemEncapKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Pqkem),
	}
}

func (h HEPKv1) Export() *HEPKv1Internal__ {
	return &HEPKv1Internal__{
		Classical: h.Classical.Export(),
		Pqkem:     h.Pqkem.Export(),
	}
}

func (h *HEPKv1) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HEPKv1) Decode(dec rpc.Decoder) error {
	var tmp HEPKv1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

var HEPKv1TypeUniqueID = rpc.TypeUniqueID(0x9c267d45631bb8c1)

func (h *HEPKv1) GetTypeUniqueID() rpc.TypeUniqueID {
	return HEPKv1TypeUniqueID
}

func (h *HEPKv1) Bytes() []byte { return nil }

type HEPKVersion int

const (
	HEPKVersion_None HEPKVersion = 0
	HEPKVersion_V1   HEPKVersion = 1
)

var HEPKVersionMap = map[string]HEPKVersion{
	"None": 0,
	"V1":   1,
}

var HEPKVersionRevMap = map[HEPKVersion]string{
	0: "None",
	1: "V1",
}

type HEPKVersionInternal__ HEPKVersion

func (h HEPKVersionInternal__) Import() HEPKVersion {
	return HEPKVersion(h)
}

func (h HEPKVersion) Export() *HEPKVersionInternal__ {
	return ((*HEPKVersionInternal__)(&h))
}

type HEPK struct {
	V     HEPKVersion
	F_1__ *HEPKv1 `json:"f1,omitempty"`
}

type HEPKInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        HEPKVersion
	Switch__ HEPKInternalSwitch__
}

type HEPKInternalSwitch__ struct {
	_struct struct{}          `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *HEPKv1Internal__ `codec:"1"`
}

func (h HEPK) GetV() (ret HEPKVersion, err error) {
	switch h.V {
	case HEPKVersion_V1:
		if h.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return h.V, nil
}

func (h HEPK) V1() HEPKv1 {
	if h.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if h.V != HEPKVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", h.V))
	}
	return *h.F_1__
}

func NewHEPKWithV1(v HEPKv1) HEPK {
	return HEPK{
		V:     HEPKVersion_V1,
		F_1__: &v,
	}
}

func (h HEPKInternal__) Import() HEPK {
	return HEPK{
		V: h.V,
		F_1__: (func(x *HEPKv1Internal__) *HEPKv1 {
			if x == nil {
				return nil
			}
			tmp := (func(x *HEPKv1Internal__) (ret HEPKv1) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(h.Switch__.F_1__),
	}
}

func (h HEPK) Export() *HEPKInternal__ {
	return &HEPKInternal__{
		V: h.V,
		Switch__: HEPKInternalSwitch__{
			F_1__: (func(x *HEPKv1) *HEPKv1Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(h.F_1__),
		},
	}
}

func (h *HEPK) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HEPK) Decode(dec rpc.Decoder) error {
	var tmp HEPKInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

var HEPKTypeUniqueID = rpc.TypeUniqueID(0x9c581beed36c7e0c)

func (h *HEPK) GetTypeUniqueID() rpc.TypeUniqueID {
	return HEPKTypeUniqueID
}

func (h *HEPK) Bytes() []byte { return nil }

type HEPKSet struct {
	V []HEPK
}

type HEPKSetInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V       *[](*HEPKInternal__)
}

func (h HEPKSetInternal__) Import() HEPKSet {
	return HEPKSet{
		V: (func(x *[](*HEPKInternal__)) (ret []HEPK) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]HEPK, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *HEPKInternal__) (ret HEPK) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(h.V),
	}
}

func (h HEPKSet) Export() *HEPKSetInternal__ {
	return &HEPKSetInternal__{
		V: (func(x []HEPK) *[](*HEPKInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*HEPKInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(h.V),
	}
}

func (h *HEPKSet) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HEPKSet) Decode(dec rpc.Decoder) error {
	var tmp HEPKSetInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h *HEPKSet) Bytes() []byte { return nil }

type HEPKFingerprint StdHash
type HEPKFingerprintInternal__ StdHashInternal__

func (h HEPKFingerprint) Export() *HEPKFingerprintInternal__ {
	tmp := ((StdHash)(h))
	return ((*HEPKFingerprintInternal__)(tmp.Export()))
}

func (h HEPKFingerprintInternal__) Import() HEPKFingerprint {
	tmp := (StdHashInternal__)(h)
	return HEPKFingerprint((func(x *StdHashInternal__) (ret StdHash) {
		if x == nil {
			return ret
		}
		return x.Import()
	})(&tmp))
}

func (h *HEPKFingerprint) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HEPKFingerprint) Decode(dec rpc.Decoder) error {
	var tmp HEPKFingerprintInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h HEPKFingerprint) Bytes() []byte {
	return ((StdHash)(h)).Bytes()
}

type CryptosystemType int

const (
	CryptosystemType_Classical CryptosystemType = 0
	CryptosystemType_PQKEM     CryptosystemType = 1
)

var CryptosystemTypeMap = map[string]CryptosystemType{
	"Classical": 0,
	"PQKEM":     1,
}

var CryptosystemTypeRevMap = map[CryptosystemType]string{
	0: "Classical",
	1: "PQKEM",
}

type CryptosystemTypeInternal__ CryptosystemType

func (c CryptosystemTypeInternal__) Import() CryptosystemType {
	return CryptosystemType(c)
}

func (c CryptosystemType) Export() *CryptosystemTypeInternal__ {
	return ((*CryptosystemTypeInternal__)(&c))
}

type HybridSecretKeySHA3Payload struct {
	Version     BoxHybridVersion
	PqKemKey    KemSharedKey
	DhSharedKey DHSharedKey
	Rcvr        HEPK
	Sndr        DHPublicKey
}

type HybridSecretKeySHA3PayloadInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Version     *BoxHybridVersionInternal__
	PqKemKey    *KemSharedKeyInternal__
	DhSharedKey *DHSharedKeyInternal__
	Rcvr        *HEPKInternal__
	Sndr        *DHPublicKeyInternal__
}

func (h HybridSecretKeySHA3PayloadInternal__) Import() HybridSecretKeySHA3Payload {
	return HybridSecretKeySHA3Payload{
		Version: (func(x *BoxHybridVersionInternal__) (ret BoxHybridVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Version),
		PqKemKey: (func(x *KemSharedKeyInternal__) (ret KemSharedKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.PqKemKey),
		DhSharedKey: (func(x *DHSharedKeyInternal__) (ret DHSharedKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.DhSharedKey),
		Rcvr: (func(x *HEPKInternal__) (ret HEPK) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Rcvr),
		Sndr: (func(x *DHPublicKeyInternal__) (ret DHPublicKey) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(h.Sndr),
	}
}

func (h HybridSecretKeySHA3Payload) Export() *HybridSecretKeySHA3PayloadInternal__ {
	return &HybridSecretKeySHA3PayloadInternal__{
		Version:     h.Version.Export(),
		PqKemKey:    h.PqKemKey.Export(),
		DhSharedKey: h.DhSharedKey.Export(),
		Rcvr:        h.Rcvr.Export(),
		Sndr:        h.Sndr.Export(),
	}
}

func (h *HybridSecretKeySHA3Payload) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HybridSecretKeySHA3Payload) Decode(dec rpc.Decoder) error {
	var tmp HybridSecretKeySHA3PayloadInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

var HybridSecretKeySHA3PayloadTypeUniqueID = rpc.TypeUniqueID(0x8a9e327647262289)

func (h *HybridSecretKeySHA3Payload) GetTypeUniqueID() rpc.TypeUniqueID {
	return HybridSecretKeySHA3PayloadTypeUniqueID
}

func (h *HybridSecretKeySHA3Payload) Bytes() []byte { return nil }

type BoxHybridVersion int

const (
	BoxHybridVersion_V1 BoxHybridVersion = 1
)

var BoxHybridVersionMap = map[string]BoxHybridVersion{
	"V1": 1,
}

var BoxHybridVersionRevMap = map[BoxHybridVersion]string{
	1: "V1",
}

type BoxHybridVersionInternal__ BoxHybridVersion

func (b BoxHybridVersionInternal__) Import() BoxHybridVersion {
	return BoxHybridVersion(b)
}

func (b BoxHybridVersion) Export() *BoxHybridVersionInternal__ {
	return ((*BoxHybridVersionInternal__)(&b))
}

type BoxHybrid struct {
	V     BoxHybridVersion
	F_1__ *BoxHybridV1 `json:"f1,omitempty"`
}

type BoxHybridInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        BoxHybridVersion
	Switch__ BoxHybridInternalSwitch__
}

type BoxHybridInternalSwitch__ struct {
	_struct struct{}               `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *BoxHybridV1Internal__ `codec:"1"`
}

func (b BoxHybrid) GetV() (ret BoxHybridVersion, err error) {
	switch b.V {
	case BoxHybridVersion_V1:
		if b.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return b.V, nil
}

func (b BoxHybrid) V1() BoxHybridV1 {
	if b.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if b.V != BoxHybridVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", b.V))
	}
	return *b.F_1__
}

func NewBoxHybridWithV1(v BoxHybridV1) BoxHybrid {
	return BoxHybrid{
		V:     BoxHybridVersion_V1,
		F_1__: &v,
	}
}

func (b BoxHybridInternal__) Import() BoxHybrid {
	return BoxHybrid{
		V: b.V,
		F_1__: (func(x *BoxHybridV1Internal__) *BoxHybridV1 {
			if x == nil {
				return nil
			}
			tmp := (func(x *BoxHybridV1Internal__) (ret BoxHybridV1) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(b.Switch__.F_1__),
	}
}

func (b BoxHybrid) Export() *BoxHybridInternal__ {
	return &BoxHybridInternal__{
		V: b.V,
		Switch__: BoxHybridInternalSwitch__{
			F_1__: (func(x *BoxHybridV1) *BoxHybridV1Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(b.F_1__),
		},
	}
}

func (b *BoxHybrid) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BoxHybrid) Decode(dec rpc.Decoder) error {
	var tmp BoxHybridInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b *BoxHybrid) Bytes() []byte { return nil }

type BoxHybridV1 struct {
	KemCtext KemCiphertext
	DhType   DHType
	Sender   *DHPublicKey
	Sbox     SecretBox
}

type BoxHybridV1Internal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	KemCtext *KemCiphertextInternal__
	DhType   *DHTypeInternal__
	Sender   *DHPublicKeyInternal__
	Sbox     *SecretBoxInternal__
}

func (b BoxHybridV1Internal__) Import() BoxHybridV1 {
	return BoxHybridV1{
		KemCtext: (func(x *KemCiphertextInternal__) (ret KemCiphertext) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.KemCtext),
		DhType: (func(x *DHTypeInternal__) (ret DHType) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.DhType),
		Sender: (func(x *DHPublicKeyInternal__) *DHPublicKey {
			if x == nil {
				return nil
			}
			tmp := (func(x *DHPublicKeyInternal__) (ret DHPublicKey) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(b.Sender),
		Sbox: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(b.Sbox),
	}
}

func (b BoxHybridV1) Export() *BoxHybridV1Internal__ {
	return &BoxHybridV1Internal__{
		KemCtext: b.KemCtext.Export(),
		DhType:   b.DhType.Export(),
		Sender: (func(x *DHPublicKey) *DHPublicKeyInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(b.Sender),
		Sbox: b.Sbox.Export(),
	}
}

func (b *BoxHybridV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BoxHybridV1) Decode(dec rpc.Decoder) error {
	var tmp BoxHybridV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

func (b *BoxHybridV1) Bytes() []byte { return nil }

type BackupSeed [26]byte
type BackupSeedInternal__ [26]byte

func (b BackupSeed) Export() *BackupSeedInternal__ {
	tmp := (([26]byte)(b))
	return ((*BackupSeedInternal__)(&tmp))
}

func (b BackupSeedInternal__) Import() BackupSeed {
	tmp := ([26]byte)(b)
	return BackupSeed((func(x *[26]byte) (ret [26]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (b *BackupSeed) Encode(enc rpc.Encoder) error {
	return enc.Encode(b.Export())
}

func (b *BackupSeed) Decode(dec rpc.Decoder) error {
	var tmp BackupSeedInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*b = tmp.Import()
	return nil
}

var BackupSeedTypeUniqueID = rpc.TypeUniqueID(0xf4c4fe8dff61a6dc)

func (b *BackupSeed) GetTypeUniqueID() rpc.TypeUniqueID {
	return BackupSeedTypeUniqueID
}

func (b BackupSeed) Bytes() []byte {
	return (b)[:]
}

type BackupKeyVersion int

const (
	BackupKeyVersion_V1 BackupKeyVersion = 1
)

var BackupKeyVersionMap = map[string]BackupKeyVersion{
	"V1": 1,
}

var BackupKeyVersionRevMap = map[BackupKeyVersion]string{
	1: "V1",
}

type BackupKeyVersionInternal__ BackupKeyVersion

func (b BackupKeyVersionInternal__) Import() BackupKeyVersion {
	return BackupKeyVersion(b)
}

func (b BackupKeyVersion) Export() *BackupKeyVersionInternal__ {
	return ((*BackupKeyVersionInternal__)(&b))
}

type Rational struct {
	Infinity bool
	Base     []byte
	Exp      int64
}

type RationalInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Infinity *bool
	Base     *[]byte
	Exp      *int64
}

func (r RationalInternal__) Import() Rational {
	return Rational{
		Infinity: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Infinity),
		Base: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Base),
		Exp: (func(x *int64) (ret int64) {
			if x == nil {
				return ret
			}
			return *x
		})(r.Exp),
	}
}

func (r Rational) Export() *RationalInternal__ {
	return &RationalInternal__{
		Infinity: &r.Infinity,
		Base:     &r.Base,
		Exp:      &r.Exp,
	}
}

func (r *Rational) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *Rational) Decode(dec rpc.Decoder) error {
	var tmp RationalInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *Rational) Bytes() []byte { return nil }

type RationalRange struct {
	Low  Rational
	High Rational
}

type RationalRangeInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Low     *RationalInternal__
	High    *RationalInternal__
}

func (r RationalRangeInternal__) Import() RationalRange {
	return RationalRange{
		Low: (func(x *RationalInternal__) (ret Rational) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.Low),
		High: (func(x *RationalInternal__) (ret Rational) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(r.High),
	}
}

func (r RationalRange) Export() *RationalRangeInternal__ {
	return &RationalRangeInternal__{
		Low:  r.Low.Export(),
		High: r.High.Export(),
	}
}

func (r *RationalRange) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RationalRange) Decode(dec rpc.Decoder) error {
	var tmp RationalRangeInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r *RationalRange) Bytes() []byte { return nil }

type Name string
type NameInternal__ string

func (n Name) Export() *NameInternal__ {
	tmp := ((string)(n))
	return ((*NameInternal__)(&tmp))
}

func (n NameInternal__) Import() Name {
	tmp := (string)(n)
	return Name((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (n *Name) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *Name) Decode(dec rpc.Decoder) error {
	var tmp NameInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n Name) Bytes() []byte {
	return nil
}

type NameHashPreimage struct {
	Name   Name
	HostId HostID
}

type NameHashPreimageInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Name    *NameInternal__
	HostId  *HostIDInternal__
}

func (n NameHashPreimageInternal__) Import() NameHashPreimage {
	return NameHashPreimage{
		Name: (func(x *NameInternal__) (ret Name) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.Name),
		HostId: (func(x *HostIDInternal__) (ret HostID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.HostId),
	}
}

func (n NameHashPreimage) Export() *NameHashPreimageInternal__ {
	return &NameHashPreimageInternal__{
		Name:   n.Name.Export(),
		HostId: n.HostId.Export(),
	}
}

func (n *NameHashPreimage) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NameHashPreimage) Decode(dec rpc.Decoder) error {
	var tmp NameHashPreimageInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

var NameHashPreimageTypeUniqueID = rpc.TypeUniqueID(0xf8556f054c4e036b)

func (n *NameHashPreimage) GetTypeUniqueID() rpc.TypeUniqueID {
	return NameHashPreimageTypeUniqueID
}

func (n *NameHashPreimage) Bytes() []byte { return nil }

type HostBuildStage int

const (
	HostBuildStage_None     HostBuildStage = 0
	HostBuildStage_Complete HostBuildStage = 1
	HostBuildStage_Aborted  HostBuildStage = 2
	HostBuildStage_Stage1   HostBuildStage = 3
	HostBuildStage_Stage2a  HostBuildStage = 4
	HostBuildStage_Stage2b  HostBuildStage = 5
)

var HostBuildStageMap = map[string]HostBuildStage{
	"None":     0,
	"Complete": 1,
	"Aborted":  2,
	"Stage1":   3,
	"Stage2a":  4,
	"Stage2b":  5,
}

var HostBuildStageRevMap = map[HostBuildStage]string{
	0: "None",
	1: "Complete",
	2: "Aborted",
	3: "Stage1",
	4: "Stage2a",
	5: "Stage2b",
}

type HostBuildStageInternal__ HostBuildStage

func (h HostBuildStageInternal__) Import() HostBuildStage {
	return HostBuildStage(h)
}

func (h HostBuildStage) Export() *HostBuildStageInternal__ {
	return ((*HostBuildStageInternal__)(&h))
}

type AutocertState int

const (
	AutocertState_None    AutocertState = 0
	AutocertState_OK      AutocertState = 1
	AutocertState_Failing AutocertState = 2
	AutocertState_Failed  AutocertState = 3
)

var AutocertStateMap = map[string]AutocertState{
	"None":    0,
	"OK":      1,
	"Failing": 2,
	"Failed":  3,
}

var AutocertStateRevMap = map[AutocertState]string{
	0: "None",
	1: "OK",
	2: "Failing",
	3: "Failed",
}

type AutocertStateInternal__ AutocertState

func (a AutocertStateInternal__) Import() AutocertState {
	return AutocertState(a)
}

func (a AutocertState) Export() *AutocertStateInternal__ {
	return ((*AutocertStateInternal__)(&a))
}

type RSAPub struct {
	N []byte
	E uint64
}

type RSAPubInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	N       *[]byte
	E       *uint64
}

func (r RSAPubInternal__) Import() RSAPub {
	return RSAPub{
		N: (func(x *[]byte) (ret []byte) {
			if x == nil {
				return ret
			}
			return *x
		})(r.N),
		E: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(r.E),
	}
}

func (r RSAPub) Export() *RSAPubInternal__ {
	return &RSAPubInternal__{
		N: &r.N,
		E: &r.E,
	}
}

func (r *RSAPub) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *RSAPub) Decode(dec rpc.Decoder) error {
	var tmp RSAPubInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

var RSAPubTypeUniqueID = rpc.TypeUniqueID(0xce5b107c6468c230)

func (r *RSAPub) GetTypeUniqueID() rpc.TypeUniqueID {
	return RSAPubTypeUniqueID
}

func (r *RSAPub) Bytes() []byte { return nil }

type CKSEncKey [32]byte
type CKSEncKeyInternal__ [32]byte

func (c CKSEncKey) Export() *CKSEncKeyInternal__ {
	tmp := (([32]byte)(c))
	return ((*CKSEncKeyInternal__)(&tmp))
}

func (c CKSEncKeyInternal__) Import() CKSEncKey {
	tmp := ([32]byte)(c)
	return CKSEncKey((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *CKSEncKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CKSEncKey) Decode(dec rpc.Decoder) error {
	var tmp CKSEncKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var CKSEncKeyTypeUniqueID = rpc.TypeUniqueID(0x84958839de919b43)

func (c *CKSEncKey) GetTypeUniqueID() rpc.TypeUniqueID {
	return CKSEncKeyTypeUniqueID
}

func (c CKSEncKey) Bytes() []byte {
	return (c)[:]
}

type CKSEncKeyString string
type CKSEncKeyStringInternal__ string

func (c CKSEncKeyString) Export() *CKSEncKeyStringInternal__ {
	tmp := ((string)(c))
	return ((*CKSEncKeyStringInternal__)(&tmp))
}

func (c CKSEncKeyStringInternal__) Import() CKSEncKeyString {
	tmp := (string)(c)
	return CKSEncKeyString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *CKSEncKeyString) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CKSEncKeyString) Decode(dec rpc.Decoder) error {
	var tmp CKSEncKeyStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c CKSEncKeyString) Bytes() []byte {
	return nil
}

type CKSBox struct {
	Key CKSKeyID
	Box SecretBox
}

type CKSBoxInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Key     *CKSKeyIDInternal__
	Box     *SecretBoxInternal__
}

func (c CKSBoxInternal__) Import() CKSBox {
	return CKSBox{
		Key: (func(x *CKSKeyIDInternal__) (ret CKSKeyID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Key),
		Box: (func(x *SecretBoxInternal__) (ret SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(c.Box),
	}
}

func (c CKSBox) Export() *CKSBoxInternal__ {
	return &CKSBoxInternal__{
		Key: c.Key.Export(),
		Box: c.Box.Export(),
	}
}

func (c *CKSBox) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CKSBox) Decode(dec rpc.Decoder) error {
	var tmp CKSBoxInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

func (c *CKSBox) Bytes() []byte { return nil }

type CKSKeyData []byte
type CKSKeyDataInternal__ []byte

func (c CKSKeyData) Export() *CKSKeyDataInternal__ {
	tmp := (([]byte)(c))
	return ((*CKSKeyDataInternal__)(&tmp))
}

func (c CKSKeyDataInternal__) Import() CKSKeyData {
	tmp := ([]byte)(c)
	return CKSKeyData((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (c *CKSKeyData) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CKSKeyData) Decode(dec rpc.Decoder) error {
	var tmp CKSKeyDataInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var CKSKeyDataTypeUniqueID = rpc.TypeUniqueID(0xddc1bec2d4dfc433)

func (c *CKSKeyData) GetTypeUniqueID() rpc.TypeUniqueID {
	return CKSKeyDataTypeUniqueID
}

func (c CKSKeyData) Bytes() []byte {
	return (c)[:]
}

type CKSCertChain struct {
	Certs [][]byte
}

type CKSCertChainInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Certs   *[]([]byte)
}

func (c CKSCertChainInternal__) Import() CKSCertChain {
	return CKSCertChain{
		Certs: (func(x *[]([]byte)) (ret [][]byte) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([][]byte, len(*x))
			for k, v := range *x {
				ret[k] = (func(x *[]byte) (ret []byte) {
					if x == nil {
						return ret
					}
					return *x
				})(&v)
			}
			return ret
		})(c.Certs),
	}
}

func (c CKSCertChain) Export() *CKSCertChainInternal__ {
	return &CKSCertChainInternal__{
		Certs: (func(x [][]byte) *[]([]byte) {
			if len(x) == 0 {
				return nil
			}
			ret := make([]([]byte), len(x))
			copy(ret, x)
			return &ret
		})(c.Certs),
	}
}

func (c *CKSCertChain) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CKSCertChain) Decode(dec rpc.Decoder) error {
	var tmp CKSCertChainInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var CKSCertChainTypeUniqueID = rpc.TypeUniqueID(0xe87182df53b5e710)

func (c *CKSCertChain) GetTypeUniqueID() rpc.TypeUniqueID {
	return CKSCertChainTypeUniqueID
}

func (c *CKSCertChain) Bytes() []byte { return nil }

type CKSAssetType int

const (
	CKSAssetType_None                      CKSAssetType = 0
	CKSAssetType_InternalClientCA          CKSAssetType = 1
	CKSAssetType_ExternalClientCA          CKSAssetType = 2
	CKSAssetType_HostchainFrontendCA       CKSAssetType = 3
	CKSAssetType_BackendCA                 CKSAssetType = 4
	CKSAssetType_HostchainFrontendX509Cert CKSAssetType = 5
	CKSAssetType_RootPKIFrontendX509Cert   CKSAssetType = 6
	CKSAssetType_RootPKIBeaconX509Cert     CKSAssetType = 7
	CKSAssetType_BackendX509Cert           CKSAssetType = 8
)

var CKSAssetTypeMap = map[string]CKSAssetType{
	"None":                      0,
	"InternalClientCA":          1,
	"ExternalClientCA":          2,
	"HostchainFrontendCA":       3,
	"BackendCA":                 4,
	"HostchainFrontendX509Cert": 5,
	"RootPKIFrontendX509Cert":   6,
	"RootPKIBeaconX509Cert":     7,
	"BackendX509Cert":           8,
}

var CKSAssetTypeRevMap = map[CKSAssetType]string{
	0: "None",
	1: "InternalClientCA",
	2: "ExternalClientCA",
	3: "HostchainFrontendCA",
	4: "BackendCA",
	5: "HostchainFrontendX509Cert",
	6: "RootPKIFrontendX509Cert",
	7: "RootPKIBeaconX509Cert",
	8: "BackendX509Cert",
}

type CKSAssetTypeInternal__ CKSAssetType

func (c CKSAssetTypeInternal__) Import() CKSAssetType {
	return CKSAssetType(c)
}

func (c CKSAssetType) Export() *CKSAssetTypeInternal__ {
	return ((*CKSAssetTypeInternal__)(&c))
}

type CKSCertKeyType int

const (
	CKSCertKeyType_Ed25519 CKSCertKeyType = 1
	CKSCertKeyType_X509    CKSCertKeyType = 2
)

var CKSCertKeyTypeMap = map[string]CKSCertKeyType{
	"Ed25519": 1,
	"X509":    2,
}

var CKSCertKeyTypeRevMap = map[CKSCertKeyType]string{
	1: "Ed25519",
	2: "X509",
}

type CKSCertKeyTypeInternal__ CKSCertKeyType

func (c CKSCertKeyTypeInternal__) Import() CKSCertKeyType {
	return CKSCertKeyType(c)
}

func (c CKSCertKeyType) Export() *CKSCertKeyTypeInternal__ {
	return ((*CKSCertKeyTypeInternal__)(&c))
}

type CKSCertKey struct {
	T     CKSCertKeyType
	F_1__ *Ed25519SecretKey `json:"f1,omitempty"`
	F_2__ *[]byte           `json:"f2,omitempty"`
}

type CKSCertKeyInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        CKSCertKeyType
	Switch__ CKSCertKeyInternalSwitch__
}

type CKSCertKeyInternalSwitch__ struct {
	_struct struct{}                    `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *Ed25519SecretKeyInternal__ `codec:"1"`
	F_2__   *[]byte                     `codec:"2"`
}

func (c CKSCertKey) GetT() (ret CKSCertKeyType, err error) {
	switch c.T {
	case CKSCertKeyType_Ed25519:
		if c.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case CKSCertKeyType_X509:
		if c.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	}
	return c.T, nil
}

func (c CKSCertKey) Ed25519() Ed25519SecretKey {
	if c.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if c.T != CKSCertKeyType_Ed25519 {
		panic(fmt.Sprintf("unexpected switch value (%v) when Ed25519 is called", c.T))
	}
	return *c.F_1__
}

func (c CKSCertKey) X509() []byte {
	if c.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if c.T != CKSCertKeyType_X509 {
		panic(fmt.Sprintf("unexpected switch value (%v) when X509 is called", c.T))
	}
	return *c.F_2__
}

func NewCKSCertKeyWithEd25519(v Ed25519SecretKey) CKSCertKey {
	return CKSCertKey{
		T:     CKSCertKeyType_Ed25519,
		F_1__: &v,
	}
}

func NewCKSCertKeyWithX509(v []byte) CKSCertKey {
	return CKSCertKey{
		T:     CKSCertKeyType_X509,
		F_2__: &v,
	}
}

func (c CKSCertKeyInternal__) Import() CKSCertKey {
	return CKSCertKey{
		T: c.T,
		F_1__: (func(x *Ed25519SecretKeyInternal__) *Ed25519SecretKey {
			if x == nil {
				return nil
			}
			tmp := (func(x *Ed25519SecretKeyInternal__) (ret Ed25519SecretKey) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(c.Switch__.F_1__),
		F_2__: c.Switch__.F_2__,
	}
}

func (c CKSCertKey) Export() *CKSCertKeyInternal__ {
	return &CKSCertKeyInternal__{
		T: c.T,
		Switch__: CKSCertKeyInternalSwitch__{
			F_1__: (func(x *Ed25519SecretKey) *Ed25519SecretKeyInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(c.F_1__),
			F_2__: c.F_2__,
		},
	}
}

func (c *CKSCertKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(c.Export())
}

func (c *CKSCertKey) Decode(dec rpc.Decoder) error {
	var tmp CKSCertKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*c = tmp.Import()
	return nil
}

var CKSCertKeyTypeUniqueID = rpc.TypeUniqueID(0xe114c9d651c01a53)

func (c *CKSCertKey) GetTypeUniqueID() rpc.TypeUniqueID {
	return CKSCertKeyTypeUniqueID
}

func (c *CKSCertKey) Bytes() []byte { return nil }

type PKIXKeyBytes []byte
type PKIXKeyBytesInternal__ []byte

func (p PKIXKeyBytes) Export() *PKIXKeyBytesInternal__ {
	tmp := (([]byte)(p))
	return ((*PKIXKeyBytesInternal__)(&tmp))
}

func (p PKIXKeyBytesInternal__) Import() PKIXKeyBytes {
	tmp := ([]byte)(p)
	return PKIXKeyBytes((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *PKIXKeyBytes) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PKIXKeyBytes) Decode(dec rpc.Decoder) error {
	var tmp PKIXKeyBytesInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

var PKIXKeyBytesTypeUniqueID = rpc.TypeUniqueID(0x9a88488af5e5adfa)

func (p *PKIXKeyBytes) GetTypeUniqueID() rpc.TypeUniqueID {
	return PKIXKeyBytesTypeUniqueID
}

func (p PKIXKeyBytes) Bytes() []byte {
	return (p)[:]
}

type Generation uint64
type GenerationInternal__ uint64

func (g Generation) Export() *GenerationInternal__ {
	tmp := ((uint64)(g))
	return ((*GenerationInternal__)(&tmp))
}

func (g GenerationInternal__) Import() Generation {
	tmp := (uint64)(g)
	return Generation((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (g *Generation) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *Generation) Decode(dec rpc.Decoder) error {
	var tmp GenerationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g Generation) Bytes() []byte {
	return nil
}

type Seqno uint64
type SeqnoInternal__ uint64

func (s Seqno) Export() *SeqnoInternal__ {
	tmp := ((uint64)(s))
	return ((*SeqnoInternal__)(&tmp))
}

func (s SeqnoInternal__) Import() Seqno {
	tmp := (uint64)(s)
	return Seqno((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *Seqno) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *Seqno) Decode(dec rpc.Decoder) error {
	var tmp SeqnoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s Seqno) Bytes() []byte {
	return nil
}

type SecretSeed32 [32]byte
type SecretSeed32Internal__ [32]byte

func (s SecretSeed32) Export() *SecretSeed32Internal__ {
	tmp := (([32]byte)(s))
	return ((*SecretSeed32Internal__)(&tmp))
}

func (s SecretSeed32Internal__) Import() SecretSeed32 {
	tmp := ([32]byte)(s)
	return SecretSeed32((func(x *[32]byte) (ret [32]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SecretSeed32) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretSeed32) Decode(dec rpc.Decoder) error {
	var tmp SecretSeed32Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SecretSeed32) Bytes() []byte {
	return (s)[:]
}

type UserSettingsType int

const (
	UserSettingsType_Passphrase UserSettingsType = 0
)

var UserSettingsTypeMap = map[string]UserSettingsType{
	"Passphrase": 0,
}

var UserSettingsTypeRevMap = map[UserSettingsType]string{
	0: "Passphrase",
}

type UserSettingsTypeInternal__ UserSettingsType

func (u UserSettingsTypeInternal__) Import() UserSettingsType {
	return UserSettingsType(u)
}

func (u UserSettingsType) Export() *UserSettingsTypeInternal__ {
	return ((*UserSettingsTypeInternal__)(&u))
}

type PassphraseInfo struct {
	Gen  PassphraseGeneration
	Salt *PassphraseSalt
	Sv   StretchVersion
}

type PassphraseInfoInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Gen     *PassphraseGenerationInternal__
	Salt    *PassphraseSaltInternal__
	Sv      *StretchVersionInternal__
}

func (p PassphraseInfoInternal__) Import() PassphraseInfo {
	return PassphraseInfo{
		Gen: (func(x *PassphraseGenerationInternal__) (ret PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Gen),
		Salt: (func(x *PassphraseSaltInternal__) *PassphraseSalt {
			if x == nil {
				return nil
			}
			tmp := (func(x *PassphraseSaltInternal__) (ret PassphraseSalt) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.Salt),
		Sv: (func(x *StretchVersionInternal__) (ret StretchVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Sv),
	}
}

func (p PassphraseInfo) Export() *PassphraseInfoInternal__ {
	return &PassphraseInfoInternal__{
		Gen: p.Gen.Export(),
		Salt: (func(x *PassphraseSalt) *PassphraseSaltInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(p.Salt),
		Sv: p.Sv.Export(),
	}
}

func (p *PassphraseInfo) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PassphraseInfo) Decode(dec rpc.Decoder) error {
	var tmp PassphraseInfoInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PassphraseInfo) Bytes() []byte { return nil }

type PassphraseGeneration uint64
type PassphraseGenerationInternal__ uint64

func (p PassphraseGeneration) Export() *PassphraseGenerationInternal__ {
	tmp := ((uint64)(p))
	return ((*PassphraseGenerationInternal__)(&tmp))
}

func (p PassphraseGenerationInternal__) Import() PassphraseGeneration {
	tmp := (uint64)(p)
	return PassphraseGeneration((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *PassphraseGeneration) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PassphraseGeneration) Decode(dec rpc.Decoder) error {
	var tmp PassphraseGenerationInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PassphraseGeneration) Bytes() []byte {
	return nil
}

type StretchVersion int

const (
	StretchVersion_TEST StretchVersion = 0
	StretchVersion_V1   StretchVersion = 1
)

var StretchVersionMap = map[string]StretchVersion{
	"TEST": 0,
	"V1":   1,
}

var StretchVersionRevMap = map[StretchVersion]string{
	0: "TEST",
	1: "V1",
}

type StretchVersionInternal__ StretchVersion

func (s StretchVersionInternal__) Import() StretchVersion {
	return StretchVersion(s)
}

func (s StretchVersion) Export() *StretchVersionInternal__ {
	return ((*StretchVersionInternal__)(&s))
}

type PassphraseSalt [16]byte
type PassphraseSaltInternal__ [16]byte

func (p PassphraseSalt) Export() *PassphraseSaltInternal__ {
	tmp := (([16]byte)(p))
	return ((*PassphraseSaltInternal__)(&tmp))
}

func (p PassphraseSaltInternal__) Import() PassphraseSalt {
	tmp := ([16]byte)(p)
	return PassphraseSalt((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (p *PassphraseSalt) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PassphraseSalt) Decode(dec rpc.Decoder) error {
	var tmp PassphraseSaltInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p PassphraseSalt) Bytes() []byte {
	return (p)[:]
}

type SecretKeyStorageType int

const (
	SecretKeyStorageType_PLAINTEXT          SecretKeyStorageType = 0
	SecretKeyStorageType_ENC_PASSPHRASE     SecretKeyStorageType = 1
	SecretKeyStorageType_ENC_MACOS_KEYCHAIN SecretKeyStorageType = 2
	SecretKeyStorageType_ENC_NOISE_FILE     SecretKeyStorageType = 3
	SecretKeyStorageType_ENC_KEYCHAIN       SecretKeyStorageType = 4
)

var SecretKeyStorageTypeMap = map[string]SecretKeyStorageType{
	"PLAINTEXT":          0,
	"ENC_PASSPHRASE":     1,
	"ENC_MACOS_KEYCHAIN": 2,
	"ENC_NOISE_FILE":     3,
	"ENC_KEYCHAIN":       4,
}

var SecretKeyStorageTypeRevMap = map[SecretKeyStorageType]string{
	0: "PLAINTEXT",
	1: "ENC_PASSPHRASE",
	2: "ENC_MACOS_KEYCHAIN",
	3: "ENC_NOISE_FILE",
	4: "ENC_KEYCHAIN",
}

type SecretKeyStorageTypeInternal__ SecretKeyStorageType

func (s SecretKeyStorageTypeInternal__) Import() SecretKeyStorageType {
	return SecretKeyStorageType(s)
}

func (s SecretKeyStorageType) Export() *SecretKeyStorageTypeInternal__ {
	return ((*SecretKeyStorageTypeInternal__)(&s))
}

type URLString string
type URLStringInternal__ string

func (u URLString) Export() *URLStringInternal__ {
	tmp := ((string)(u))
	return ((*URLStringInternal__)(&tmp))
}

func (u URLStringInternal__) Import() URLString {
	tmp := (string)(u)
	return URLString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (u *URLString) Encode(enc rpc.Encoder) error {
	return enc.Encode(u.Export())
}

func (u *URLString) Decode(dec rpc.Decoder) error {
	var tmp URLStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*u = tmp.Import()
	return nil
}

func (u URLString) Bytes() []byte {
	return nil
}

type HMACKeyID [16]byte
type HMACKeyIDInternal__ [16]byte

func (h HMACKeyID) Export() *HMACKeyIDInternal__ {
	tmp := (([16]byte)(h))
	return ((*HMACKeyIDInternal__)(&tmp))
}

func (h HMACKeyIDInternal__) Import() HMACKeyID {
	tmp := ([16]byte)(h)
	return HMACKeyID((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (h *HMACKeyID) Encode(enc rpc.Encoder) error {
	return enc.Encode(h.Export())
}

func (h *HMACKeyID) Decode(dec rpc.Decoder) error {
	var tmp HMACKeyIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*h = tmp.Import()
	return nil
}

func (h HMACKeyID) Bytes() []byte {
	return (h)[:]
}

type Random16 [16]byte
type Random16Internal__ [16]byte

func (r Random16) Export() *Random16Internal__ {
	tmp := (([16]byte)(r))
	return ((*Random16Internal__)(&tmp))
}

func (r Random16Internal__) Import() Random16 {
	tmp := ([16]byte)(r)
	return Random16((func(x *[16]byte) (ret [16]byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (r *Random16) Encode(enc rpc.Encoder) error {
	return enc.Encode(r.Export())
}

func (r *Random16) Decode(dec rpc.Decoder) error {
	var tmp Random16Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*r = tmp.Import()
	return nil
}

func (r Random16) Bytes() []byte {
	return (r)[:]
}

type Date struct {
	Year  uint64
	Month uint64
	Day   uint64
}

type DateInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Year    *uint64
	Month   *uint64
	Day     *uint64
}

func (d DateInternal__) Import() Date {
	return Date{
		Year: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(d.Year),
		Month: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(d.Month),
		Day: (func(x *uint64) (ret uint64) {
			if x == nil {
				return ret
			}
			return *x
		})(d.Day),
	}
}

func (d Date) Export() *DateInternal__ {
	return &DateInternal__{
		Year:  &d.Year,
		Month: &d.Month,
		Day:   &d.Day,
	}
}

func (d *Date) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *Date) Decode(dec rpc.Decoder) error {
	var tmp DateInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d *Date) Bytes() []byte { return nil }

type DbKey []byte
type DbKeyInternal__ []byte

func (d DbKey) Export() *DbKeyInternal__ {
	tmp := (([]byte)(d))
	return ((*DbKeyInternal__)(&tmp))
}

func (d DbKeyInternal__) Import() DbKey {
	tmp := ([]byte)(d)
	return DbKey((func(x *[]byte) (ret []byte) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (d *DbKey) Encode(enc rpc.Encoder) error {
	return enc.Encode(d.Export())
}

func (d *DbKey) Decode(dec rpc.Decoder) error {
	var tmp DbKeyInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*d = tmp.Import()
	return nil
}

func (d DbKey) Bytes() []byte {
	return (d)[:]
}

func init() {
	rpc.AddUnique(HostIDTypeUniqueID)
	rpc.AddUnique(FQUserTypeUniqueID)
	rpc.AddUnique(FQUserAndRoleTypeUniqueID)
	rpc.AddUnique(ECDSACompressedPublicKeyTypeUniqueID)
	rpc.AddUnique(TreeLocationTypeUniqueID)
	rpc.AddUnique(TreeLocationCommitmentTypeUniqueID)
	rpc.AddUnique(BoxTypeUniqueID)
	rpc.AddUnique(TempDHKeySigTemplateTypeUniqueID)
	rpc.AddUnique(FQTeamParsedTypeUniqueID)
	rpc.AddUnique(HEPKv1TypeUniqueID)
	rpc.AddUnique(HEPKTypeUniqueID)
	rpc.AddUnique(HybridSecretKeySHA3PayloadTypeUniqueID)
	rpc.AddUnique(BackupSeedTypeUniqueID)
	rpc.AddUnique(NameHashPreimageTypeUniqueID)
	rpc.AddUnique(RSAPubTypeUniqueID)
	rpc.AddUnique(CKSEncKeyTypeUniqueID)
	rpc.AddUnique(CKSKeyDataTypeUniqueID)
	rpc.AddUnique(CKSCertChainTypeUniqueID)
	rpc.AddUnique(CKSCertKeyTypeUniqueID)
	rpc.AddUnique(PKIXKeyBytesTypeUniqueID)
}
