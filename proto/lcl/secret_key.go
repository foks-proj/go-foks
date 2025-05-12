// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lcl/secret_key.snowp

package lcl

import (
	"errors"
	"fmt"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type SecretKeyBundleVersion int

const (
	SecretKeyBundleVersion_V1 SecretKeyBundleVersion = 1
)

var SecretKeyBundleVersionMap = map[string]SecretKeyBundleVersion{
	"V1": 1,
}

var SecretKeyBundleVersionRevMap = map[SecretKeyBundleVersion]string{
	1: "V1",
}

type SecretKeyBundleVersionInternal__ SecretKeyBundleVersion

func (s SecretKeyBundleVersionInternal__) Import() SecretKeyBundleVersion {
	return SecretKeyBundleVersion(s)
}

func (s SecretKeyBundleVersion) Export() *SecretKeyBundleVersionInternal__ {
	return ((*SecretKeyBundleVersionInternal__)(&s))
}

type SecretKeyBundle struct {
	V     SecretKeyBundleVersion
	F_1__ *lib.SecretSeed32 `json:"f1,omitempty"`
}

type SecretKeyBundleInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        SecretKeyBundleVersion
	Switch__ SecretKeyBundleInternalSwitch__
}

type SecretKeyBundleInternalSwitch__ struct {
	_struct struct{}                    `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_1__   *lib.SecretSeed32Internal__ `codec:"1"`
}

func (s SecretKeyBundle) GetV() (ret SecretKeyBundleVersion, err error) {
	switch s.V {
	case SecretKeyBundleVersion_V1:
		if s.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	}
	return s.V, nil
}

func (s SecretKeyBundle) V1() lib.SecretSeed32 {
	if s.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.V != SecretKeyBundleVersion_V1 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V1 is called", s.V))
	}
	return *s.F_1__
}

func NewSecretKeyBundleWithV1(v lib.SecretSeed32) SecretKeyBundle {
	return SecretKeyBundle{
		V:     SecretKeyBundleVersion_V1,
		F_1__: &v,
	}
}

func (s SecretKeyBundleInternal__) Import() SecretKeyBundle {
	return SecretKeyBundle{
		V: s.V,
		F_1__: (func(x *lib.SecretSeed32Internal__) *lib.SecretSeed32 {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.SecretSeed32Internal__) (ret lib.SecretSeed32) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_1__),
	}
}

func (s SecretKeyBundle) Export() *SecretKeyBundleInternal__ {
	return &SecretKeyBundleInternal__{
		V: s.V,
		Switch__: SecretKeyBundleInternalSwitch__{
			F_1__: (func(x *lib.SecretSeed32) *lib.SecretSeed32Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_1__),
		},
	}
}

func (s *SecretKeyBundle) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretKeyBundle) Decode(dec rpc.Decoder) error {
	var tmp SecretKeyBundleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

var SecretKeyBundleTypeUniqueID = rpc.TypeUniqueID(0x8456933bbb8a54ae)

func (s *SecretKeyBundle) GetTypeUniqueID() rpc.TypeUniqueID {
	return SecretKeyBundleTypeUniqueID
}

func (s *SecretKeyBundle) Bytes() []byte { return nil }

type SecretStoreVersion int

const (
	SecretStoreVersion_V2 SecretStoreVersion = 2
)

var SecretStoreVersionMap = map[string]SecretStoreVersion{
	"V2": 2,
}

var SecretStoreVersionRevMap = map[SecretStoreVersion]string{
	2: "V2",
}

type SecretStoreVersionInternal__ SecretStoreVersion

func (s SecretStoreVersionInternal__) Import() SecretStoreVersion {
	return SecretStoreVersion(s)
}

func (s SecretStoreVersion) Export() *SecretStoreVersionInternal__ {
	return ((*SecretStoreVersionInternal__)(&s))
}

type PassphraseEncryptedSecretKeyBundle struct {
	Ppgen          lib.PassphraseGeneration
	Salt           lib.PassphraseSalt
	StretchVersion lib.StretchVersion
	SecretBox      lib.SecretBox
}

type PassphraseEncryptedSecretKeyBundleInternal__ struct {
	_struct        struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Ppgen          *lib.PassphraseGenerationInternal__
	Salt           *lib.PassphraseSaltInternal__
	StretchVersion *lib.StretchVersionInternal__
	SecretBox      *lib.SecretBoxInternal__
}

func (p PassphraseEncryptedSecretKeyBundleInternal__) Import() PassphraseEncryptedSecretKeyBundle {
	return PassphraseEncryptedSecretKeyBundle{
		Ppgen: (func(x *lib.PassphraseGenerationInternal__) (ret lib.PassphraseGeneration) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Ppgen),
		Salt: (func(x *lib.PassphraseSaltInternal__) (ret lib.PassphraseSalt) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Salt),
		StretchVersion: (func(x *lib.StretchVersionInternal__) (ret lib.StretchVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.StretchVersion),
		SecretBox: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.SecretBox),
	}
}

func (p PassphraseEncryptedSecretKeyBundle) Export() *PassphraseEncryptedSecretKeyBundleInternal__ {
	return &PassphraseEncryptedSecretKeyBundleInternal__{
		Ppgen:          p.Ppgen.Export(),
		Salt:           p.Salt.Export(),
		StretchVersion: p.StretchVersion.Export(),
		SecretBox:      p.SecretBox.Export(),
	}
}

func (p *PassphraseEncryptedSecretKeyBundle) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *PassphraseEncryptedSecretKeyBundle) Decode(dec rpc.Decoder) error {
	var tmp PassphraseEncryptedSecretKeyBundleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *PassphraseEncryptedSecretKeyBundle) Bytes() []byte { return nil }

type MacOSKeychainEncryptedSecretBundle struct {
	Account   string
	Service   string
	SecretBox lib.SecretBox
}

type MacOSKeychainEncryptedSecretBundleInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Account   *string
	Service   *string
	SecretBox *lib.SecretBoxInternal__
}

func (m MacOSKeychainEncryptedSecretBundleInternal__) Import() MacOSKeychainEncryptedSecretBundle {
	return MacOSKeychainEncryptedSecretBundle{
		Account: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Account),
		Service: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(m.Service),
		SecretBox: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(m.SecretBox),
	}
}

func (m MacOSKeychainEncryptedSecretBundle) Export() *MacOSKeychainEncryptedSecretBundleInternal__ {
	return &MacOSKeychainEncryptedSecretBundleInternal__{
		Account:   &m.Account,
		Service:   &m.Service,
		SecretBox: m.SecretBox.Export(),
	}
}

func (m *MacOSKeychainEncryptedSecretBundle) Encode(enc rpc.Encoder) error {
	return enc.Encode(m.Export())
}

func (m *MacOSKeychainEncryptedSecretBundle) Decode(dec rpc.Decoder) error {
	var tmp MacOSKeychainEncryptedSecretBundleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*m = tmp.Import()
	return nil
}

func (m *MacOSKeychainEncryptedSecretBundle) Bytes() []byte { return nil }

type NoiseFileEncryptedSecretBundle struct {
	Filename  string
	SecretBox lib.SecretBox
}

type NoiseFileEncryptedSecretBundleInternal__ struct {
	_struct   struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Filename  *string
	SecretBox *lib.SecretBoxInternal__
}

func (n NoiseFileEncryptedSecretBundleInternal__) Import() NoiseFileEncryptedSecretBundle {
	return NoiseFileEncryptedSecretBundle{
		Filename: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(n.Filename),
		SecretBox: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(n.SecretBox),
	}
}

func (n NoiseFileEncryptedSecretBundle) Export() *NoiseFileEncryptedSecretBundleInternal__ {
	return &NoiseFileEncryptedSecretBundleInternal__{
		Filename:  &n.Filename,
		SecretBox: n.SecretBox.Export(),
	}
}

func (n *NoiseFileEncryptedSecretBundle) Encode(enc rpc.Encoder) error {
	return enc.Encode(n.Export())
}

func (n *NoiseFileEncryptedSecretBundle) Decode(dec rpc.Decoder) error {
	var tmp NoiseFileEncryptedSecretBundleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*n = tmp.Import()
	return nil
}

func (n *NoiseFileEncryptedSecretBundle) Bytes() []byte { return nil }

type KeychainEncryptedSecretBundle struct {
	Service   string
	SecretBox lib.SecretBox
}

type KeychainEncryptedSecretBundleInternal__ struct {
	_struct     struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Deprecated0 *struct{}
	Service     *string
	SecretBox   *lib.SecretBoxInternal__
}

func (k KeychainEncryptedSecretBundleInternal__) Import() KeychainEncryptedSecretBundle {
	return KeychainEncryptedSecretBundle{
		Service: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(k.Service),
		SecretBox: (func(x *lib.SecretBoxInternal__) (ret lib.SecretBox) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(k.SecretBox),
	}
}

func (k KeychainEncryptedSecretBundle) Export() *KeychainEncryptedSecretBundleInternal__ {
	return &KeychainEncryptedSecretBundleInternal__{
		Service:   &k.Service,
		SecretBox: k.SecretBox.Export(),
	}
}

func (k *KeychainEncryptedSecretBundle) Encode(enc rpc.Encoder) error {
	return enc.Encode(k.Export())
}

func (k *KeychainEncryptedSecretBundle) Decode(dec rpc.Decoder) error {
	var tmp KeychainEncryptedSecretBundleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*k = tmp.Import()
	return nil
}

func (k *KeychainEncryptedSecretBundle) Bytes() []byte { return nil }

type StoredSecretKeyBundle struct {
	T     lib.SecretKeyStorageType
	F_0__ *SecretKeyBundle                    `json:"f0,omitempty"`
	F_1__ *PassphraseEncryptedSecretKeyBundle `json:"f1,omitempty"`
	F_2__ *MacOSKeychainEncryptedSecretBundle `json:"f2,omitempty"`
	F_3__ *NoiseFileEncryptedSecretBundle     `json:"f3,omitempty"`
	F_4__ *KeychainEncryptedSecretBundle      `json:"f4,omitempty"`
}

type StoredSecretKeyBundleInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	T        lib.SecretKeyStorageType
	Switch__ StoredSecretKeyBundleInternalSwitch__
}

type StoredSecretKeyBundleInternalSwitch__ struct {
	_struct struct{}                                      `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_0__   *SecretKeyBundleInternal__                    `codec:"0"`
	F_1__   *PassphraseEncryptedSecretKeyBundleInternal__ `codec:"1"`
	F_2__   *MacOSKeychainEncryptedSecretBundleInternal__ `codec:"2"`
	F_3__   *NoiseFileEncryptedSecretBundleInternal__     `codec:"3"`
	F_4__   *KeychainEncryptedSecretBundleInternal__      `codec:"4"`
}

func (s StoredSecretKeyBundle) GetT() (ret lib.SecretKeyStorageType, err error) {
	switch s.T {
	case lib.SecretKeyStorageType_PLAINTEXT:
		if s.F_0__ == nil {
			return ret, errors.New("unexpected nil case for F_0__")
		}
	case lib.SecretKeyStorageType_ENC_PASSPHRASE:
		if s.F_1__ == nil {
			return ret, errors.New("unexpected nil case for F_1__")
		}
	case lib.SecretKeyStorageType_ENC_MACOS_KEYCHAIN:
		if s.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	case lib.SecretKeyStorageType_ENC_NOISE_FILE:
		if s.F_3__ == nil {
			return ret, errors.New("unexpected nil case for F_3__")
		}
	case lib.SecretKeyStorageType_ENC_KEYCHAIN:
		if s.F_4__ == nil {
			return ret, errors.New("unexpected nil case for F_4__")
		}
	}
	return s.T, nil
}

func (s StoredSecretKeyBundle) Plaintext() SecretKeyBundle {
	if s.F_0__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.T != lib.SecretKeyStorageType_PLAINTEXT {
		panic(fmt.Sprintf("unexpected switch value (%v) when Plaintext is called", s.T))
	}
	return *s.F_0__
}

func (s StoredSecretKeyBundle) EncPassphrase() PassphraseEncryptedSecretKeyBundle {
	if s.F_1__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.T != lib.SecretKeyStorageType_ENC_PASSPHRASE {
		panic(fmt.Sprintf("unexpected switch value (%v) when EncPassphrase is called", s.T))
	}
	return *s.F_1__
}

func (s StoredSecretKeyBundle) EncMacosKeychain() MacOSKeychainEncryptedSecretBundle {
	if s.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.T != lib.SecretKeyStorageType_ENC_MACOS_KEYCHAIN {
		panic(fmt.Sprintf("unexpected switch value (%v) when EncMacosKeychain is called", s.T))
	}
	return *s.F_2__
}

func (s StoredSecretKeyBundle) EncNoiseFile() NoiseFileEncryptedSecretBundle {
	if s.F_3__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.T != lib.SecretKeyStorageType_ENC_NOISE_FILE {
		panic(fmt.Sprintf("unexpected switch value (%v) when EncNoiseFile is called", s.T))
	}
	return *s.F_3__
}

func (s StoredSecretKeyBundle) EncKeychain() KeychainEncryptedSecretBundle {
	if s.F_4__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.T != lib.SecretKeyStorageType_ENC_KEYCHAIN {
		panic(fmt.Sprintf("unexpected switch value (%v) when EncKeychain is called", s.T))
	}
	return *s.F_4__
}

func NewStoredSecretKeyBundleWithPlaintext(v SecretKeyBundle) StoredSecretKeyBundle {
	return StoredSecretKeyBundle{
		T:     lib.SecretKeyStorageType_PLAINTEXT,
		F_0__: &v,
	}
}

func NewStoredSecretKeyBundleWithEncPassphrase(v PassphraseEncryptedSecretKeyBundle) StoredSecretKeyBundle {
	return StoredSecretKeyBundle{
		T:     lib.SecretKeyStorageType_ENC_PASSPHRASE,
		F_1__: &v,
	}
}

func NewStoredSecretKeyBundleWithEncMacosKeychain(v MacOSKeychainEncryptedSecretBundle) StoredSecretKeyBundle {
	return StoredSecretKeyBundle{
		T:     lib.SecretKeyStorageType_ENC_MACOS_KEYCHAIN,
		F_2__: &v,
	}
}

func NewStoredSecretKeyBundleWithEncNoiseFile(v NoiseFileEncryptedSecretBundle) StoredSecretKeyBundle {
	return StoredSecretKeyBundle{
		T:     lib.SecretKeyStorageType_ENC_NOISE_FILE,
		F_3__: &v,
	}
}

func NewStoredSecretKeyBundleWithEncKeychain(v KeychainEncryptedSecretBundle) StoredSecretKeyBundle {
	return StoredSecretKeyBundle{
		T:     lib.SecretKeyStorageType_ENC_KEYCHAIN,
		F_4__: &v,
	}
}

func (s StoredSecretKeyBundleInternal__) Import() StoredSecretKeyBundle {
	return StoredSecretKeyBundle{
		T: s.T,
		F_0__: (func(x *SecretKeyBundleInternal__) *SecretKeyBundle {
			if x == nil {
				return nil
			}
			tmp := (func(x *SecretKeyBundleInternal__) (ret SecretKeyBundle) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_0__),
		F_1__: (func(x *PassphraseEncryptedSecretKeyBundleInternal__) *PassphraseEncryptedSecretKeyBundle {
			if x == nil {
				return nil
			}
			tmp := (func(x *PassphraseEncryptedSecretKeyBundleInternal__) (ret PassphraseEncryptedSecretKeyBundle) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_1__),
		F_2__: (func(x *MacOSKeychainEncryptedSecretBundleInternal__) *MacOSKeychainEncryptedSecretBundle {
			if x == nil {
				return nil
			}
			tmp := (func(x *MacOSKeychainEncryptedSecretBundleInternal__) (ret MacOSKeychainEncryptedSecretBundle) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_2__),
		F_3__: (func(x *NoiseFileEncryptedSecretBundleInternal__) *NoiseFileEncryptedSecretBundle {
			if x == nil {
				return nil
			}
			tmp := (func(x *NoiseFileEncryptedSecretBundleInternal__) (ret NoiseFileEncryptedSecretBundle) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_3__),
		F_4__: (func(x *KeychainEncryptedSecretBundleInternal__) *KeychainEncryptedSecretBundle {
			if x == nil {
				return nil
			}
			tmp := (func(x *KeychainEncryptedSecretBundleInternal__) (ret KeychainEncryptedSecretBundle) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_4__),
	}
}

func (s StoredSecretKeyBundle) Export() *StoredSecretKeyBundleInternal__ {
	return &StoredSecretKeyBundleInternal__{
		T: s.T,
		Switch__: StoredSecretKeyBundleInternalSwitch__{
			F_0__: (func(x *SecretKeyBundle) *SecretKeyBundleInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_0__),
			F_1__: (func(x *PassphraseEncryptedSecretKeyBundle) *PassphraseEncryptedSecretKeyBundleInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_1__),
			F_2__: (func(x *MacOSKeychainEncryptedSecretBundle) *MacOSKeychainEncryptedSecretBundleInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_2__),
			F_3__: (func(x *NoiseFileEncryptedSecretBundle) *NoiseFileEncryptedSecretBundleInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_3__),
			F_4__: (func(x *KeychainEncryptedSecretBundle) *KeychainEncryptedSecretBundleInternal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_4__),
		},
	}
}

func (s *StoredSecretKeyBundle) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *StoredSecretKeyBundle) Decode(dec rpc.Decoder) error {
	var tmp StoredSecretKeyBundleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *StoredSecretKeyBundle) Bytes() []byte { return nil }

type SecretKeyBundleMinorVersion uint64
type SecretKeyBundleMinorVersionInternal__ uint64

func (s SecretKeyBundleMinorVersion) Export() *SecretKeyBundleMinorVersionInternal__ {
	tmp := ((uint64)(s))
	return ((*SecretKeyBundleMinorVersionInternal__)(&tmp))
}

func (s SecretKeyBundleMinorVersionInternal__) Import() SecretKeyBundleMinorVersion {
	tmp := (uint64)(s)
	return SecretKeyBundleMinorVersion((func(x *uint64) (ret uint64) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SecretKeyBundleMinorVersion) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretKeyBundleMinorVersion) Decode(dec rpc.Decoder) error {
	var tmp SecretKeyBundleMinorVersionInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SecretKeyBundleMinorVersion) Bytes() []byte {
	return nil
}

type LabeledSecretKeyBundle struct {
	Fqur         lib.FQUserAndRole
	KeyID        lib.DeviceID
	SelfTok      lib.PermissionToken
	Bundle       StoredSecretKeyBundle
	Provisional  bool
	Ctime        lib.Time
	Mtime        lib.Time
	MinorVersion SecretKeyBundleMinorVersion
}

type LabeledSecretKeyBundleInternal__ struct {
	_struct      struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqur         *lib.FQUserAndRoleInternal__
	KeyID        *lib.DeviceIDInternal__
	SelfTok      *lib.PermissionTokenInternal__
	Bundle       *StoredSecretKeyBundleInternal__
	Provisional  *bool
	Ctime        *lib.TimeInternal__
	Mtime        *lib.TimeInternal__
	MinorVersion *SecretKeyBundleMinorVersionInternal__
}

func (l LabeledSecretKeyBundleInternal__) Import() LabeledSecretKeyBundle {
	return LabeledSecretKeyBundle{
		Fqur: (func(x *lib.FQUserAndRoleInternal__) (ret lib.FQUserAndRole) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Fqur),
		KeyID: (func(x *lib.DeviceIDInternal__) (ret lib.DeviceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.KeyID),
		SelfTok: (func(x *lib.PermissionTokenInternal__) (ret lib.PermissionToken) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.SelfTok),
		Bundle: (func(x *StoredSecretKeyBundleInternal__) (ret StoredSecretKeyBundle) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Bundle),
		Provisional: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(l.Provisional),
		Ctime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Ctime),
		Mtime: (func(x *lib.TimeInternal__) (ret lib.Time) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.Mtime),
		MinorVersion: (func(x *SecretKeyBundleMinorVersionInternal__) (ret SecretKeyBundleMinorVersion) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(l.MinorVersion),
	}
}

func (l LabeledSecretKeyBundle) Export() *LabeledSecretKeyBundleInternal__ {
	return &LabeledSecretKeyBundleInternal__{
		Fqur:         l.Fqur.Export(),
		KeyID:        l.KeyID.Export(),
		SelfTok:      l.SelfTok.Export(),
		Bundle:       l.Bundle.Export(),
		Provisional:  &l.Provisional,
		Ctime:        l.Ctime.Export(),
		Mtime:        l.Mtime.Export(),
		MinorVersion: l.MinorVersion.Export(),
	}
}

func (l *LabeledSecretKeyBundle) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LabeledSecretKeyBundle) Decode(dec rpc.Decoder) error {
	var tmp LabeledSecretKeyBundleInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LabeledSecretKeyBundle) Bytes() []byte { return nil }

type FQUserRoleAndDeviceID struct {
	Fqur  lib.FQUserAndRole
	KeyID lib.DeviceID
}

type FQUserRoleAndDeviceIDInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Fqur    *lib.FQUserAndRoleInternal__
	KeyID   *lib.DeviceIDInternal__
}

func (f FQUserRoleAndDeviceIDInternal__) Import() FQUserRoleAndDeviceID {
	return FQUserRoleAndDeviceID{
		Fqur: (func(x *lib.FQUserAndRoleInternal__) (ret lib.FQUserAndRole) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.Fqur),
		KeyID: (func(x *lib.DeviceIDInternal__) (ret lib.DeviceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(f.KeyID),
	}
}

func (f FQUserRoleAndDeviceID) Export() *FQUserRoleAndDeviceIDInternal__ {
	return &FQUserRoleAndDeviceIDInternal__{
		Fqur:  f.Fqur.Export(),
		KeyID: f.KeyID.Export(),
	}
}

func (f *FQUserRoleAndDeviceID) Encode(enc rpc.Encoder) error {
	return enc.Encode(f.Export())
}

func (f *FQUserRoleAndDeviceID) Decode(dec rpc.Decoder) error {
	var tmp FQUserRoleAndDeviceIDInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*f = tmp.Import()
	return nil
}

func (f *FQUserRoleAndDeviceID) Bytes() []byte { return nil }

type SecretKeyKeychainLabelV1 struct {
	Liid lib.LocalInstanceID
	Fqur lib.FQUserAndRole
}

type SecretKeyKeychainLabelV1Internal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Liid    *lib.LocalInstanceIDInternal__
	Fqur    *lib.FQUserAndRoleInternal__
}

func (s SecretKeyKeychainLabelV1Internal__) Import() SecretKeyKeychainLabelV1 {
	return SecretKeyKeychainLabelV1{
		Liid: (func(x *lib.LocalInstanceIDInternal__) (ret lib.LocalInstanceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Liid),
		Fqur: (func(x *lib.FQUserAndRoleInternal__) (ret lib.FQUserAndRole) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Fqur),
	}
}

func (s SecretKeyKeychainLabelV1) Export() *SecretKeyKeychainLabelV1Internal__ {
	return &SecretKeyKeychainLabelV1Internal__{
		Liid: s.Liid.Export(),
		Fqur: s.Fqur.Export(),
	}
}

func (s *SecretKeyKeychainLabelV1) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretKeyKeychainLabelV1) Decode(dec rpc.Decoder) error {
	var tmp SecretKeyKeychainLabelV1Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SecretKeyKeychainLabelV1) Bytes() []byte { return nil }

type SecretKeyKeychainLabelV2 struct {
	Liid lib.LocalInstanceID
	Fqu  lib.FQUser
	Did  lib.DeviceID
}

type SecretKeyKeychainLabelV2Internal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Liid    *lib.LocalInstanceIDInternal__
	Fqu     *lib.FQUserInternal__
	Did     *lib.DeviceIDInternal__
}

func (s SecretKeyKeychainLabelV2Internal__) Import() SecretKeyKeychainLabelV2 {
	return SecretKeyKeychainLabelV2{
		Liid: (func(x *lib.LocalInstanceIDInternal__) (ret lib.LocalInstanceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Liid),
		Fqu: (func(x *lib.FQUserInternal__) (ret lib.FQUser) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Fqu),
		Did: (func(x *lib.DeviceIDInternal__) (ret lib.DeviceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Did),
	}
}

func (s SecretKeyKeychainLabelV2) Export() *SecretKeyKeychainLabelV2Internal__ {
	return &SecretKeyKeychainLabelV2Internal__{
		Liid: s.Liid.Export(),
		Fqu:  s.Fqu.Export(),
		Did:  s.Did.Export(),
	}
}

func (s *SecretKeyKeychainLabelV2) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretKeyKeychainLabelV2) Decode(dec rpc.Decoder) error {
	var tmp SecretKeyKeychainLabelV2Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SecretKeyKeychainLabelV2) Bytes() []byte { return nil }

type SecretKeyKeychainLabelString string
type SecretKeyKeychainLabelStringInternal__ string

func (s SecretKeyKeychainLabelString) Export() *SecretKeyKeychainLabelStringInternal__ {
	tmp := ((string)(s))
	return ((*SecretKeyKeychainLabelStringInternal__)(&tmp))
}

func (s SecretKeyKeychainLabelStringInternal__) Import() SecretKeyKeychainLabelString {
	tmp := (string)(s)
	return SecretKeyKeychainLabelString((func(x *string) (ret string) {
		if x == nil {
			return ret
		}
		return *x
	})(&tmp))
}

func (s *SecretKeyKeychainLabelString) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretKeyKeychainLabelString) Decode(dec rpc.Decoder) error {
	var tmp SecretKeyKeychainLabelStringInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s SecretKeyKeychainLabelString) Bytes() []byte {
	return nil
}

type SecretStoreV2 struct {
	Id   lib.LocalInstanceID
	Keys []LabeledSecretKeyBundle
}

type SecretStoreV2Internal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Id      *lib.LocalInstanceIDInternal__
	Keys    *[](*LabeledSecretKeyBundleInternal__)
}

func (s SecretStoreV2Internal__) Import() SecretStoreV2 {
	return SecretStoreV2{
		Id: (func(x *lib.LocalInstanceIDInternal__) (ret lib.LocalInstanceID) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(s.Id),
		Keys: (func(x *[](*LabeledSecretKeyBundleInternal__)) (ret []LabeledSecretKeyBundle) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]LabeledSecretKeyBundle, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *LabeledSecretKeyBundleInternal__) (ret LabeledSecretKeyBundle) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(s.Keys),
	}
}

func (s SecretStoreV2) Export() *SecretStoreV2Internal__ {
	return &SecretStoreV2Internal__{
		Id: s.Id.Export(),
		Keys: (func(x []LabeledSecretKeyBundle) *[](*LabeledSecretKeyBundleInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*LabeledSecretKeyBundleInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(s.Keys),
	}
}

func (s *SecretStoreV2) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretStoreV2) Decode(dec rpc.Decoder) error {
	var tmp SecretStoreV2Internal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SecretStoreV2) Bytes() []byte { return nil }

type SecretStore struct {
	V     SecretStoreVersion
	F_2__ *SecretStoreV2 `json:"f2,omitempty"`
}

type SecretStoreInternal__ struct {
	_struct  struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	V        SecretStoreVersion
	Switch__ SecretStoreInternalSwitch__
}

type SecretStoreInternalSwitch__ struct {
	_struct struct{}                 `codec:",omitempty"` //lint:ignore U1000 msgpack internal field
	F_2__   *SecretStoreV2Internal__ `codec:"2"`
}

func (s SecretStore) GetV() (ret SecretStoreVersion, err error) {
	switch s.V {
	case SecretStoreVersion_V2:
		if s.F_2__ == nil {
			return ret, errors.New("unexpected nil case for F_2__")
		}
	}
	return s.V, nil
}

func (s SecretStore) V2() SecretStoreV2 {
	if s.F_2__ == nil {
		panic("unexepected nil case; should have been checked")
	}
	if s.V != SecretStoreVersion_V2 {
		panic(fmt.Sprintf("unexpected switch value (%v) when V2 is called", s.V))
	}
	return *s.F_2__
}

func NewSecretStoreWithV2(v SecretStoreV2) SecretStore {
	return SecretStore{
		V:     SecretStoreVersion_V2,
		F_2__: &v,
	}
}

func (s SecretStoreInternal__) Import() SecretStore {
	return SecretStore{
		V: s.V,
		F_2__: (func(x *SecretStoreV2Internal__) *SecretStoreV2 {
			if x == nil {
				return nil
			}
			tmp := (func(x *SecretStoreV2Internal__) (ret SecretStoreV2) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(s.Switch__.F_2__),
	}
}

func (s SecretStore) Export() *SecretStoreInternal__ {
	return &SecretStoreInternal__{
		V: s.V,
		Switch__: SecretStoreInternalSwitch__{
			F_2__: (func(x *SecretStoreV2) *SecretStoreV2Internal__ {
				if x == nil {
					return nil
				}
				return (*x).Export()
			})(s.F_2__),
		},
	}
}

func (s *SecretStore) Encode(enc rpc.Encoder) error {
	return enc.Encode(s.Export())
}

func (s *SecretStore) Decode(dec rpc.Decoder) error {
	var tmp SecretStoreInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*s = tmp.Import()
	return nil
}

func (s *SecretStore) Bytes() []byte { return nil }

func init() {
	rpc.AddUnique(SecretKeyBundleTypeUniqueID)
}
