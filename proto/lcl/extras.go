// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lcl

import (
	"encoding/json"
	"fmt"
	"strings"

	lib "github.com/foks-proj/go-foks/proto/lib"
)

// HasData returns true if the given secret store object has any data.
// It will return false on SecretStores from the future, since it only
// knows about SecretStoreVersion_V1.
func (s *SecretStore) HasData() bool {
	if s == nil {
		return false
	}
	vers, err := s.GetV()
	if err != nil {
		return false
	}
	switch vers {
	case SecretStoreVersion_V2:
		return s.V2().HasData()
	default:
		return false
	}
}

func (s SecretStoreV2) HasData() bool {
	return len(s.Keys) > 0
}

func (d DataType) ExportToDB() int { return int(d) }

func (s *UserSigchainState) LookupDevice(e lib.EntityID) *lib.DeviceInfo {
	for _, d := range s.Devices {
		if d.Key.Member.Id.Entity.Eq(e) {
			return &d
		}
	}
	return nil
}

func (r RoleAndGenus) DbKey() (lib.DbKey, error) {
	s, err := r.Role.ShortStringErr()
	if err != nil {
		return lib.DbKey{}, err
	}
	i := fmt.Sprintf("%d", int(r.Genus))
	s += "-" + i
	return []byte(s), nil
}

func (k PUKBoxDBKey) DbKey() (lib.DbKey, error) {
	rg, err := k.Rg.DbKey()
	if err != nil {
		return lib.DbKey{}, err
	}
	eid, err := k.Eid.StringErr()
	if err != nil {
		return lib.DbKey{}, err
	}
	return []byte(fmt.Sprintf("%s-%s", rg, eid)), nil
}

func (s SecretKeyKeychainLabelV2) StringErr() (string, error) {
	u, err := s.Fqu.StringErr()
	if err != nil {
		return "", err
	}
	iid, err := s.Liid.StringErr()
	if err != nil {
		return "", err
	}
	did, err := s.Did.StringErr()
	if err != nil {
		return "", err
	}
	parts := []string{iid, did, u}
	return strings.Join(parts, "-"), nil
}

func (s SecretKeyKeychainLabelV1) StringErr() (string, error) {
	p1, err := s.Fqur.StringErr()
	if err != nil {
		return "", err
	}
	if s.Liid.IsZero() {
		return p1, nil
	}
	p0 := s.Liid.String()
	return fmt.Sprintf("%s-%s", p0, p1), nil
}

func (s StoredSecretKeyBundle) StripSecrets() (StoredSecretKeyBundle, error) {
	t, err := s.GetT()
	if err != nil {
		return s, err
	}
	switch t {
	case lib.SecretKeyStorageType_PLAINTEXT:
		return NewStoredSecretKeyBundleWithPlaintext(SecretKeyBundle{}), nil
	case lib.SecretKeyStorageType_ENC_NOISE_FILE:
		nf := s.EncNoiseFile()
		nf.SecretBox = lib.SecretBox{}
		return NewStoredSecretKeyBundleWithEncNoiseFile(nf), nil
	case lib.SecretKeyStorageType_ENC_MACOS_KEYCHAIN:
		mac := s.EncMacosKeychain()
		mac.SecretBox = lib.SecretBox{}
		return NewStoredSecretKeyBundleWithEncMacosKeychain(mac), nil
	case lib.SecretKeyStorageType_ENC_PASSPHRASE:
		pp := s.EncPassphrase()
		pp.SecretBox = lib.SecretBox{}
		return NewStoredSecretKeyBundleWithEncPassphrase(pp), nil
	case lib.SecretKeyStorageType_ENC_KEYCHAIN:
		kc := s.EncKeychain()
		kc.SecretBox = lib.SecretBox{}
		return NewStoredSecretKeyBundleWithEncKeychain(kc), nil
	default:
		return s, lib.DataError(
			fmt.Sprintf("bad type of secret key bundle (%d)", t),
		)
	}
}

func (a NamedFQParty) CompareString() string {
	h := string(a.Host)
	if len(h) == 0 {
		var err error
		h, err = a.Fqp.Host.StringErr()
		if err != nil {
			h = "-"
		}
	}
	p := string(a.Name)
	if len(p) == 0 {
		var err error
		p, err = a.Fqp.Party.EntityID().StringErr()
		if err != nil {
			p = "-"
		}
	}
	return fmt.Sprintf("%s>%s", h, p)
}

func (a NamedFQParty) Cmp(b NamedFQParty) int {
	return strings.Compare(a.CompareString(), b.CompareString())
}

func (s TokRoleString) Parse() (*TokRole, error) {
	tmp := strings.TrimSpace(string(s))
	if len(tmp) == 0 {
		return nil, lib.DataError("cannot parse a len=0 TokRole")
	}

	parts := strings.Split(tmp, lib.RoleSep)
	if len(parts) > 3 {
		return nil, lib.DataError("can have at most two '/' chars in a TokRole string")
	}
	p0 := lib.TeamRSVPString(parts[0])
	tok, err := p0.Parse()
	if err != nil {
		return nil, err
	}
	role := lib.DefaultRole
	if len(parts) > 1 {
		raw := strings.Join(parts[1:], lib.RoleSep)
		p1 := lib.RoleString(raw)
		tmp, err := p1.Parse()
		if err != nil {
			return nil, err
		}
		role = *tmp
	}
	return &TokRole{Tok: *tok, Role: role}, nil
}

func (s BackupHESPString) Split() BackupHESP {
	parts := strings.Fields(string(s))
	return BackupHESP(parts)
}

func (s BackupHESP) Flatten() BackupHESPString {
	return BackupHESPString(strings.Join(s, " "))
}

func (s BackupHESPString) String() string {
	return string(s)
}

func (s SKMWK) String() string                  { return lib.B62Encode(s[:]) }
func (s SKMWK) MarshalJSON() ([]byte, error)    { return json.Marshal(s.String()) }
func (s *SKMWK) UnmarshalJSON(dat []byte) error { return lib.UnmarshalJsonFixed((*s)[:], dat) }
