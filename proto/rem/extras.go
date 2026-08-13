// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package rem

import (
	"crypto/hmac"
	"encoding/hex"
	"strings"

	lib "github.com/foks-proj/go-foks/proto/lib"
)

func (t *TeamCertV1Signed) GetSignatures() []lib.Signature {
	return t.Signatures
}

func (t *TeamCertV1Signed) SetSignatures(s []lib.Signature) {
	t.Signatures = s
}

func (t KexActorType) Other() KexActorType {
	if t == KexActorType_Provisionee {
		return KexActorType_Provisioner
	} else {
		return KexActorType_Provisionee
	}
}

func (k *KexWrapperMsg) AssertNormalized() error    { return nil }
func (c *ChallengePayload) AssertNormalized() error { return nil }

func (p *TeamBearerTokenChallengePayload) AssertNormalized() error { return nil }
func (a GrantLocalViewPermissionPayload) AssertNormalized() error  { return nil }
func (a GrantRemoteViewPermissionPayload) AssertNormalized() error { return nil }
func (c TeamCertV1Signed) AssertNormalized() error                 { return nil }
func (t TeamVOBearerTokenChallenge) AssertNormalized() error       { return nil }
func (u *NameCommitment) AssertNormalized() error                  { return u.Name.AssertNormalized() }

func (t NameType) ExportToDB() string {
	switch t {
	case NameType_Team:
		return "team"
	case NameType_User:
		return "user"
	default:
		return "unknown"
	}
}

func (a GrantLocalViewPermissionPayload) Time() lib.Time       { return a.Tm }
func (a GrantLocalViewPermissionPayload) Signer() lib.PartyID  { return a.Viewee }
func (a GrantRemoteViewPermissionPayload) Time() lib.Time      { return a.Tm }
func (a GrantRemoteViewPermissionPayload) Signer() lib.PartyID { return a.Viewee }

func (t TeamBearerToken) ExportToDB() []byte   { return t[:] }
func (t TeamVOBearerToken) ExportToDB() []byte { return t[:] }

func (r TeamVOBearerTokenReq) Eq(r2 TeamVOBearerTokenReq) (bool, error) {
	if r.Gen != r2.Gen || !r.Member.Eq(r2.Member) {
		return false, nil
	}
	ok, err := r.SrcRole.Eq(r2.SrcRole)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	ok, err = r.Team.Eq(r2.Team)
	if err != nil {
		return false, err
	}
	return ok, nil
}

func (k TeamRemovalKey) Eq(k2 TeamRemovalKey) bool {
	return hmac.Equal(k[:], k2[:])
}

// Eq compares bearer tokens in constant time (they're secrets, so a
// short-circuiting comparison could leak via timing if ever used against
// attacker-supplied input). Pointer form since tokens are optional in many
// spots; nil equals only nil.
func (t *TeamVOBearerToken) Eq(t2 *TeamVOBearerToken) bool {
	if t == nil || t2 == nil {
		return t == t2
	}
	return hmac.Equal(t[:], t2[:])
}

func (r TeamRawInboxRowVar) Token() (lib.TeamRSVP, error) {
	var zed lib.TeamRSVP
	typ, err := r.GetT()
	if err != nil {
		return zed, err
	}
	switch typ {
	case TeamJoinReqType_Local:
		return lib.NewTeamRSVPWithLocal(r.Local().Tok), nil
	case TeamJoinReqType_Remote:
		return lib.NewTeamRSVPWithRemote(r.Remote().Tok), nil
	}
	return zed, lib.DataError("bad team join req type")
}

func (r GetEncryptedChunkRes) GetVersion() lib.Version {
	return lib.Version(0)
}

func (i LockID) ExportToDB() []byte {
	return i[:]
}

func (i *LockID) ImportFromDB(r []byte) error {
	if len(r) != len(*i) {
		return lib.DataError("bad lock id")
	}
	copy((*i)[:], r)
	return nil
}

func (s WebSession) ExportToDB() []byte {
	return s[:]
}

func (s WebSession) EncodeToHex() string {
	return hex.EncodeToString(s[:])
}

func (s *WebSession) ImportFromBytes(b []byte) error {
	if len(b) != len(*s) {
		return lib.DataError("bad web session")
	}
	copy((*s)[:], b)
	return nil
}

func (s WebSessionString) Parse() (*WebSession, error) {
	raw, err := lib.B62Decode(string(s))
	if err != nil {
		return nil, err
	}
	var ret WebSession
	if len(raw) != len(ret) {
		return nil, lib.DataError("bad WebSession, wrong length")
	}
	copy(ret[:], raw)
	return &ret, nil
}

func (s *WebSession) EncodeToString() WebSessionString {
	return WebSessionString(lib.B62Encode((*s)[:]))
}

func (c MultiUseInviteCode) String() string {
	return string(c)
}

func (a MultiUseInviteCode) Cmp(b MultiUseInviteCode) int {
	x1 := strings.ToLower(a.String())
	x2 := strings.ToLower(b.String())
	return strings.Compare(x1, x2)
}

func (r RTChannelSet) GetVersion() lib.Version {
	return lib.Version(r.Vers)
}
