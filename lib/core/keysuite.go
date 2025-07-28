// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/hex"

	proto "github.com/foks-proj/go-foks/proto/lib"
)

// A pin like the kind a Yubi needs to unlock, will be implemented by various UIs.
type Pin struct {
	string
}

func (p Pin) String() string { return p.string }

func (p Pin) IsSet() bool { return len(p.string) > 0 }

type Pinner interface {
	Pin(ctx context.Context) (Pin, error)
}

type PrivateSuite25519 struct {
	Role     proto.Role
	typ      proto.EntityType
	seed     proto.SecretSeed32
	sign     ed25519.PrivateKey
	verify   ed25519.PublicKey
	enc      proto.Curve25519PublicKey
	dec      proto.Curve25519SecretKey
	kemEncap proto.KemEncapKey
	kemDecap proto.KemDecapKey
	hostID   *proto.HostID
}

func (p PrivateSuite25519) Eq(p2 PrivateSuite25519) bool {
	return hmac.Equal(p.sign[:], p2.sign[:])
}

func PrivateSuiterEqual(ps1, ps2 PrivateSuiter) (bool, error) {
	e1, err := ps1.EntityID()
	if err != nil {
		return false, err
	}
	e2, err := ps2.EntityID()
	if err != nil {
		return false, err
	}
	return e1.Eq(e2), nil
}

func PublicPrivateSuiterEqual(p1 PublicSuiter, p2 PrivateSuiter) (bool, error) {
	e1 := p1.GetEntityID()
	e2, err := p2.EntityID()
	if err != nil {
		return false, err
	}
	return e1.Eq(e2), nil
}

func PublicSuiterEq(p1, p2 PublicSuiter) bool {
	return p1.GetEntityID().Eq(p2.GetEntityID())
}

type PrivateSuiter interface {
	PrivateBoxer
	ExportToMember(host proto.HostID) (*proto.Member, error)
	GetRole() proto.Role
	Publicize(hostID *proto.HostID) (PublicSuiter, error)
	ExportKeySuite() (*proto.KeySuite, error)
	CertSigner() (EntityPrivate, error)
	HasSubkey() bool
	ExportToYubiKeyInfo(ctx context.Context) (*proto.YubiKeyInfoHybrid, error) // Will return nil if not a yubi

	// The EntityID() returned by public boxer is fixed, for entities like users and teams.
	// But obviously those corresponding keys (PUKs and PTKs) can roll, so they get a
	// different prefix (but the same public key).
	RollingEntityID() (proto.EntityID, error)
}

type PublicSuite25519 struct {
	EntityPublicEd25519
	HostID    *proto.HostID
	Hepk      *proto.HEPK
	Role      proto.Role
	StartEpno *proto.MerkleEpno
}

type PublicSuiteECDSA struct {
	EntityPublicECDSA
	HostID    *proto.HostID
	Role      proto.Role
	StartEpno *proto.MerkleEpno
	Hepk      *proto.HEPK
}

type PublicSuiter interface {
	PublicBoxer
	GetRole() proto.Role
	GetStartEpno() *proto.MerkleEpno
}

var _ PublicSuiter = (*PublicSuite25519)(nil)
var _ PublicBoxer = (*PublicSuite25519)(nil)
var _ Verifier = (*PublicSuite25519)(nil)
var _ Verifier = (*SharedPublicSuite)(nil)
var _ PrivateSuiter = (*PrivateSuite25519)(nil)

func (p *PublicSuite25519) ECDSA() (*ecdsa.PublicKey, error) {
	return nil, KeyNotFoundError{Which: "ECDSA public key"}
}
func (p *PublicSuite25519) DHType() proto.DHType                { return proto.DHType_Curve25519 }
func (p *PublicSuite25519) Ephemeral() (EphemeralSender, error) { return NewEphemeralSender25519() }
func (p *PublicSuite25519) GetHostID() *proto.HostID            { return p.HostID }
func (p *PublicSuite25519) GetRole() proto.Role                 { return p.Role }
func (p *PublicSuite25519) GetStartEpno() *proto.MerkleEpno     { return p.StartEpno }
func (p *PublicSuite25519) ExportHEPK() (*proto.HEPK, error)    { return p.Hepk, nil }
func (p *PublicSuite25519) DHPublicKey() (*proto.DHPublicKey, error) {
	return HEPK(p.Hepk).DHPublicKey()
}
func (p *PublicSuite25519) KemEncapKey() (*proto.KemEncapKey, error) {
	return HEPK(p.Hepk).KemEncapKey()
}

func (p *PublicSuiteECDSA) DHType() proto.DHType                { return proto.DHType_P256 }
func (p *PublicSuiteECDSA) Ephemeral() (EphemeralSender, error) { return NewEphemeralSenderECDSA() }
func (p *PublicSuiteECDSA) GetHostID() *proto.HostID            { return p.HostID }
func (p *PublicSuiteECDSA) GetRole() proto.Role                 { return p.Role }
func (p *PublicSuiteECDSA) GetStartEpno() *proto.MerkleEpno     { return p.StartEpno }
func (p *PublicSuiteECDSA) ExportHEPK() (*proto.HEPK, error)    { return p.Hepk, nil }
func (p *PublicSuiteECDSA) DHPublicKey() (*proto.DHPublicKey, error) {
	return HEPK(p.Hepk).DHPublicKey()
}
func (p *PublicSuiteECDSA) KemEncapKey() (*proto.KemEncapKey, error) {
	return HEPK(p.Hepk).KemEncapKey()
}

func (p *PublicSuiteECDSA) Curve25519() (*proto.Curve25519PublicKey, error) {
	return nil, KeyNotFoundError{Which: "curve25519 DH"}
}

func (p *PublicSuite25519) Curve25519() (*proto.Curve25519PublicKey, error) {
	ret, err := HEPK(p.Hepk).ExtractCurve25519()
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return nil, KeyNotFoundError{Which: "curve25519 DH"}
	}
	return ret, nil
}

func (p *PrivateSuite25519) Curve25519() *proto.Curve25519SecretKey { return &p.dec }

func exportKeySuite(p PrivateSuiter) (*proto.KeySuite, error) {
	eid, err := p.EntityID()
	if err != nil {
		return nil, err
	}
	hepk, err := p.ExportHEPK()
	if err != nil {
		return nil, err
	}
	return &proto.KeySuite{
		Entity: eid,
		Hepk:   *hepk,
	}, nil
}

func (p *PrivateSuite25519) ExportKeySuite() (*proto.KeySuite, error) {
	return exportKeySuite(p)
}

func (p *PrivateSuite25519) PrivateKeyForCert() (crypto.PrivateKey, error) { return &p.sign, nil }
func (p *PrivateSuite25519) CertSigner() (EntityPrivate, error)            { return p, nil }
func (p *PrivateSuite25519) HasSubkey() bool                               { return false }

func (p *PrivateSuite25519) ExportToYubiKeyInfo(ctx context.Context) (*proto.YubiKeyInfoHybrid, error) {
	return nil, nil
}

func (p *PublicSuiteECDSA) ECDSA() (*ecdsa.PublicKey, error) {
	return HEPK(p.Hepk).ExtractP256()
}

func (p *PublicSuiteECDSA) ExportToMember(h proto.HostID) (*proto.Member, *proto.HEPK, error) {
	hepk, err := p.ExportHEPK()
	if err != nil {
		return nil, nil, err
	}
	fp, err := HEPK(hepk).Fingerprint()
	if err != nil {
		return nil, nil, err
	}
	return &proto.Member{
		Id: proto.FQEntityInHostScope{
			Entity: p.EntityPublicECDSA.EntityID,
			Host:   PickHostIDInScope(p.HostID, h),
		},
		Keys: proto.NewMemberKeysWithUser(
			proto.UserMemberKeys{
				HepkFp: *fp,
			},
		),
	}, hepk, nil
}

func (p *PublicSuiteECDSA) ExportToTarget(h proto.HostID) (*proto.SharedKeyBoxTarget, error) {
	return &proto.SharedKeyBoxTarget{
		Eid:  p.EntityPublicECDSA.EntityID,
		Host: PickHostIDInScope(p.HostID, h),
	}, nil
}

func (p *PublicSuite25519) ExportToMember(h proto.HostID) (*proto.Member, *proto.HEPK, error) {
	hepk, err := p.ExportHEPK()
	if err != nil {
		return nil, nil, err
	}
	fp, err := HEPK(hepk).Fingerprint()
	if err != nil {
		return nil, nil, err
	}

	ret := proto.Member{
		Id: proto.FQEntityInHostScope{
			Entity: p.GetEntityID(),
			Host:   PickHostIDInScope(p.HostID, h),
		},
		Keys: proto.NewMemberKeysWithUser(
			proto.UserMemberKeys{
				HepkFp: *fp,
			},
		),
	}
	return &ret, hepk, nil
}

func (p *PublicSuite25519) ExportToTarget(h proto.HostID) (*proto.SharedKeyBoxTarget, error) {
	return &proto.SharedKeyBoxTarget{
		Eid:  p.GetEntityID(),
		Host: PickHostIDInScope(p.HostID, h),
	}, nil
}

func ImportPublicSuiterFromTeamMemberKeys(p proto.TeamMemberKeys, hepks *HEPKSet, h proto.HostID, r proto.Role) (*PublicSuite25519, error) {
	if !p.VerifyKey.Type().IsEd25519() {
		return nil, PublicKeyError("team member keys must be 25519 keys")
	}
	hepk, ok := hepks.Lookup(&p.HepkFp)
	if !ok {
		return nil, KeyNotFoundError{Which: "hepk"}
	}

	return &PublicSuite25519{
		EntityPublicEd25519: EntityPublicEd25519{EntityID: p.VerifyKey},
		Hepk:                hepk.Obj(),
		HostID:              &h,
		Role:                r,
	}, nil
}

func (p *PrivateSuite25519) PublicizeToBoxer() (PublicBoxer, error) {
	return p.Publicize(nil)
}

func (p *PrivateSuite25519) Publicize(hostID *proto.HostID) (PublicSuiter, error) {
	ent, err := p.EntityID()
	if err != nil {
		return nil, err
	}
	hepk, err := p.ExportHEPK()
	if err != nil {
		return nil, err
	}
	return &PublicSuite25519{
		EntityPublicEd25519: EntityPublicEd25519{ent},
		HostID:              hostID,
		Hepk:                hepk,
		Role:                p.Role,
	}, nil
}

func (p *PrivateSuite25519) DHType() proto.DHType {
	return proto.DHType_Curve25519
}

func Snap8(b []byte) string {
	return hex.EncodeToString(b[0:4]) + "." + hex.EncodeToString(b[len(b)-4:])
}

func (p *PrivateSuite25519) BoxFor(o CryptoPayloader, br PublicBoxer, opts BoxOpts) (*proto.Box, error) {
	err := AssertDHTypeMatch(p, br)
	if err != nil {
		return nil, err
	}
	return hybridEncrypt25519(o, &p.dec, &p.enc, br, opts)
}

func (p *PrivateSuite25519) UnboxForIncludedEphemeral(
	o CryptoPayloader,
	box proto.Box,
) error {
	v1, err := OpenBoxHybrid(box)
	if err != nil {
		return err
	}
	sender := v1.Sender
	if sender == nil {
		return BoxError("no sender in box")
	}
	_, err = p.unboxWithSenderDH(o, v1, sender)
	return err
}

func (p *PrivateSuite25519) UnboxForEphemeral(
	o CryptoPayloader,
	box proto.Box,
	sender proto.DHPublicKey,
) error {
	v1, err := OpenBoxHybrid(box)
	if err != nil {
		return err
	}
	_, err = p.unboxWithSenderDH(o, v1, &sender)
	return err
}

func (p *PrivateSuite25519) UnboxFor(
	o CryptoPayloader,
	box proto.Box,
	sender PublicBoxer,
) (
	DHPublicKey,
	error,
) {
	v1, sDh, err := OpenBoxAndSenderHybrid(box, sender)
	if err != nil {
		return nil, err
	}
	return p.unboxWithSenderDH(o, v1, sDh)
}

func (p *PrivateSuite25519) unboxWithSenderDH(
	o CryptoPayloader,
	v1 *proto.BoxHybridV1,
	sDh *proto.DHPublicKey,
) (
	DHPublicKey,
	error,
) {
	if v1.DhType != proto.DHType_Curve25519 {
		return nil, BoxError("got non-Curve25519 box")
	}
	sDhTyp, err := sDh.GetT()
	if err != nil {
		return nil, err
	}
	if sDhTyp != proto.DHType_Curve25519 {
		return nil, BoxError("got non-Curve25519 sender key")
	}
	sDh25519 := sDh.Curve25519()

	dhKey, err := Curve25519DHExchange(&p.dec, &sDh25519)
	if err != nil {
		return nil, err
	}
	hepk, err := p.ExportHEPK()
	if err != nil {
		return nil, err
	}

	err = HybridUnboxCommon(o, v1, dhKey.ToDHSharedKey(), sDh, &p.kemDecap, *hepk)
	if err != nil {
		return nil, err
	}
	return DHPublicKey25519{Curve25519PublicKey: &sDh25519}, nil

}

func (p *PrivateSuite25519) GetRole() proto.Role {
	return p.Role
}

func (p *PrivateSuite25519) ExportDHPublicKey(inContextOfSigKey bool) proto.DHPublicKey {
	return proto.NewDHPublicKeyWithCurve25519(p.enc)
}

func (p *PrivateSuite25519) Seed() proto.SecretSeed32 {
	return p.seed
}

func ImportPublicSuite(o *proto.MemberRole, hepks *HEPKSet, host proto.HostID) (PublicSuiter, error) {

	typ, err := o.Member.Keys.GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.MemberKeysType_User {
		return nil, KeyImportError("only user keys supported")
	}

	ukeys := o.Member.Keys.User()
	hepk, ok := hepks.Lookup(&ukeys.HepkFp)
	if !ok {
		return nil, KeyNotFoundError{Which: "hepk"}
	}

	// No need to check fingerprint since we've computed the HEPKSet on our own,
	// and the lookup succeeding is proof the fingerprint matches the key.
	return importPublicSuiteHelper(
		o.Member.Id.Entity,
		hepk.Obj(),
		o.Member.Id.Host,
		host,
		o.DstRole,
	)
}

func importPublicSuiteHelper(
	eid proto.EntityID,
	hepk *proto.HEPK,
	h1 *proto.HostID,
	h2 proto.HostID,
	role proto.Role,
) (PublicSuiter, error) {

	dh, err := HEPK(hepk).DHPublicKey()
	if err != nil {
		return nil, err
	}

	dhtyp, err := dh.GetT()
	if err != nil {
		return nil, err
	}
	host := h2
	if h1 != nil && !h1.Eq(h2) {
		return nil, HostMismatchError{}
	}
	switch eid.Type() {
	case proto.EntityType_Device, proto.EntityType_User, proto.EntityType_Team,
		proto.EntityType_BackupKey, proto.EntityType_PassphraseKey,
		proto.EntityType_BotTokenKey:
		if dhtyp != proto.DHType_Curve25519 {
			return nil, KeyImportError("wrong type of DH key in key import")
		}
		ret := PublicSuite25519{
			EntityPublicEd25519: EntityPublicEd25519{EntityID: eid},
			HostID:              &host,
			Role:                role,
			Hepk:                hepk,
		}
		return &ret, nil
	case proto.EntityType_Yubi:
		if dhtyp != proto.DHType_P256 {
			return nil, KeyImportError("need DH type P256 with Yubikey/ECDSA")
		}
		i := dh.P256()
		j, err := eid.ECDSACompressedPublicKey()
		if err != nil {
			return nil, err
		}
		if !i.Eq(j) {
			return nil, KeyImportError("ECDSA public key mismatch")
		}
		ret := PublicSuiteECDSA{
			EntityPublicECDSA: EntityPublicECDSA{EntityID: eid},
			HostID:            &host,
			Role:              role,
			Hepk:              hepk,
		}
		return &ret, nil
	default:
		return nil, KeyImportError("unknown key type in import")
	}
}

func NewPrivateSuite25519(typ proto.EntityType, role proto.Role, s proto.SecretSeed32, h proto.HostID) (*PrivateSuite25519, error) {
	svs, err := DeviceSigningSecretKey(s)
	if err != nil {
		return nil, err
	}
	dhs, err := DeviceDHSecretKey(s)
	if err != nil {
		return nil, err
	}
	kemEnc, kemDec, err := GenPQKemKeysFromSeed(s)
	if err != nil {
		return nil, err
	}
	sign := ed25519.NewKeyFromSeed(svs[:])
	verify := sign.Public().(ed25519.PublicKey)
	ret := PrivateSuite25519{
		Role:     role,
		typ:      typ,
		seed:     s,
		sign:     sign,
		verify:   verify,
		hostID:   &h,
		kemEncap: *kemEnc,
		kemDecap: kemDec,
	}
	copy(ret.dec[:], dhs[:])
	ret.enc = *ret.dec.PublicKey()
	return &ret, nil
}

func PickHostIDInScope(keyHostID *proto.HostID, currentHostID proto.HostID) *proto.HostID {
	if keyHostID == nil {
		return nil
	}
	if keyHostID.Eq(currentHostID) {
		return nil
	}
	return keyHostID
}

func (s *PrivateSuite25519) ExportToTarget(h proto.HostID) (*proto.SharedKeyBoxTarget, error) {
	e, err := s.typ.MakeEntityID(s.verify)
	if err != nil {
		return nil, err
	}
	ret := proto.SharedKeyBoxTarget{
		Eid:  e,
		Host: PickHostIDInScope(s.hostID, h),
	}
	return &ret, nil
}

func (s *PrivateSuite25519) ExportHEPK() (*proto.HEPK, error) {
	ret := proto.NewHEPKWithV1(
		proto.HEPKv1{
			Classical: proto.NewDHPublicKeyWithCurve25519(s.enc),
			Pqkem:     s.kemEncap,
		},
	)
	return &ret, nil
}

func exportToMember(p PrivateSuiter, h1 *proto.HostID, h2 proto.HostID) (*proto.Member, error) {
	eid, err := p.EntityID()
	if err != nil {
		return nil, err
	}
	hepk, err := p.ExportHEPK()
	if err != nil {
		return nil, err
	}
	fp, err := HEPK(hepk).Fingerprint()
	if err != nil {
		return nil, err
	}
	ret := proto.Member{
		Id: proto.FQEntityInHostScope{
			Entity: eid,
			Host:   PickHostIDInScope(h1, h2),
		},
		Keys: proto.NewMemberKeysWithUser(
			proto.UserMemberKeys{
				HepkFp: *fp,
			},
		),
	}
	return &ret, nil

}

func (s *PrivateSuite25519) ExportToMember(h proto.HostID) (*proto.Member, error) {
	return exportToMember(s, s.hostID, h)
}

func (s *PrivateSuite25519) EntityID() (proto.EntityID, error) {
	return s.typ.MakeEntityID(s.verify)
}

func (s *PrivateSuite25519) RollingEntityID() (proto.EntityID, error) {
	return s.typ.RollingType().MakeEntityID(s.verify)
}

func (s *PrivateSuite25519) DeviceID() (proto.DeviceID, error) {
	eid, err := s.EntityID()
	if err != nil {
		return nil, err
	}
	return eid.ToDeviceID()
}

func (s *PrivateSuite25519) EntityPublic() (EntityPublic, error) {
	eid, err := s.EntityID()
	if err != nil {
		return nil, err
	}
	return EntityPublicEd25519{eid}, nil
}

func (e PrivateSuite25519) Sign(obj Verifiable) (*proto.Signature, error) {
	return SignWithEd21559Private(e.sign, obj)
}

func (e PrivateSuite25519) Verify(s proto.Signature, obj Verifiable) error {
	return VerifyWithEd25519Public(e.verify, s, obj)
}

func ImportKeySuite(k proto.KeySuite, role proto.Role, host proto.HostID) (PublicSuiter, error) {
	return importPublicSuiteHelper(k.Entity, &k.Hepk, &host, host, role)
}

type EntityPublicAtHost struct {
	ep   EntityPublic
	host proto.HostID
}

func ImportEntityPublicWithHost(eid proto.EntityID, host proto.HostID) (*EntityPublicAtHost, error) {
	ep, err := ImportEntityPublic(eid)
	if err != nil {
		return nil, err
	}
	return &EntityPublicAtHost{ep: ep, host: host}, nil
}

func ImportEntityPublicAtHost(fqe proto.FQEntityInHostScope, host proto.HostID) (*EntityPublicAtHost, error) {
	if fqe.Host != nil && !fqe.Host.Eq(host) {
		return nil, HostMismatchError{}
	}
	ep, err := ImportEntityPublic(fqe.Entity)
	if err != nil {
		return nil, err
	}
	return &EntityPublicAtHost{ep: ep, host: host}, nil
}

func (e *EntityPublicAtHost) Eq(ps PublicSuiter) (bool, error) {
	host := ps.GetHostID()
	if host == nil {
		return false, MissingHostError{}
	}
	return host.Eq(e.host) && e.ep.GetEntityID().Eq(ps.GetEntityID()), nil
}

func ImportPublicSuiteFromDB(
	ep EntityPublic,
	hepk *proto.HEPK,
	role proto.Role,
	hostId proto.HostID,
	epno *proto.MerkleEpno,
) (PublicSuiter, error) {
	dh, err := HEPK(hepk).DHPublicKey()
	if err != nil {
		return nil, err
	}
	dht, err := dh.GetT()
	if err != nil {
		return nil, err
	}
	switch tep := ep.(type) {
	case EntityPublicEd25519:
		if dht != proto.DHType_Curve25519 {
			return nil, KeyImportError("need DH key for curve25519 key suite, got something else")
		}
		return &PublicSuite25519{
			EntityPublicEd25519: tep,
			Role:                role,
			HostID:              &hostId,
			Hepk:                hepk,
			StartEpno:           epno,
		}, nil
	case EntityPublicECDSA:
		if dht != proto.DHType_P256 {
			return nil, KeyImportError("need a DH key for yubi/ECDSA key suite")
		}
		return &PublicSuiteECDSA{
			EntityPublicECDSA: tep,
			Role:              role,
			HostID:            &hostId,
			StartEpno:         epno,
			Hepk:              hepk,
		}, nil
	default:
		return nil, KeyImportError("unknown key type in import")
	}
}

func GetUserKeysFromMember(m proto.Member) (*proto.UserMemberKeys, error) {
	typ, err := m.Keys.GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.MemberKeysType_User {
		return nil, KeyImportError("only user keys supported")
	}
	tmp := m.Keys.User()
	return &tmp, nil
}

func ImportPublicSuiteFromDeviceInfo(d proto.DeviceInfo, hepks *HEPKSet, h proto.HostID) (PublicSuiter, error) {
	ukeys, err := GetUserKeysFromMember(d.Key.Member)
	if err != nil {
		return nil, err
	}
	hepk, ok := hepks.Lookup(&ukeys.HepkFp)
	if !ok {
		return nil, KeyNotFoundError{Which: "hepk"}
	}
	return importPublicSuiteHelper(
		d.Key.Member.Id.Entity,
		hepk.Obj(),
		d.Key.Member.Id.Host,
		h,
		d.Key.DstRole,
	)
}

func ImportPublicSuiterFromHEPK(eid proto.EntityID, k *proto.HEPK) (PublicSuiter, error) {
	var role proto.Role
	var host proto.HostID
	return importPublicSuiteHelper(eid, k, nil, host, role)

}
