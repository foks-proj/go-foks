// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/keybase/go-codec/codec"
)

type PublicSuiterWithSeqno struct {
	Ps    PublicSuiter
	Seqno proto.Seqno
}

type SignerPair struct {
	Eid   proto.EntityID // A key ID
	Seqno proto.Seqno    // The seqno it was introduced in chain (needed for reuse of yubikeys)
}

func (s SignerPair) Cmp(s2 SignerPair) int {
	c := s.Eid.Cmp(s2.Eid)
	if c != 0 {
		return c
	}
	d := int(s.Seqno) - int(s2.Seqno)
	if d < 0 {
		return -1
	}
	if d > 0 {
		return 1
	}
	return d
}

func (p PublicSuiterWithSeqno) ToSignerPair() SignerPair {
	return SignerPair{
		Eid:   p.Ps.GetEntityID(),
		Seqno: p.Seqno,
	}
}

func RandomCommitmentKey() (*proto.RandomCommitmentKey, error) {
	var ret proto.RandomCommitmentKey
	err := RandomFill(ret[:])
	return &ret, err
}

func Commit(v Verifiable) (*proto.RandomCommitmentKey, *proto.Commitment, error) {
	err := v.AssertNormalized()
	if err != nil {
		return nil, nil, err
	}
	rck, err := RandomCommitmentKey()
	if err != nil {
		return nil, nil, err
	}
	commitment, err := computeCommitment(v, rck)
	if err != nil {
		return nil, nil, err
	}
	return rck, commitment, nil
}

func ComputeKeyCommitment(p CryptoPayloader) (*proto.KeyCommitment, error) {
	var ret proto.KeyCommitment
	err := PrefixedHashInto(p, ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func computeCommitment(v Verifiable, key *proto.RandomCommitmentKey) (*proto.Commitment, error) {
	digest := hmac.New(sha512.New512_256, key[:])
	mh := Codec()
	err := v.GetTypeUniqueID().Encode(digest)
	if err != nil {
		return nil, err
	}
	enc := codec.NewEncoder(digest, mh)
	err = v.Encode(enc)
	if err != nil {
		return nil, err
	}
	sum := digest.Sum(nil)
	var commitment proto.Commitment
	copy(commitment[:], sum)

	return &commitment, nil
}

func MakeTreeLocation() (*proto.TreeLocation, *proto.TreeLocationCommitment, error) {
	loc, err := RandomTreeLocation()
	if err != nil {
		return nil, nil, err
	}
	com, err := PrefixedHash(&loc)
	if err != nil {
		return nil, nil, err
	}
	tlc := proto.TreeLocationCommitment(*com)
	return &loc, &tlc, nil
}

func OpenCommitment(v Verifiable, key *proto.RandomCommitmentKey, expected *proto.Commitment) error {
	err := v.AssertNormalized()
	if err != nil {
		return err
	}
	computed, err := computeCommitment(v, key)
	if err != nil {
		return err
	}
	if !hmac.Equal(computed[:], expected[:]) {
		return VerifyError("commitment failed")
	}
	return nil
}

type OpenDeviceProvisionRes struct {
	Gc                   *proto.GroupChange
	Lov1                 *proto.LinkOuterV1
	verifiers            []Verifier
	NewDevice            PublicSuiter
	SharedKey            *SharedPublicSuite
	DeviceNameCommitment *proto.Commitment
	Root                 proto.TreeRoot
	ExistingDevice       EntityPublic
	Subkey               EntityPublic
}

func openDeviceProvisionPUK(
	puk *SharedPublicSuite,
	lowlyDevice bool,
	pukGens map[RoleKey]proto.Generation,
	newDevice PublicSuiter,
) error {

	if !lowlyDevice {
		return LinkError("can only add a shared key if adding a lower-privileged device")
	}
	ir, err := ImportRole(puk.Role)
	if err != nil {
		return err
	}
	curr, found := pukGens[*ir]
	newGen := puk.Gen
	if !found && !newGen.IsFirst() {
		return LinkError("exepected gen=1 for new PUK shared key")
	}
	if found && newGen != curr+1 {
		return LinkError(fmt.Sprintf("expected pukGen %d, but got %d", curr+1, newGen))
	}
	err = puk.Role.AssertEq(
		newDevice.GetRole(),
		LinkError("need PUK role to be same as new device"),
	)
	if err != nil {
		return err
	}
	return nil
}

// A device acting at a role equal or lower to its own, since for an owner
// owning a reader key, for instance.
type DeviceAtRole struct {
	Id   proto.FixedEntityID
	Host proto.HostID
	Role RoleKey
}

func ComputeRotateNewBoxGameplan(
	currentDevices map[proto.FQEntityFixed]RoleKey,
	pukGens map[RoleKey]proto.Generation,
	ceiling RoleKey,
) (
	map[DeviceAtRole]proto.Generation,
	error,
) {
	ret := make(map[DeviceAtRole]proto.Generation)
	for id, devRk := range currentDevices {
		for role, gen := range pukGens {
			if role.LessThanOrEqual(ceiling) && role.LessThanOrEqual(devRk) {
				ret[DeviceAtRole{Id: id.Entity, Role: role, Host: id.Host}] = gen + 1
			}
		}
	}
	return ret, nil
}

func CheckChangeUsername(
	odc *OpenDeviceChangeRes,
	hostID proto.HostID,
	currentDevices map[proto.FQEntityFixed]PublicSuiterWithSeqno,
) (
	*proto.Commitment,
	error,
) {
	if len(odc.Gc.Changes) != 0 {
		return nil, LinkError("expected exactly 0 device changes for user rename")
	}
	if len(odc.Gc.Metadata) != 1 {
		return nil, LinkError("expected exactly 1 metada change for user rename")
	}
	typ, err := odc.Gc.Metadata[0].GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.ChangeType_Username {
		return nil, LinkError("expected user name metadata change for user rename")
	}
	unc := odc.Gc.Metadata[0].Username()
	return &unc, nil
}

func CheckSharedKeyUpdate(
	sharedKeys []proto.SharedKey,
	pukGens map[RoleKey]proto.Generation,
	upperLimit RoleKey,
) error {

	foundPUKs := make(map[RoleKey]bool)

	for _, puk := range sharedKeys {
		rk, err := ImportRole(puk.Role)
		if err != nil {
			return err
		}
		if gen, found := pukGens[*rk]; !found {
			return LinkError(fmt.Sprintf("found unneeded new PUK for generation %+v", *rk))
		} else if gen+1 != puk.Gen {
			return LinkError(fmt.Sprintf(
				"got wrong PUK generation, expected a strict +1 increment; "+
					"(got %d and current gen is %d)", puk.Gen, gen))
		}
		if foundPUKs[*rk] {
			return LinkError(fmt.Sprintf("repeated PUK For %+v", *rk))
		}
		foundPUKs[*rk] = true
	}

	for rk := range pukGens {
		if rk.LessThanOrEqual(upperLimit) && !foundPUKs[rk] {
			return LinkError(fmt.Sprintf("missing PUK for role %+v", rk))
		}
	}

	return nil
}

func countRemainingOwners(
	targetId proto.EntityID,
	currentDevices map[proto.FQEntityFixed]PublicSuiterWithSeqno,
) (int, error) {
	numRemainingOwners := 0
	for fqe, dev := range currentDevices {
		if fqe.Entity.Unfix().Eq(targetId) {
			continue
		}
		role, err := dev.Ps.GetRole().GetT()
		if err != nil {
			return 0, err
		}
		if role == proto.RoleType_OWNER {
			numRemainingOwners++
		}
	}
	return numRemainingOwners, nil
}

type CheckDeviceRevokeRes struct {
	Role    RoleKey
	ID      proto.EntityID
	Epno    proto.MerkleEpno
	Pswsqno *PublicSuiterWithSeqno
}

func (c *CheckDeviceRevokeRes) IsRevoke() bool {
	return c.ID != nil
}

func CheckDeviceRevokeOrRotate(
	odc *OpenDeviceChangeRes,
	hostID proto.HostID,
	currentDevices map[proto.FQEntityFixed]PublicSuiterWithSeqno,
	pukGens map[RoleKey]proto.Generation,
) (
	*CheckDeviceRevokeRes, error,
) {
	nChanges := len(odc.Gc.Changes)
	var res *CheckDeviceRevokeRes
	var err error
	switch nChanges {
	case 1:
		res, err = checkDeviceRevoke(odc, hostID, currentDevices, pukGens)
	case 0:
		res, err = checkDeviceRotate(odc, hostID, currentDevices, pukGens)
	default:
		return nil, LinkError("expected exactly 1 device change for revoke device (or 0 for a rotate)")
	}
	if err != nil {
		return nil, err
	}
	res.Epno = odc.Gc.Chainer.Base.Root.Epno
	return res, nil
}

func checkDeviceRevoke(
	odc *OpenDeviceChangeRes,
	hostID proto.HostID,
	currentDevices map[proto.FQEntityFixed]PublicSuiterWithSeqno,
	pukGens map[RoleKey]proto.Generation,
) (
	*CheckDeviceRevokeRes, error,
) {

	target := odc.Gc.Changes[0]
	if target.Member.Id.Host != nil && !target.Member.Id.Host.Eq(hostID) {
		return nil, LinkError("wrong hostID for revoked device")
	}
	rt, err := target.DstRole.GetT()
	if err != nil {
		return nil, err
	}
	if rt != proto.RoleType_NONE {
		return nil, LinkError("revoke must actually revoke the device")
	}
	ktyp, err := target.Member.Keys.GetT()
	if err != nil {
		return nil, err
	}
	if ktyp != proto.MemberKeysType_None {
		return nil, LinkError("member keys must be none for revoke")
	}
	targetId := target.Member.Id.Entity
	targetIdFixed, err := targetId.Fixed()
	if err != nil {
		return nil, err
	}
	targetPS, found := currentDevices[proto.FQEntityFixed{Entity: targetIdFixed, Host: hostID}]
	if !found {
		return nil, LinkError("device to revoke is not currently active")
	}

	targetRole, err := ImportRole(targetPS.Ps.GetRole())
	if err != nil {
		return nil, err
	}

	// Might not have any shared keys if a self-revoke
	selfRevoke := odc.Gc.Signer.Key.Eq(target.Member.Id.Entity)
	if len(odc.Gc.SharedKeys) != 0 && selfRevoke {
		return nil, LinkError("for self-revoke, need 0 shared keys")
	}
	if len(odc.Gc.SharedKeys) == 0 && !selfRevoke {
		return nil, LinkError("if not self-revoking, then need to provide shared keys")
	}

	if targetRole.Typ == proto.RoleType_OWNER {
		numRemainingOwners, err := countRemainingOwners(targetId, currentDevices)
		if err != nil {
			return nil, err
		}
		if numRemainingOwners == 0 {
			return nil, RevokeError("cannot revoke last owner device")
		}
	}
	err = checkRotateRevokeCommon(odc, hostID, currentDevices, pukGens, targetRole)
	if err != nil {
		return nil, err
	}
	return &CheckDeviceRevokeRes{
		Role:    *targetRole,
		ID:      targetId,
		Epno:    odc.Gc.Chainer.Base.Root.Epno,
		Pswsqno: &targetPS,
	}, nil
}

func checkDeviceRotate(
	odc *OpenDeviceChangeRes,
	hostID proto.HostID,
	currentDevices map[proto.FQEntityFixed]PublicSuiterWithSeqno,
	pukGens map[RoleKey]proto.Generation,
) (*CheckDeviceRevokeRes, error) {
	if len(odc.SharedKeys) == 0 {
		return nil, LinkError("need at least 1 new shared key")
	}

	// All roles up to upper limit must be rotated, but we just get
	// that upper limit from the keys specified. Unlike with revoke,
	// we can't reeally enforce a maximum upper limit.
	seniorDevice := odc.SharedKeys[len(odc.SharedKeys)-1]
	upperLimit, err := ImportRole(seniorDevice.Role)
	if err != nil {
		return nil, err
	}

	err = checkRotateRevokeCommon(odc, hostID, currentDevices, pukGens, upperLimit)
	if err != nil {
		return nil, err
	}
	res := CheckDeviceRevokeRes{
		Role: *upperLimit,
	}
	return &res, nil
}

func checkRotateRevokeCommon(
	odc *OpenDeviceChangeRes,
	hostID proto.HostID,
	currentDevices map[proto.FQEntityFixed]PublicSuiterWithSeqno,
	pukGens map[RoleKey]proto.Generation,
	targetRole *RoleKey,
) error {

	fid, err := odc.ExistingDevice.GetEntityID().Fixed()
	if err != nil {
		return err
	}
	signer, found := currentDevices[proto.FQEntityFixed{Entity: fid, Host: hostID}]
	if !found {
		return ValidationError("attempt to revoke without a current device")
	}

	err = signer.Ps.GetRole().AssertEq(proto.NewRoleDefault(proto.RoleType_OWNER),
		PermissionError("only owner devices can revoke devices or rotate PUKs"),
	)
	if err != nil {
		return err
	}

	if len(odc.Gc.SharedKeys) > 0 {
		err = CheckSharedKeyUpdate(odc.Gc.SharedKeys, pukGens, *targetRole)
		if err != nil {
			return err
		}
	}

	if odc.Gc.Chainer.Base.Root.Epno == 0 {
		return RevokeError("need non-zero merkle Epno for revoke")
	}
	return nil
}

func OpenDeviceProvision(
	odc *OpenDeviceChangeRes,
	currentDevices map[proto.FQEntityFixed]PublicSuiterWithSeqno,
	pukGens map[RoleKey]proto.Generation,
	hostID proto.HostID,
) (
	res *OpenDeviceProvisionRes,
	err error,
) {
	if len(odc.Gc.Changes) != 1 || odc.newDevice == nil || !odc.newDevice.GetRole().IsSet() {
		return nil, LinkError("expected exactly 1 new device for device provision")
	}
	rt, err := odc.newDevice.GetRole().GetT()
	if err != nil {
		return nil, err
	}
	if rt == proto.RoleType_NONE {
		return nil, LinkError("cannot revoke a device via provision")
	}
	fid, err := odc.ExistingDevice.GetEntityID().Fixed()
	if err != nil {
		return nil, err
	}
	signer, found := currentDevices[proto.FQEntityFixed{Entity: fid, Host: hostID}]
	if !found {
		return nil, ValidationError("attempt to provision without a current device")
	}
	err = signer.Ps.GetRole().AssertEq(proto.NewRoleDefault(proto.RoleType_OWNER),
		PermissionError("only owner devices can add new devices"),
	)
	if err != nil {
		return nil, err
	}
	lowlyDevice, err := signer.Ps.GetRole().GreaterThan(odc.newDevice.GetRole())
	if err != nil {
		return nil, err
	}
	if len(odc.Gc.Metadata) != 1 {
		return nil, LinkError("expected exactly one metadata change")
	}
	commitment, err := openDeviceName(odc.Gc.Metadata[0])
	if err != nil {
		return nil, err
	}
	if len(odc.SharedKeys) > 1 {
		return nil, LinkError("only can have at most 1 shared key (if adding a lower-privileged device")
	}
	var puk *SharedPublicSuite
	if len(odc.SharedKeys) == 1 {
		puk = &odc.SharedKeys[0]
		err = openDeviceProvisionPUK(puk, lowlyDevice, pukGens, odc.newDevice)
		if err != nil {
			return nil, err
		}
	}

	return &OpenDeviceProvisionRes{
		Gc:                   odc.Gc,
		Lov1:                 odc.lov1,
		verifiers:            odc.verifiers,
		NewDevice:            odc.newDevice,
		SharedKey:            puk,
		DeviceNameCommitment: commitment,
		Root:                 odc.Gc.Chainer.Base.Root,
		ExistingDevice:       odc.ExistingDevice,
		Subkey:               odc.Subkey,
	}, nil
}

func openDeviceName(m proto.ChangeMetadata) (*proto.Commitment, error) {
	mdt, err := m.GetT()
	if err != nil {
		return nil, err
	}
	if mdt != proto.ChangeType_DeviceName {
		return nil, LinkError("wrong type of metadata; need DeviceName")
	}
	commitment := m.Devicename()
	return &commitment, nil
}

func openSubchainTreeLocationCommitment(m proto.ChangeMetadata) (*proto.TreeLocationCommitment, error) {
	mdt, err := m.GetT()
	if err != nil {
		return nil, err
	}
	if mdt != proto.ChangeType_Eldest {
		return nil, LinkError("wrong type of metadata; need Eldest")
	}
	commitment := m.Eldest().SubchainTreeLocationSeedCommitment
	return &commitment, nil
}

func openUsername(m proto.ChangeMetadata) (*proto.Commitment, error) {
	mdt, err := m.GetT()
	if err != nil {
		return nil, err
	}
	if mdt != proto.ChangeType_Username {
		return nil, LinkError("wrong type of metadata; need Username")
	}
	commitment := m.Username()
	return &commitment, nil
}

type OpenEldestRes struct {
	Uid                            proto.UID
	Device                         PublicSuiter
	UserKey                        SharedPublicSuite
	DeviceNameCommitment           *proto.Commitment
	UsernameCommitment             *proto.Commitment
	SubchainTreeLocationCommitment *proto.TreeLocationCommitment
	Root                           proto.TreeRoot
	LocationVRFID                  *proto.LocationVRFID
	NextLocationCommitment         proto.TreeLocationCommitment
	Subkey                         EntityPublic
	Seqno                          proto.Seqno
}

func OpenEldestLink(
	link *proto.LinkOuter,
	hepks *HEPKSet,
	hostID proto.HostID,
) (
	res *OpenEldestRes,
	err error,
) {

	odc, err := OpenDeviceChange(link, hepks, nil, hostID)
	if err != nil {
		return nil, err
	}
	return OpenEldestLinkWithODC(link, hostID, odc)
}

func CheckEldestChainer(b proto.BaseChainer) error {
	if !b.Seqno.IsValid() {
		return LinkError("invalid seqno for eldest chainlink")
	}
	if !b.Seqno.IsEldest() {
		return LinkError("need seqno=0 for eldest chainlink")
	}
	if b.Prev != nil {
		return LinkError("need nil hash for eldest chainlink")
	}
	return nil
}

var FirstPUKGeneration = proto.FirstGeneration

func OpenEldestLinkWithODC(
	link *proto.LinkOuter,
	hostID proto.HostID,
	odc *OpenDeviceChangeRes,
) (
	*OpenEldestRes,
	error,
) {

	if len(odc.Gc.Changes) != 1 || odc.newDevice == nil || !odc.newDevice.GetRole().IsSet() {
		return nil, LinkError("expected exactly 1 new device for eldest link")
	}

	err := odc.newDevice.GetRole().AssertEq(
		proto.NewRoleDefault(proto.RoleType_OWNER),
		LinkError("expected a role=owner, level=0 role for eldest device"),
	)
	if err != nil {
		return nil, err
	}
	if !odc.Gc.Signer.Key.Eq(odc.newDevice.GetEntityID()) {
		return nil, LinkError("mismatched self-signing public keys")
	}
	if len(odc.SharedKeys) != 1 {
		return nil, LinkError("expected exactly one PUK for eldest link")
	}
	if odc.Gc.Signer.KeyOwner != nil {
		return nil, LinkError("expected a nil Signer.KeyOwner for user-sigchain links")
	}
	sharedKey := odc.SharedKeys[0]
	if !odc.Gc.Entity.Entity.RollingEq(sharedKey.VerifyKey) {
		return nil, LinkError("mismatched entity for User in eldest link")
	}
	err = sharedKey.Role.AssertEq(
		proto.NewRoleDefault(proto.RoleType_OWNER),
		LinkError("expected role=owner PUK for eldest"),
	)
	if err != nil {
		return nil, err
	}
	if sharedKey.Gen != FirstPUKGeneration {
		return nil, LinkError("expected seqno=1 PUK for eldest")
	}

	if len(odc.Gc.Metadata) < 3 {
		return nil, LinkError("expected at least 3 metadata changes")
	}
	userCommitment, err := openUsername(odc.Gc.Metadata[0])
	if err != nil {
		return nil, err
	}
	devCommitment, err := openDeviceName(odc.Gc.Metadata[1])
	if err != nil {
		return nil, err
	}
	sctlc, err := openSubchainTreeLocationCommitment(odc.Gc.Metadata[2])
	if err != nil {
		return nil, err
	}

	err = CheckEldestChainer(odc.Gc.Chainer.Base)
	if err != nil {
		return nil, err
	}

	uid, err := odc.Gc.Entity.Entity.ToUID()
	if err != nil {
		return nil, err
	}

	return &OpenEldestRes{
		Uid:                            uid,
		Device:                         odc.newDevice,
		UserKey:                        sharedKey,
		DeviceNameCommitment:           devCommitment,
		UsernameCommitment:             userCommitment,
		SubchainTreeLocationCommitment: sctlc,
		Root:                           odc.Gc.Chainer.Base.Root,
		LocationVRFID:                  odc.Gc.LocationVRFID,
		NextLocationCommitment:         odc.Gc.Chainer.NextLocationCommitment,
		Subkey:                         odc.Subkey,
		Seqno:                          odc.Gc.Chainer.Base.Seqno,
	}, nil
}

func OpenGroupChange(
	link *proto.LinkOuter,
) (
	gc *proto.GroupChange,
	lov1p *proto.LinkOuterV1,
	err error,
) {
	v, err := link.GetV()
	if err != nil {
		return nil, nil, err
	}
	if v != proto.LinkVersion_V1 {
		return nil, nil, VersionNotSupportedError("can only handle outer links V1")
	}
	lov1 := link.V1()
	li, err := lov1.Inner.AllocAndDecode(DecoderFactory{})
	if err != nil {
		return nil, nil, err
	}
	typ, err := li.GetT()
	if err != nil {
		return nil, nil, err
	}
	if typ != proto.LinkType_GROUP_CHANGE {
		return nil, nil, LinkError("unknown link type: " + proto.LinkTypeRevMap[typ])
	}
	ret := li.GroupChange()
	return &ret, &lov1, nil
}

type OpenDeviceChangeRes struct {
	Gc             *proto.GroupChange
	lov1           *proto.LinkOuterV1
	verifiers      []Verifier
	newDevice      PublicSuiter
	RawNewDevice   *proto.MemberRole
	ExistingDevice EntityPublic
	SharedKeys     []SharedPublicSuite
	Subkey         EntityPublic
	LastSigner     EntityPublic
}

func OpenSharedKeys(
	gc *proto.GroupChange,
	hepks *HEPKSet,
) (
	[]Verifier,
	[]SharedPublicSuite,
	error,
) {

	var verifiers []Verifier
	var sharedKeys []SharedPublicSuite
	for i, sk := range gc.SharedKeys {
		if i >= 1 {
			lt, err := gc.SharedKeys[i-1].Role.LessThan(sk.Role)
			if err != nil {
				return nil, nil, err
			}
			if !lt {
				return nil, nil, LinkError("need roles to be in strictly increasing order")
			}
		}
		w, ok := hepks.Lookup(&sk.HepkFp)
		if !ok {
			return nil, nil, KeyNotFoundError{Which: "hepk"}
		}

		sharedKey, err := ImportSharedPublicSuite(&sk, w.Obj())
		if err != nil {
			return nil, nil, err
		}
		verifiers = append(verifiers, sharedKey)
		sharedKeys = append(sharedKeys, *sharedKey)
	}
	return verifiers, sharedKeys, nil
}

func OpenChainer(
	gc *proto.GroupChange,
) error {
	if gc.Chainer.NextLocationCommitment.IsZero() {
		return LinkError("need non-zero next location commitment for all links")
	}
	if (gc.Chainer.Base.Seqno.IsEldest()) != (gc.Chainer.Base.Prev == nil) {
		return LinkError("nil prev hash iff seqno==0")
	}
	if !gc.Chainer.Base.Seqno.IsValid() {
		return LinkError("invalid seqno (< 1)")
	}
	return nil
}

func OpenDeviceChange(
	link *proto.LinkOuter,
	hepks *HEPKSet,
	uid *proto.UID,
	hostID proto.HostID,
) (
	res *OpenDeviceChangeRes,
	err error,
) {
	gc, lov1, err := OpenGroupChange(link)
	if err != nil {
		return nil, err
	}

	if gc.Entity.Entity.Type() != proto.EntityType_User {
		return nil, LinkError("expected a link for a User entity")
	}
	if !hostID.Eq(gc.Entity.Host) {
		return nil, LinkError("wrong host given")
	}
	if uid != nil && !uid.EntityID().Eq(gc.Entity.Entity) {
		return nil, LinkError("wrong user given")
	}

	verifiers, sharedKeys, err := OpenSharedKeys(gc, hepks)
	if err != nil {
		return nil, err
	}

	if len(gc.Changes) > 1 {
		return nil, LinkError("expected 0 or 1 device changes, got more")
	}

	var newDevice PublicSuiter
	var rawNewDeviceP *proto.MemberRole
	var subkey EntityPublic

	if gc.Signer.KeyOwner != nil {
		return nil, LinkError("expected a nil Signer.KeyOwner for user-sigchain links")
	}

	existingDevice, err := ImportEntityPublicWithHost(gc.Signer.Key, hostID)
	if err != nil {
		return nil, err
	}

	if len(gc.Changes) == 1 {
		rt, err := gc.Changes[0].DstRole.GetT()
		if err != nil {
			return nil, err
		}
		if rt != proto.RoleType_NONE {
			rawNewDevice := gc.Changes[0]
			rawNewDeviceP = &rawNewDevice

			newDevice, err = ImportPublicSuite(&rawNewDevice, hepks, hostID)
			if err != nil {
				return nil, err
			}
			if rawNewDevice.Member.Id.Host != nil {
				return nil, LinkError("expected empty host in change")
			}
			kt, err := rawNewDevice.Member.Keys.GetT()
			if err != nil {
				return nil, err
			}
			if kt != proto.MemberKeysType_User {
				return nil, LinkError("expected user keys in change")
			}
			ukeys := rawNewDevice.Member.Keys.User()
			if ukeys.SubKey != nil {
				subkey, err = ImportEntityPublic(*ukeys.SubKey)
				if err != nil {
					return nil, err
				}
				verifiers = append(verifiers, subkey)
			}
			if gc.Chainer.Base.Seqno.IsEldest() {
				eq, err := existingDevice.Eq(newDevice)
				if err != nil {
					return nil, err
				}
				if !eq {
					return nil, LinkError("expected eldest-link to be self-signed")
				}
			} else {
				verifiers = append(verifiers, newDevice)
			}

		}
	}

	lastSigner := existingDevice.ep
	verifiers = append(verifiers, existingDevice.ep)

	err = OpenChainer(gc)
	if err != nil {
		return nil, err
	}

	err = VerifyStackedSignature(lov1, verifiers)
	if err != nil {
		return nil, err
	}

	return &OpenDeviceChangeRes{
		Gc:             gc,
		lov1:           lov1,
		verifiers:      verifiers,
		newDevice:      newDevice,
		ExistingDevice: existingDevice.ep,
		SharedKeys:     sharedKeys,
		RawNewDevice:   rawNewDeviceP,
		Subkey:         subkey,
		LastSigner:     lastSigner,
	}, nil
}

func RandomTreeLocation() (proto.TreeLocation, error) {
	var ret proto.TreeLocation
	err := RandomFill((ret[:]))
	if err != nil {
		return ret, err
	}
	return ret, nil
}

type MakeLinkResBase struct {
	Link                     *proto.LinkOuter
	NextTreeLocation         *proto.TreeLocation
	SubchainTreeLocationSeed *proto.TreeLocation
	HEPKSet                  *proto.HEPKSet
	Seqno                    proto.Seqno
}

type MakeLinkRes struct {
	MakeLinkResBase
	DevNameCommitmentKey  *proto.RandomCommitmentKey
	UsernameCommitmentKey *proto.RandomCommitmentKey
}

func MakeEldestLink(
	host proto.HostID,
	username rem.NameCommitment,
	device PrivateSuiter,
	userKey SharedPrivateSuiter,
	deviceLabel proto.DeviceLabel,
	root proto.TreeRoot,
	subkey EntityPrivate,
) (*MakeLinkRes, error) {

	if !username.Seq.IsValid() {
		return nil, InternalError("invalid seqno for username passed to MakeEldestLink")
	}

	usernameRck, usernameCommit, err := Commit(&username)
	if err != nil {
		return nil, err
	}

	devRck, devCommit, err := Commit(&deviceLabel)
	if err != nil {
		return nil, err
	}
	deviceID, err := device.EntityID()
	if err != nil {
		return nil, err
	}
	ske, skHepk, err := userKey.ExportToSharedKey()
	if err != nil {
		return nil, err
	}
	user, err := ske.VerifyKey.Persistent()
	if err != nil {
		return nil, err
	}
	deviceMember, err := device.ExportToMember(host)
	if err != nil {
		return nil, err
	}

	treeLoc, treeLocCommitment, err := MakeTreeLocation()
	if err != nil {
		return nil, err
	}

	sctl, sctlc, err := MakeTreeLocation()
	if err != nil {
		return nil, err
	}

	hepkDev, err := device.ExportHEPK()
	if err != nil {
		return nil, err
	}

	hepks := proto.HEPKSet{
		V: []proto.HEPK{
			*skHepk,
			*hepkDev,
		},
	}
	seqno := proto.ChainEldestSeqno

	gc := proto.GroupChange{
		Chainer: proto.HidingChainer{
			Base: proto.BaseChainer{
				Seqno: seqno,
				Root:  root,
				Time:  proto.Now(),
			},
			NextLocationCommitment: *treeLocCommitment,
		},
		Entity: proto.FQEntity{
			Host:   host,
			Entity: user,
		},
		Signer: proto.GroupChangeSigner{
			Key: deviceID,
		},
		Changes: []proto.MemberRole{
			{
				DstRole: proto.OwnerRole,
				Member:  *deviceMember,
			},
		},
		SharedKeys: []proto.SharedKey{*ske},
		Metadata: []proto.ChangeMetadata{
			proto.NewChangeMetadataWithUsername(*usernameCommit),
			proto.NewChangeMetadataWithDevicename(*devCommit),
			proto.NewChangeMetadataWithEldest(
				proto.EldestMetadata{
					SubchainTreeLocationSeedCommitment: *sctlc,
				},
			),
		},
	}

	// Subkeys are used mainly for yubikeys, so we can have an "always-on"
	// key for authentication, without spamming the yubikey for signautres.
	// A PUK almost works here, but there are annoying corner cases to consider
	// like PUK rotation on a different device calling this device's sessions
	// to be invalidated.
	err = addSubkey(&gc, subkey)
	if err != nil {
		return nil, err
	}

	li := proto.NewLinkInnerWithGroupChange(gc)
	b, err := li.EncodeTyped(EncoderFactory{})
	if err != nil {
		return nil, err
	}
	lo := proto.LinkOuterV1{
		Inner: *b,
	}
	signingKeys := []Signer{userKey}
	if subkey != nil {
		signingKeys = append(signingKeys, subkey)
	}
	signingKeys = append(signingKeys, device)

	err = SignStacked(&lo, signingKeys)
	if err != nil {
		return nil, err
	}
	link := proto.NewLinkOuterWithV1(lo)
	ret := MakeLinkRes{
		MakeLinkResBase: MakeLinkResBase{
			Link:                     &link,
			NextTreeLocation:         treeLoc,
			SubchainTreeLocationSeed: sctl,
			HEPKSet:                  &hepks,
			Seqno:                    seqno,
		},
		DevNameCommitmentKey:  devRck,
		UsernameCommitmentKey: usernameRck,
	}
	return &ret, nil
}

func MakeChangeUsernameLink(
	uid proto.UID,
	host proto.HostID,
	signingDevice PrivateSuiter,
	username rem.NameCommitment,
	seqno proto.Seqno,
	prev proto.LinkHash,
	root proto.TreeRoot,
) (*MakeLinkRes, error) {

	if !username.Seq.IsValid() {
		return nil, InternalError("invalid seqno for username passed to MakeChangeUsernameLink")
	}
	usernameRck, usernameCommit, err := Commit(&username)
	if err != nil {
		return nil, err
	}
	deviceID, err := signingDevice.EntityID()
	if err != nil {
		return nil, err
	}
	treeLoc, treeLocCommitment, err := MakeTreeLocation()
	if err != nil {
		return nil, err
	}
	gc := proto.GroupChange{
		Chainer: proto.HidingChainer{
			Base: proto.BaseChainer{
				Seqno: seqno,
				Prev:  &prev,
				Root:  root,
				Time:  proto.Now(),
			},
			NextLocationCommitment: *treeLocCommitment,
		},
		Entity: proto.FQEntity{
			Host:   host,
			Entity: uid.EntityID(),
		},
		Signer: proto.GroupChangeSigner{
			Key: deviceID,
		},
		Metadata: []proto.ChangeMetadata{
			proto.NewChangeMetadataWithUsername(*usernameCommit),
		},
	}
	li := proto.NewLinkInnerWithGroupChange(gc)
	b, err := EncodeToBytes(&li)
	if err != nil {
		return nil, err
	}
	lo := proto.LinkOuterV1{
		Inner: b,
	}
	signingKeys := []Signer{signingDevice}
	err = SignStacked(&lo, signingKeys)
	if err != nil {
		return nil, err
	}
	link := proto.NewLinkOuterWithV1(lo)
	ret := MakeLinkRes{
		MakeLinkResBase: MakeLinkResBase{
			Link:             &link,
			NextTreeLocation: treeLoc,
		},
		UsernameCommitmentKey: usernameRck,
	}
	return &ret, nil
}

func MakeRevokeLink(
	uid proto.UID,
	host proto.HostID,
	signingDevice PrivateSuiter,
	targetDevice PublicSuiter,
	newUserKeys []SharedPrivateSuiter,
	seqno proto.Seqno,
	prev proto.LinkHash,
	root proto.TreeRoot,
) (*MakeLinkRes, error) {

	deviceID, err := signingDevice.EntityID()
	if err != nil {
		return nil, err
	}

	sharedKeys := make([]proto.SharedKey, len(newUserKeys))
	hepks := proto.HEPKSet{
		V: make([]proto.HEPK, len(newUserKeys)),
	}
	for i, puk := range newUserKeys {
		x, hepk, err := puk.ExportToSharedKey()
		if err != nil {
			return nil, err
		}
		sharedKeys[i] = *x
		hepks.V[i] = *hepk
	}

	treeLoc, treeLocCommitment, err := MakeTreeLocation()
	if err != nil {
		return nil, err
	}

	// On a rotate after a revoke, there might not be a target device to revoke.
	var changes []proto.MemberRole
	if targetDevice != nil {
		changes = []proto.MemberRole{
			{
				Member: proto.Member{
					Id: proto.FQEntityInHostScope{
						Entity: targetDevice.GetEntityID(),
					},
					Keys: proto.NewMemberKeysWithNone(),
				},
				DstRole: proto.NewRoleDefault(proto.RoleType_NONE),
			},
		}
	}

	gc := proto.GroupChange{
		Chainer: proto.HidingChainer{
			Base: proto.BaseChainer{
				Seqno: seqno,
				Prev:  &prev,
				Root:  root,
				Time:  proto.Now(),
			},
			NextLocationCommitment: *treeLocCommitment,
		},
		Entity: proto.FQEntity{
			Host:   host,
			Entity: uid.EntityID(),
		},
		Signer: proto.GroupChangeSigner{
			Key: deviceID,
		},
		Changes:    changes,
		SharedKeys: sharedKeys,
	}
	li := proto.NewLinkInnerWithGroupChange(gc)
	b, err := EncodeToBytes(&li)
	if err != nil {
		return nil, err
	}
	lo := proto.LinkOuterV1{
		Inner: b,
	}
	var signingKeys []Signer
	for _, puk := range newUserKeys {
		signingKeys = append(signingKeys, puk)
	}
	signingKeys = append(signingKeys, signingDevice)
	err = SignStacked(&lo, signingKeys)
	if err != nil {
		return nil, err
	}
	link := proto.NewLinkOuterWithV1(lo)
	ret := MakeLinkRes{
		MakeLinkResBase: MakeLinkResBase{
			Link:             &link,
			NextTreeLocation: treeLoc,
			HEPKSet:          &hepks,
		},
	}
	return &ret, nil
}

func MakeProvisionLink(
	uid proto.UID,
	host proto.HostID,
	existingDevice PublicSuiter,
	newDevice PrivateSuiter,
	newDeviceRole proto.Role,
	newUserKey SharedPrivateSuiter,
	deviceLabel proto.DeviceLabel,
	seqno proto.Seqno,
	prev proto.LinkHash,
	root proto.TreeRoot,
	subkey EntityPrivate,
) (*MakeLinkRes, error) {

	newDevicePub, err := newDevice.Publicize(nil)
	if err != nil {
		return nil, err
	}
	res, err := MakeProvisionLinkWithPub(
		uid,
		host,
		existingDevice,
		newDevicePub,
		newDeviceRole,
		newUserKey,
		deviceLabel,
		seqno,
		prev,
		root,
		subkey,
	)
	if err != nil {
		return nil, err
	}
	lo := res.Link
	lo, err = CountersignProvisionLink(lo, newDevice)
	if err != nil {
		return nil, err
	}
	res.Link = lo
	return res, nil
}

func addSubkey(gc *proto.GroupChange, subkey EntityPrivate) error {
	if subkey == nil {
		return nil
	}
	ep, err := subkey.EntityPublic()
	if err != nil {
		return err
	}
	id := ep.GetEntityID()
	chng := gc.Changes[0]
	ktyp, err := chng.Member.Keys.GetT()
	if err != nil {
		return err
	}
	if ktyp != proto.MemberKeysType_User {
		return InternalError("expected user keys")
	}
	ukeys := chng.Member.Keys.User()
	ukeys.SubKey = &id
	gc.Changes[0].Member.Keys = proto.NewMemberKeysWithUser(ukeys)

	return nil
}

func MakeProvisionLinkWithPub(
	uid proto.UID,
	host proto.HostID,
	existingDevice PublicSuiter,
	newDevice PublicSuiter,
	newDeviceRole proto.Role,
	newUserKey SharedPrivateSuiter,
	deviceLabel proto.DeviceLabel,
	seqno proto.Seqno,
	prev proto.LinkHash,
	root proto.TreeRoot,
	subkey EntityPrivate,
) (*MakeLinkRes, error) {

	rck, commit, err := Commit(&deviceLabel)
	if err != nil {
		return nil, err
	}
	deviceID := existingDevice.GetEntityID()
	var ske *proto.SharedKey
	var hepks proto.HEPKSet
	if newUserKey != nil {
		tmp, hepk, err := newUserKey.ExportToSharedKey()
		if err != nil {
			return nil, err
		}
		ske = tmp
		hepks.V = []proto.HEPK{*hepk}
	}

	deviceMember, hepk, err := newDevice.ExportToMember(host)
	if err != nil {
		return nil, err
	}
	hepks.V = append(hepks.V, *hepk)

	treeLoc, treeLocCommitment, err := MakeTreeLocation()
	if err != nil {
		return nil, err
	}

	gc := proto.GroupChange{
		Chainer: proto.HidingChainer{
			Base: proto.BaseChainer{
				Seqno: seqno,
				Prev:  &prev,
				Root:  root,
				Time:  proto.Now(),
			},
			NextLocationCommitment: *treeLocCommitment,
		},
		Entity: proto.FQEntity{
			Host:   host,
			Entity: uid.EntityID(),
		},
		Signer: proto.GroupChangeSigner{
			Key: deviceID,
		},
		Changes: []proto.MemberRole{
			{
				Member:  *deviceMember,
				DstRole: newDeviceRole,
			},
		},
		Metadata: []proto.ChangeMetadata{proto.NewChangeMetadataWithDevicename(*commit)},
	}
	if ske != nil {
		gc.SharedKeys = []proto.SharedKey{*ske}
	}
	err = addSubkey(&gc, subkey)
	if err != nil {
		return nil, err
	}

	li := proto.NewLinkInnerWithGroupChange(gc)
	b, err := EncodeToBytes(&li)
	if err != nil {
		return nil, err
	}
	lo := proto.LinkOuterV1{
		Inner: b,
	}
	var signers []Signer
	if newUserKey != nil {
		signers = append(signers, newUserKey)
	}
	if subkey != nil {
		signers = append(signers, subkey)
	}

	if len(signers) > 0 {
		err = SignStacked(&lo, signers)
		if err != nil {
			return nil, err
		}
	}
	link := proto.NewLinkOuterWithV1(lo)
	ret := MakeLinkRes{
		MakeLinkResBase: MakeLinkResBase{
			Link:             &link,
			NextTreeLocation: treeLoc,
			HEPKSet:          &hepks,
		},
		DevNameCommitmentKey: rck,
	}
	return &ret, nil
}

func OpenLinkV1(link *proto.LinkOuter) (*proto.LinkOuterV1, error) {
	v, err := link.GetV()
	if err != nil {
		return nil, err
	}
	if v != proto.LinkVersion_V1 {
		return nil, VersionNotSupportedError("can only support link V1s")
	}
	lov1 := link.V1()
	return &lov1, nil
}

func CountersignProvisionLinkReturnSig(
	link *proto.LinkOuter,
	device Signer,
) (*proto.Signature, *proto.LinkOuterV1, error) {
	lov1, err := OpenLinkV1(link)
	if err != nil {
		return nil, nil, err
	}
	sig, err := device.Sign(lov1)
	if err != nil {
		return nil, nil, err
	}
	return sig, lov1, nil
}

func CountersignProvisionLink(
	link *proto.LinkOuter,
	device Signer,
) (*proto.LinkOuter, error) {
	sig, lov1, err := CountersignProvisionLinkReturnSig(link, device)
	if err != nil {
		return nil, err
	}
	lov1.Signatures = append(lov1.Signatures, *sig)
	ret := proto.NewLinkOuterWithV1(*lov1)
	return &ret, nil
}

func VerifyTreeLocationCommitment(loc proto.TreeLocation, given proto.TreeLocationCommitment) error {
	computed, err := PrefixedHash(&loc)
	if err != nil {
		return err
	}
	if !computed.Eq(proto.StdHash(given)) {
		return CommitmentError("bad location commitment")
	}
	return nil
}

type OpenAndVerifyGenericLinkRes struct {
	Blob     proto.LinkInnerBlob
	Link     proto.GenericLink
	Verifier EntityPublic
}

func OpenAndVerifyGenericLink(
	link proto.LinkOuter,
) (
	*OpenAndVerifyGenericLinkRes,
	error,
) {
	v, err := link.GetV()
	if err != nil {
		return nil, err
	}
	if v != proto.LinkVersion_V1 {
		return nil, VersionNotSupportedError("can only support link V1s")
	}
	lov1 := link.V1()
	li, err := lov1.Inner.AllocAndDecode(DecoderFactory{})
	if err != nil {
		return nil, err
	}
	typ, err := li.GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.LinkType_GENERIC {
		return nil, LinkError("expected a generic link")
	}
	glink := li.Generic()
	if len(lov1.Signatures) != 1 {
		return nil, LinkError("expected exactly one signature for a generic link")
	}

	ep, err := ImportEntityPublic(glink.Signer.Entity)
	if err != nil {
		return nil, err
	}

	err = VerifyStackedSignature(&lov1, []Verifier{ep})
	if err != nil {
		return nil, err
	}

	return &OpenAndVerifyGenericLinkRes{
		Blob:     lov1.Inner,
		Link:     li.Generic(),
		Verifier: ep,
	}, nil
}

func MakeGenericLink(
	eid proto.EntityID,
	host proto.HostID,
	signer PrivateSuiter,
	payload proto.GenericLinkPayload,
	seqno proto.Seqno,
	prev *proto.LinkHash,
	root proto.TreeRoot,
) (
	*MakeLinkRes,
	error,
) {

	if !seqno.IsValid() {
		return nil, InternalError("invalid seqno passed to MakeGenericLink")
	}

	deviceID, err := signer.EntityID()
	if err != nil {
		return nil, err
	}

	treeLoc, treeLocCommitment, err := MakeTreeLocation()
	if err != nil {
		return nil, err
	}

	gl := proto.GenericLink{
		Chainer: proto.HidingChainer{
			Base: proto.BaseChainer{
				Seqno: seqno,
				Prev:  prev,
				Root:  root,
			},
			NextLocationCommitment: *treeLocCommitment,
		},
		Entity: proto.FQEntity{
			Host:   host,
			Entity: eid,
		},
		Signer: proto.FQEntityInHostScope{
			Entity: deviceID,
		},
		Payload: payload,
	}
	li := proto.NewLinkInnerWithGeneric(gl)
	b, err := EncodeToBytes(&li)
	if err != nil {
		return nil, err
	}
	lo := proto.LinkOuterV1{
		Inner: b,
	}
	signingKeys := []Signer{signer}
	err = SignStacked(&lo, signingKeys)
	if err != nil {
		return nil, err
	}
	link := proto.NewLinkOuterWithV1(lo)
	ret := MakeLinkRes{
		MakeLinkResBase: MakeLinkResBase{
			Link:             &link,
			NextTreeLocation: treeLoc,
		},
	}
	return &ret, nil
}
