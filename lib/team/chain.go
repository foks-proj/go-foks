// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package team

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type PTKGens map[core.RoleKey]proto.Generation

type OpeanTeamLinkRes struct {
	Gc         proto.GroupChange
	SharedKeys []core.SharedPublicSuite
	signer     core.EntityPublic
	RosterPost *Roster
	Sched      KeySchedule
	Tnc        *proto.Commitment
	Range      *core.RationalRange
}

type OpenEldestRes struct {
	OpeanTeamLinkRes
	Stltc proto.TreeLocationCommitment
}

func OpenEldestLink(
	link *proto.LinkOuter,
	hepks *core.HEPKSet,
	hostID proto.HostID,
) (
	*OpenEldestRes,
	error,
) {
	otlr, err := OpenTeamLink(link, hepks, nil, hostID, nil)
	if err != nil {
		return nil, err
	}
	return OpenEldestLinkWithOTLR(link, hostID, otlr)
}

func FindChangeForMember(changes []proto.MemberRole, ko proto.KeyOwner) *proto.MemberRole {
	for _, chng := range changes {
		if chng.Member.Id.Entity.Eq(ko.Party.EntityID()) && chng.Member.Id.Host == nil {
			eq, err := chng.Member.SrcRole.Eq(ko.SrcRole)
			if err == nil && eq {
				return &chng
			}
		}
	}
	return nil
}

func findSharedKeyForRole(k []proto.SharedKey, role proto.Role) (*proto.SharedKey, error) {
	for _, sk := range k {
		eq, err := sk.Role.Eq(role)
		if err != nil {
			return nil, err
		}
		if eq {
			return &sk, nil
		}
	}
	return nil, nil
}

func OpenEldestLinkWithOTLR(
	link *proto.LinkOuter,
	hostID proto.HostID,
	otlr *OpeanTeamLinkRes,
) (
	*OpenEldestRes,
	error,
) {

	ret := OpenEldestRes{
		OpeanTeamLinkRes: *otlr,
	}

	if len(otlr.Gc.Metadata) < 3 {
		return nil, core.LinkError("eldest link must have at least three metadata entries")
	}

	typ, err := otlr.Gc.Metadata[0].GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.ChangeType_Teamname {
		return nil, core.LinkError("first metadata entry must be a teamname commitment")
	}
	if otlr.Tnc == nil {
		return nil, core.LinkError("eldest link must have a teamname commitment")
	}
	typ, err = otlr.Gc.Metadata[1].GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.ChangeType_Eldest {
		return nil, core.LinkError("second metadata entry must be an eldest metadata")
	}
	ret.Stltc = otlr.Gc.Metadata[1].Eldest().SubchainTreeLocationSeedCommitment

	typ, err = otlr.Gc.Metadata[2].GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.ChangeType_TeamIndexRange {
		return nil, core.LinkError("third metadata entry must be a team index range")
	}
	tmp := core.NewRationalRange(otlr.Gc.Metadata[2].Teamindexrange())
	ret.Range = &tmp

	err = core.CheckEldestChainer(otlr.Gc.Chainer.Base)
	if err != nil {
		return nil, err
	}

	// Check that the signer is part of the team, and an owner
	signerChange := FindChangeForMember(otlr.Gc.Changes, *otlr.Gc.Signer.KeyOwner)
	if signerChange == nil {
		return nil, core.LinkError("signer must be a member of the team")
	}
	err = signerChange.DstRole.AssertEq(proto.OwnerRole, core.LinkError("signer must be an owner"))
	if err != nil {
		return nil, err
	}

	// Check that the admin key (v0) is the same ID as the team ID.
	adminKey, err := findSharedKeyForRole(otlr.Gc.SharedKeys, proto.AdminRole)
	if adminKey == nil {
		return nil, core.LinkError("an owner key must exist for a new team")
	}
	if err != nil {
		return nil, err
	}
	if !otlr.Gc.Entity.Entity.RollingEq(adminKey.VerifyKey) {
		return nil, core.LinkError("team ID mismatch")
	}

	return &ret, nil
}

// We need to lock operations on this team before we officially "open it".
// So at first we just extract the teamID and the seqno, then lock, then we
// go back and open it. Slightly duplicative but not the end of the world.
func ExtractTeamAndSeqno(
	link *proto.LinkOuter,
) (
	*proto.TeamID,
	proto.Seqno,
	error,
) {
	gc, _, err := core.OpenGroupChange(link)
	if err != nil {
		return nil, 0, err
	}
	tid, err := gc.Entity.Entity.ToTeamID()
	if err != nil {
		return nil, 0, err
	}
	return &tid, gc.Chainer.Base.Seqno, nil
}

func OpenTeamLink(
	link *proto.LinkOuter,
	hepks *core.HEPKSet,
	team *proto.TeamID,
	hostID proto.HostID,
	rPre *Roster,
) (
	*OpeanTeamLinkRes,
	error,
) {

	gc, lo1, err := core.OpenGroupChange(link)
	if err != nil {
		return nil, err
	}
	if gc.Entity.Entity.Type() != proto.EntityType_Team {
		return nil, core.LinkError("expected a link for a Team entity")
	}
	if !hostID.Eq(gc.Entity.Host) {
		return nil, core.LinkError("wrong host given")
	}
	if team != nil && !team.EntityID().Eq(gc.Entity.Entity) {
		return nil, core.LinkError("wrong user given")
	}
	verifiers, sharedKeys, err := core.OpenSharedKeys(gc, hepks)
	if err != nil {
		return nil, err
	}
	signerEp, err := core.ImportEntityPublic(gc.Signer.Key)
	if err != nil {
		return nil, err
	}
	if gc.Signer.KeyOwner == nil {
		return nil, core.LinkError("team links must specify siging key owners")
	}
	verifiers = append(verifiers, signerEp)

	// The link is countersigned with the new team keys we are introducing,
	// and also whoever the signer is. Verify it as quickly as we can.
	// We later need to check the signer was a legit signer for this link.
	err = core.VerifyStackedSignature(lo1, verifiers)
	if err != nil {
		return nil, err
	}

	err = core.OpenChainer(gc)
	if err != nil {
		return nil, err
	}

	mrq := make([]proto.MemberRoleSeqno, len(gc.Changes))
	for i, ch := range gc.Changes {
		mrq[i] = proto.MemberRoleSeqno{
			Mr:    ch,
			Seqno: gc.Chainer.Base.Seqno,
			Time:  gc.Chainer.Base.Time,
		}
	}

	// Given the current roster, the signer ID, and the changes, compute
	// the new roster, the rekey schedule. Also check the changes for sanity.
	rPost, sched, err := rPre.Gameplan(*gc.Signer.KeyOwner, hostID, mrq, gc.Signer.Key, nil)
	if err != nil {
		return nil, err
	}

	var tnc *proto.Commitment
	var rng *core.RationalRange
	// Open link metadata -- only team name changes are supported now, and team index range changes are supported.
	for _, md := range gc.Metadata {
		typ, err := md.GetT()
		if err != nil {
			return nil, err
		}
		switch typ {
		case proto.ChangeType_Teamname:
			if tnc != nil {
				return nil, core.LinkError("only one teamname commitment allowed")
			}
			tmp := md.Teamname()
			tnc = &tmp
		case proto.ChangeType_TeamIndexRange:
			if rng != nil {
				return nil, core.LinkError("only one team index range allowed")
			}
			tmp := core.NewRationalRange(md.Teamindexrange())
			rng = &tmp
		}
	}

	ret := OpeanTeamLinkRes{
		Gc:         *gc,
		SharedKeys: sharedKeys,
		signer:     signerEp,
		RosterPost: rPost,
		Sched:      *sched,
		Tnc:        tnc,
		Range:      rng,
	}

	return &ret, nil
}

type MakeLinkRes struct {
	core.MakeLinkResBase
	TeamnameCommitmentKey *proto.RandomCommitmentKey
	TeamID                proto.EntityID
}

func exportToMemberRole(
	role proto.Role,
	host proto.HostID,
	fqe proto.FQEntity,
	sk proto.SharedKey,
	removalKeyCommitment proto.KeyCommitment,
) proto.MemberRole {
	tmk := sk.ToTeamMemberKeys(nil)
	tmk.Trkc = &removalKeyCommitment
	return proto.MemberRole{
		DstRole: role,
		Member: proto.Member{
			Id:      fqe.AtHost(host),
			SrcRole: sk.Role,
			Keys:    proto.NewMemberKeysWithTeam(tmk),
		},
	}
}

func EldestRoles() []proto.Role {
	return []proto.Role{
		proto.MinKVRole,
		proto.DefaultRole,
		proto.NewRoleDefault(proto.RoleType_ADMIN),
		proto.NewRoleDefault(proto.RoleType_OWNER),
	}
}

func MakeEldestLink(
	host proto.HostID,
	name rem.NameCommitment,
	owner proto.KeyOwner, // can be either a team or a user
	uotKey core.SharedPrivateSuiter, // for users, the current PUK; for teams, the current PTK (uot = user or team)
	teamKeys []core.SharedPrivateSuiter,
	root proto.TreeRoot,
	removalKeyCommitment proto.KeyCommitment,
) (*MakeLinkRes, error) {

	teamRck, teamCom, err := core.Commit(&name)
	if err != nil {
		return nil, err
	}
	signerID, err := uotKey.EntityID()
	if err != nil {
		return nil, err
	}

	var tkes []proto.SharedKey
	var adminTke *proto.SharedKey
	for _, tk := range teamKeys {
		tke, _, err := tk.ExportToSharedKey()
		if err != nil {
			return nil, err
		}
		tkes = append(tkes, *tke)
		r, err := tke.Role.GetT()
		if err != nil {
			return nil, err
		}
		if r == proto.RoleType_ADMIN {
			adminTke = tke
		}
	}
	if len(teamKeys) != len(EldestRoles()) {
		return nil, core.LinkError("need 3 PTKs for a new team")
	}
	if adminTke == nil {
		return nil, core.LinkError("need an ADMIN PTK for a new team")
	}
	team, err := adminTke.VerifyKey.Persistent()
	if err != nil {
		return nil, err
	}

	treeLoc, treeLocCommitment, err := core.MakeTreeLocation()
	if err != nil {
		return nil, err
	}

	sctl, sctlc, err := core.MakeTreeLocation()
	if err != nil {
		return nil, err
	}

	ownerSharedKey, _, err := uotKey.ExportToSharedKey()
	if err != nil {
		return nil, err
	}

	ownerChange := exportToMemberRole(
		proto.OwnerRole,
		host,
		owner.Party.EntityID().ScopeToHost(host),
		*ownerSharedKey,
		removalKeyCommitment,
	)

	gc := proto.GroupChange{
		Chainer: proto.HidingChainer{
			Base: proto.BaseChainer{
				Seqno: proto.ChainEldestSeqno,
				Root:  root,
				Time:  proto.Now(),
			},
			NextLocationCommitment: *treeLocCommitment,
		},
		Entity: proto.FQEntity{
			Host:   host,
			Entity: team,
		},
		Signer: proto.GroupChangeSigner{
			Key:      signerID,
			KeyOwner: &owner,
		},
		Changes:    []proto.MemberRole{ownerChange},
		SharedKeys: tkes,
		Metadata: []proto.ChangeMetadata{
			proto.NewChangeMetadataWithTeamname(*teamCom),
			proto.NewChangeMetadataWithEldest(
				proto.EldestMetadata{
					SubchainTreeLocationSeedCommitment: *sctlc,
				},
			),
			proto.NewChangeMetadataWithTeamindexrange(
				core.NewDefaultRange().RationalRange,
			),
		},
	}

	li := proto.NewLinkInnerWithGroupChange(gc)
	b, err := li.EncodeTyped(core.EncoderFactory{})
	if err != nil {
		return nil, err
	}
	lo := proto.LinkOuterV1{
		Inner: *b,
	}
	var signingKeys []core.Signer
	for _, tk := range teamKeys {
		signingKeys = append(signingKeys, tk)
	}
	signingKeys = append(signingKeys, uotKey)

	err = core.SignStacked(&lo, signingKeys)
	if err != nil {
		return nil, err
	}
	link := proto.NewLinkOuterWithV1(lo)

	ret := MakeLinkRes{
		MakeLinkResBase: core.MakeLinkResBase{
			Link:                     &link,
			SubchainTreeLocationSeed: sctl,
			NextTreeLocation:         treeLoc,
		},
		TeamnameCommitmentKey: teamRck,
		TeamID:                team,
	}

	return &ret, nil
}

func MakeTeamLink(
	host proto.HostID,
	team proto.TeamID,
	signerKO proto.KeyOwner,
	signerKey core.SharedPrivateSuiter,
	changes []proto.MemberRole,
	newTeamKeys []core.SharedPrivateSuiter,
	seqno proto.Seqno,
	prev proto.LinkHash,
	root proto.TreeRoot,
	md []proto.ChangeMetadata,
) (
	*core.MakeLinkResBase,
	error,
) {

	var tkes []proto.SharedKey
	var allSigningKeys []core.Signer
	for _, tk := range newTeamKeys {
		tke, _, err := tk.ExportToSharedKey()
		if err != nil {
			return nil, err
		}
		tkes = append(tkes, *tke)
		allSigningKeys = append(allSigningKeys, tk)
	}

	treeLoc, treeLocCommitment, err := core.MakeTreeLocation()
	if err != nil {
		return nil, err
	}

	signerPubKey, _, err := signerKey.ExportToSharedKey()
	if err != nil {
		return nil, err
	}

	allSigningKeys = append(allSigningKeys, signerKey)

	gc := proto.GroupChange{
		Chainer: proto.HidingChainer{
			Base: proto.BaseChainer{
				Seqno: seqno,
				Root:  root,
				Prev:  &prev,
				Time:  proto.Now(),
			},
			NextLocationCommitment: *treeLocCommitment,
		},
		Entity: proto.FQEntity{
			Host:   host,
			Entity: team.EntityID(),
		},
		Signer: proto.GroupChangeSigner{
			Key:      signerPubKey.VerifyKey,
			KeyOwner: &signerKO,
		},
		Changes:    changes,
		SharedKeys: tkes,
		Metadata:   md,
	}

	li := proto.NewLinkInnerWithGroupChange(gc)
	b, err := li.EncodeTyped(core.EncoderFactory{})
	if err != nil {
		return nil, err
	}
	lo := proto.LinkOuterV1{
		Inner: *b,
	}
	err = core.SignStacked(&lo, allSigningKeys)
	if err != nil {
		return nil, err
	}
	link := proto.NewLinkOuterWithV1(lo)

	ret := core.MakeLinkResBase{
		NextTreeLocation: treeLoc,
		Link:             &link,
	}

	return &ret, nil
}

func NewTeamRemovalKey() (*rem.TeamRemovalKey, error) {
	var ret rem.TeamRemovalKey
	err := core.RandomFill(ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func NewBoxedTeamRemovalKey(
	sender core.SharedPrivateSuiter,
	teamReceiver *core.SPSBoxer,
	memberReceiver *core.SPSBoxer,
	md rem.TeamRemovalKeyMetadata,
) (
	*rem.TeamRemovalBoxData,
	*rem.TeamRemovalKey,
	error,
) {
	key, err := NewTeamRemovalKey()
	if err != nil {
		return nil, nil, err
	}
	box, err := BoxTeamRemovalKey(sender, teamReceiver, memberReceiver, md, key)
	if err != nil {
		return nil, nil, err
	}
	return box, key, nil
}

func BoxTeamRemovalKey(
	sender core.SharedPrivateSuiter,
	teamReceiver *core.SPSBoxer,
	memberReceiver *core.SPSBoxer,
	md rem.TeamRemovalKeyMetadata,
	key *rem.TeamRemovalKey,
) (
	*rem.TeamRemovalBoxData,
	error,
) {
	payload := rem.TeamRemovalKeyBoxPayload{
		Md:  md,
		Key: *key,
	}
	boxOne := func(r *core.SPSBoxer) (*proto.TeamRemovalKeyBox, error) {
		box, err := sender.BoxFor(&payload, r, core.BoxOpts{IncludePublicKey: true})
		if err != nil {
			return nil, err
		}
		return &proto.TeamRemovalKeyBox{
			Box: *box,
			EncKey: proto.RoleAndGen{
				Role: r.Role,
				Gen:  r.Gen,
			},
		}, nil
	}

	tm, err := boxOne(teamReceiver)
	if err != nil {
		return nil, err
	}
	mm, err := boxOne(memberReceiver)
	if err != nil {
		return nil, err
	}
	comm, err := core.ComputeKeyCommitment(key)
	if err != nil {
		return nil, err
	}

	return &rem.TeamRemovalBoxData{
		Md:     md,
		Team:   *tm,
		Member: *mm,
		Comm:   *comm,
	}, nil
}
