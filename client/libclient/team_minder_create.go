package libclient

import (
	"slices"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type TeamCreator struct {
	// params passed in from caller
	tm *TeamMinder
	nm proto.NameUtf8 // or empty if ad-hoc team

	// param only needed for ad-hoc teams, which can have multiple
	// founding members. for now, they most be users, and cannot be teams,
	// though we can relax this in the future. Cannot include the owner.
	membs []lcl.FQPartyParsedAndRole

	hepks  core.HEPKSet
	cli    *rem.TeamAdminClient
	au     *UserContext
	rtr    *rem.ReserveNameRes
	nnm    proto.Name // normalized name
	nc     *rem.NameCommitment
	puk    core.SharedPrivateSuiter
	skb    *core.SharedKeyBoxer
	mePub  *core.SPSBoxer
	boxes  *proto.SharedKeyBoxSet
	hostid proto.HostID
	ptks   []core.SharedPrivateSuiter
	ptkMap map[core.RoleKey]core.SharedPrivateSuiter
	tr     *proto.TreeRoot
	rmkey  *rem.TeamRemovalKey
	comm   *proto.KeyCommitment
	mlr    *team.MakeLinkRes
	seqno  proto.Seqno
	tid    proto.TeamID
	fqt    proto.FQTeam
	trkbp  *rem.TeamRemovalBoxData
	glink  *rem.PostGenericLinkArg

	// loaded members for ad-hoc teams, and their public keys
	otherMrs  []proto.MemberRole
	otherPubs []*core.SPSBoxer

	adminPtk    core.SharedPrivateSuiter
	adminPtkPub *core.SPSBoxer

	srcRole proto.Role
	dstRole proto.Role
}

func (t *TeamCreator) TeamID() *proto.TeamID {
	return &t.tid
}

func (t *TeamCreator) setup(m MetaContext) error {
	au, err := t.tm.activeUser(m)
	if err != nil {
		return err
	}
	cli, err := au.TeamAdminClient(m)
	if err != nil {
		return err
	}
	t.au = au
	t.cli = cli
	t.hostid = au.HostID()
	return nil
}

func (t *TeamCreator) setupRoles(m MetaContext) error {
	// For now, only possible to have the user's owner PUK as the time creator, but
	// that is an artificial limitation, can potentially relax it.
	t.srcRole = team.UserSrcRole
	t.dstRole = proto.OwnerRole
	return nil
}

func (t *TeamCreator) reserveTeamname(m MetaContext) error {
	if t.nm.IsZero() {
		return nil
	}
	nnm, err := core.NormalizeName(t.nm)
	if err != nil {
		return err
	}
	rtr, err := t.cli.ReserveTeamname(m.Ctx(), nnm)
	if err != nil {
		return err
	}
	t.rtr = &rtr
	t.nnm = nnm
	t.nc = &rem.NameCommitment{
		Name: nnm,
		Seq:  rtr.Seq,
	}
	return nil
}

func (t *TeamCreator) setupKeys(m MetaContext) error {
	puk := t.au.PrivKeys.LatestPuk()
	if puk == nil {
		return core.KeyNotFoundError{Which: "puk"}
	}
	skb, err := core.NewSharedKeyBoxer(t.hostid, puk)
	if err != nil {
		return err
	}
	mePub, err := core.PublicizeToSPSBoxer(puk, t.au.FQU().FQParty())
	if err != nil {
		return err
	}
	t.puk = puk
	t.skb = skb
	t.mePub = mePub
	return nil
}

// sortPubsLikeSchedule reorders pubs in place to match the order the server
// computes for the KeySchedule's per-role member buckets (MemberID.Cmp), so
// that MatchBoxes lines up box i with member i.
func sortPubsLikeSchedule(pubs []*core.SPSBoxer) error {
	type pubWithID struct {
		pub *core.SPSBoxer
		mid team.MemberID
	}
	keyed := make([]pubWithID, len(pubs))
	for i, pub := range pubs {
		fqef, err := pub.Parent.FQEntity().Fixed()
		if err != nil {
			return err
		}
		rk, err := core.ImportRole(pub.Role)
		if err != nil {
			return err
		}
		keyed[i] = pubWithID{pub: pub, mid: team.MemberID{Fqe: *fqef, SrcRole: *rk}}
	}
	slices.SortFunc(keyed, func(a, b pubWithID) int {
		return a.mid.Cmp(b.mid)
	})
	for i, k := range keyed {
		pubs[i] = k.pub
	}
	return nil
}

func (t *TeamCreator) makeBoxes(m MetaContext) error {
	var ptks []core.SharedPrivateSuiter
	ptkMap := make(map[core.RoleKey]core.SharedPrivateSuiter)
	roles := team.EldestRoles()
	allPubs := []*core.SPSBoxer{t.mePub}
	allPubs = append(allPubs, t.otherPubs...)

	// The server canonicalizes the KeySchedule by sorting the members in each
	// role bucket by MemberID.Cmp (see team.KeySchedule / planChangesLocked),
	// and MatchBoxes then checks the boxes positionally against that sorted
	// order. So we must emit boxes in the same order. Note we sort only the
	// boxes here, not the chain-link changes: the server re-derives and sorts
	// the schedule from the changes, so their order in the link is irrelevant
	// (this mirrors how the edit path's runBoxes follows t.sched).
	if err := sortPubsLikeSchedule(allPubs); err != nil {
		return err
	}

	for _, role := range roles {
		ss := core.RandomSecretSeed32()
		ptk, err := core.NewSharedPrivateSuite25519(
			proto.EntityType_NamedTeam,
			role,
			ss,
			proto.FirstGeneration,
			t.hostid,
		)
		if err != nil {
			return err
		}
		err = t.hepks.AddHEPKExporter(ptk)
		if err != nil {
			return err
		}
		ptks = append(ptks, ptk)
		for _, pub := range allPubs {
			err = t.skb.Box(ptk, pub)
			if err != nil {
				return err
			}
		}
		rk, err := core.ImportRole(role)
		if err != nil {
			return err
		}
		ptkMap[*rk] = ptk
	}
	boxes, err := t.skb.Finish()
	if err != nil {
		return err
	}
	t.boxes = boxes
	t.ptks = ptks
	t.ptkMap = ptkMap
	return nil
}

func (t *TeamCreator) getTreeRoot(m MetaContext) error {
	ma, err := t.au.MerkleAgent(m)
	if err != nil {
		return err
	}
	tr, err := ma.GetLatestTreeRootFromServer(m.Ctx())
	if err != nil {
		return err
	}
	t.tr = &tr
	return nil
}

func (t *TeamCreator) makeRemovalKey(m MetaContext) error {
	// For adhoc teams, no removal key is needed:
	if t.nm.IsZero() {
		return nil
	}
	rmkey, err := team.NewTeamRemovalKey()
	if err != nil {
		return err
	}
	comm, err := core.ComputeKeyCommitment(rmkey)
	if err != nil {
		return err
	}
	t.rmkey = rmkey
	t.comm = comm
	return nil
}

func (t *TeamCreator) makeEldestLink(m MetaContext) error {

	mlr, err := team.MakeEldestLink(
		t.hostid,
		t.nc,
		proto.KeyOwner{
			Party:   t.au.UID().ToPartyID(),
			SrcRole: team.UserSrcRole,
		},
		t.puk,
		t.ptks,
		*t.tr,
		t.comm,
		t.otherMrs,
	)
	if err != nil {
		return err
	}
	t.mlr = mlr
	t.seqno = mlr.Seqno
	t.tid, err = mlr.TeamID.ToTeamID()
	if err != nil {
		return err
	}
	t.fqt = proto.FQTeam{
		Team: t.tid,
		Host: t.hostid,
	}
	return nil
}

func (t *TeamCreator) findAdminPtk(m MetaContext) error {
	adminPtk, found := t.ptkMap[core.AdminRole]
	if !found {
		return core.KeyNotFoundError{Which: "admin PTK"}
	}
	adminPtkPub, err := core.PublicizeToSPSBoxer(adminPtk, t.fqt.FQParty())
	if err != nil {
		return err
	}
	t.adminPtk = adminPtk
	t.adminPtkPub = adminPtkPub
	return nil
}

func (t *TeamCreator) makeRemovalKeyBox(m MetaContext) error {
	// Will be nil for adhoc teams.
	if t.rmkey == nil {
		return nil
	}
	trkbp, err := team.BoxTeamRemovalKey(
		t.puk,
		t.adminPtkPub,
		t.mePub,
		rem.TeamRemovalKeyMetadata{
			Tm:     t.fqt,
			Member: t.au.FQU().FQParty(),
			Dst: proto.RoleAndSeqno{
				Seqno: t.seqno,
				Role:  t.dstRole,
			},
			SrcRole: t.srcRole,
		},
		t.rmkey,
	)
	if err != nil {
		return err
	}
	t.trkbp = trkbp
	return nil
}

func (t *TeamCreator) makeTeamMembershipLink(m MetaContext) error {
	tad := proto.TeamMembershipApprovedDetails{
		Dst: proto.RoleAndSeqno{
			Seqno: t.seqno,
			Role:  t.dstRole,
		},
	}
	if t.trkbp != nil {
		tad.KeyComm = t.trkbp.Comm
	}
	tml := proto.TeamMembershipLink{
		Team:    t.fqt,
		SrcRole: t.srcRole,
		State: proto.NewTeamMembershipDetailsWithApproved(
			tad,
		),
	}
	glp := proto.NewGenericLinkPayloadWithTeammembership(
		tml,
	)
	glink, err := t.tm.makeMembershipChainLink(
		m, nil, glp, t.tr,
	)
	if err != nil {
		return err
	}
	t.glink = glink
	return nil
}

func (t *TeamCreator) postAdhoc(m MetaContext) error {
	if t.rtr != nil {
		return core.InternalError("unexpected non-nil reserve name result")
	}
	if t.mlr == nil {
		return core.InternalError("unexpected nil make link result")
	}
	if t.mlr.TeamnameCommitmentKey != nil {
		return core.InternalError("unexpected non-nil teamname commitment key")
	}
	if t.boxes == nil {
		return core.InternalError("unexpected nil boxes")
	}
	if t.trkbp != nil {
		return core.InternalError("unexpected non-nil removal key box")
	}
	if t.glink == nil {
		return core.InternalError("unexpected non-nil team membership link")
	}
	arg := rem.CreateTeamCommonArg{
		SubchainTreeLocationSeed: *t.mlr.SubchainTreeLocationSeed,
		Eta:                      t.makeEditTeamArg(m),
		TeamMembershipLink:       t.makePostGenericLinkArg(m),
	}
	err := t.cli.CreateTeamAdHoc(m.Ctx(), arg)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamCreator) post(m MetaContext) error {
	if t.nm.IsZero() {
		return t.postAdhoc(m)
	}
	return t.postNamed(m)
}

func (t *TeamCreator) makeEditTeamArg(m MetaContext) rem.EditTeamArg {
	ret := rem.EditTeamArg{
		Link:             *t.mlr.Link,
		NextTreeLocation: *t.mlr.NextTreeLocation,
		Obd: rem.OffchainBoxData{
			PtkBoxes: *t.boxes,
			Hepks:    t.hepks.Export(),
		},
	}
	if t.trkbp != nil {
		ret.Obd.RemovalKeys = []rem.TeamRemovalBoxData{*t.trkbp}
	}
	return ret
}

func (t *TeamCreator) makePostGenericLinkArg(m MetaContext) rem.PostGenericLinkArg {
	return rem.PostGenericLinkArg{
		Link:             t.glink.Link,
		NextTreeLocation: t.glink.NextTreeLocation,
	}
}

func (t *TeamCreator) postNamed(m MetaContext) error {
	if t.rtr == nil {
		return core.InternalError("unexpected nil reserve name result")
	}
	if t.mlr == nil {
		return core.InternalError("unexpected nil make link result")
	}
	if t.mlr.TeamnameCommitmentKey == nil {
		return core.InternalError("unexpected nil teamname commitment key")
	}
	if t.boxes == nil {
		return core.InternalError("unexpected nil boxes")
	}
	if t.trkbp == nil {
		return core.InternalError("unexpected nil removal key box")
	}
	if t.glink == nil {
		return core.InternalError("unexpected nil team membership link")
	}

	eta := t.makeEditTeamArg(m)
	glp := t.makePostGenericLinkArg(m)

	arg := rem.CreateTeamArg{
		NameUtf8:                 t.nm,
		TeamnameCommitmentKey:    *t.mlr.TeamnameCommitmentKey,
		SubchainTreeLocationSeed: *t.mlr.SubchainTreeLocationSeed,
		Rnr:                      *t.rtr,
		Eta:                      eta,
		TeamMembershipLink:       glp,
	}
	err := t.cli.CreateTeam(m.Ctx(), arg)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamCreator) adHocLoadOthers(
	m MetaContext,
) error {
	for _, party := range t.membs {
		err := t.adHocLoadOther(m, party)
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *TeamCreator) adHocLoadOther(
	m MetaContext,
	party lcl.FQPartyParsedAndRole,
) error {
	user, team, err := party.Fqp.Party.Select()
	if err != nil {
		return err
	}
	if team != nil {
		return core.BadArgsError("can only include users as founding members in adhoc teams")
	}
	if user == nil {
		return core.InternalError("unexpected nil user in addHocLoadOther")
	}
	if party.Role != nil && !party.Role.SimpleEq(proto.OwnerRole) {
		return core.BadArgsError("can only include the owner as a founding member in adhoc teams")
	}
	uw, err := LoadUserByFQUserParsed(m,
		proto.FQUserParsed{
			User: *user,
			Host: party.Fqp.Host,
		},
	)
	if err != nil {
		return err
	}
	if !uw.fqu.HostID.Eq(t.hostid) {
		return core.HostMismatchError{}
	}
	id := uw.fqu.ToFQEntity().AtHost(t.hostid)
	rk, err := core.ImportRole(t.srcRole)
	if err != nil {
		return err
	}
	tmk, hepk, err := uw.TeamMemberKeys(*rk)
	if err != nil {
		return err
	}
	err = t.hepks.Add(*hepk)
	if err != nil {
		return err
	}
	mr := proto.MemberRole{
		DstRole: t.dstRole,
		Member: proto.Member{
			Id:      id,
			SrcRole: t.srcRole,
		},
	}
	fqe := mr.Member.Id.WithHost(t.hostid)
	creator := t.au.FQU().ToFQEntity()
	if fqe.Eq(creator) {
		return core.BadArgsError("cannot include the owner in the list of other founding members")
	}

	ps, err := core.ImportSPSBoxer(
		fqe,
		&t.hepks,
		*tmk,
		t.srcRole,
	)
	if err != nil {
		return err
	}

	mr.Member.Keys = proto.NewMemberKeysWithTeam(*tmk)

	t.otherPubs = append(t.otherPubs, ps)
	t.otherMrs = append(t.otherMrs, mr)
	return nil
}

func (t *TeamCreator) adHocPrepareOtherMembers(m MetaContext) error {

	if len(t.membs) == 0 {
		return nil
	}

	if !t.nm.IsZero() {
		return core.InternalError("can only add other founding members to ad-hoc teams")
	}

	err := t.adHocLoadOthers(m)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamCreator) Run(m MetaContext) error {

	err := t.setup(m)
	if err != nil {
		return err
	}
	err = t.setupRoles(m)
	if err != nil {
		return err
	}
	err = t.reserveTeamname(m)
	if err != nil {
		return err
	}
	err = t.setupKeys(m)
	if err != nil {
		return err
	}
	err = t.adHocPrepareOtherMembers(m)
	if err != nil {
		return err
	}
	// Test-only: let a test corrupt the founding membership (e.g. make a member
	// remote) before the eldest link is signed, to exercise server-side rejection.
	if h := t.tm.TestHooks; h != nil && h.AdHocMutateFoundingMembers != nil {
		h.AdHocMutateFoundingMembers(t.otherMrs)
	}
	err = t.makeBoxes(m)
	if err != nil {
		return err
	}
	err = t.getTreeRoot(m)
	if err != nil {
		return err
	}
	err = t.makeRemovalKey(m)
	if err != nil {
		return err
	}
	err = t.makeEldestLink(m)
	if err != nil {
		return err
	}
	err = t.findAdminPtk(m)
	if err != nil {
		return err
	}
	err = t.makeRemovalKeyBox(m)
	if err != nil {
		return err
	}
	err = t.makeTeamMembershipLink(m)
	if err != nil {
		return err
	}
	err = t.post(m)
	if err != nil {
		return err
	}
	return nil
}
