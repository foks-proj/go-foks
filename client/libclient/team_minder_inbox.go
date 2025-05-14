// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

func (t *TeamMinder) createInviteWithTeam(
	m MetaContext,
	tw *TeamRecord,
) (
	*proto.TeamInvite,
	error,
) {
	cert, err := t.getOrMakeCert(m, tw)
	if err != nil {
		return nil, err
	}
	var certHash proto.TeamCertHash
	err = core.PrefixedHashInto(&cert.cert, certHash[:])
	if err != nil {
		return nil, err
	}
	i1 := proto.TeamInviteV1{
		Hsh:  certHash,
		Host: tw.FQT().Host,
	}
	i := proto.NewTeamInviteWithV1(i1)
	return &i, nil
}

func (t *TeamMinder) makeAdminBearerToken(
	m MetaContext,
	tmid proto.FQTeam,
	ptk core.SharedPrivateSuiter,
) (
	*rem.TeamBearerToken,
	error,
) {
	if !tmid.Host.Eq(t.au.HostID()) {
		return nil, core.HostMismatchError{}
	}
	err := ptk.GetRole().AssertAdminOrAbove(core.PermissionError("not admin"))
	if err != nil {
		return nil, err
	}
	cli, err := t.au.TeamAdminClient(m)
	if err != nil {
		return nil, err
	}
	tok, err := cli.MakeInertTeamBearerToken(m.Ctx(),
		rem.MakeInertTeamBearerTokenArg{
			Team: tmid.Team,
			Gen:  ptk.Metadata().Gen,
			Role: ptk.GetRole(),
		},
	)
	if err != nil {
		return nil, err
	}
	sig, obj, err := team.SignBearerTokenChallenge(
		t.au.FQU(),
		tmid.Team,
		ptk.GetRole(),
		ptk.Metadata().Gen,
		tok,
		ptk,
	)
	if err != nil {
		return nil, err
	}
	err = cli.ActivateTeamBearerToken(m.Ctx(),
		rem.ActivateTeamBearerTokenArg{
			Bl:  obj,
			Sig: *sig,
		},
	)
	if err != nil {
		return nil, err
	}
	return &tok, nil
}

func (t *TeamMinder) loadTeamAndAdminToken(
	m MetaContext,
	tmid proto.FQTeam,
	opts LoadTeamOpts,
) (
	*TeamRecord,
	*rem.TeamBearerToken,
	error,
) {
	tm, err := t.LoadTeamWithFQTeam(m, tmid, opts)
	if err != nil {
		return nil, nil, err
	}
	ptks := tm.Tw().KeyRing().KeysForRole(core.AdminRole)
	if ptks == nil || !ptks.LastGen().IsValid() {
		return nil, nil, core.KeyNotFoundError{Which: "admin PUK"}
	}
	ptk := ptks.Current()
	tok, err := t.makeAdminBearerToken(m, tmid, ptk)
	if err != nil {
		return nil, nil, err
	}
	return tm, tok, nil
}

func (t *TeamMinder) adminTokenAndClient(
	m MetaContext,
	tmid proto.FQTeam,
	opts LoadTeamOpts,
) (
	*rem.TeamBearerToken,
	*rem.TeamAdminClient,
	*TeamRecord,
	error,
) {
	tm, tok, err := t.loadTeamAndAdminToken(m, tmid, opts)
	if err != nil {
		return nil, nil, nil, err
	}
	cli, err := t.au.TeamAdminClient(m)
	if err != nil {
		return nil, nil, nil, err
	}
	return tok, cli, tm, nil
}

func checkCertIsCurrent(cert rem.TeamCert) bool {
	v, err := cert.GetV()
	if err != nil {
		return false
	}
	if v != rem.TeamCertVersion_V1 {
		return false
	}
	payload := cert.V1().Payload
	dat, err := payload.AllocAndDecode(core.DecoderFactory{})
	if err != nil {
		return false
	}

	// Earlier versions of certs didn't have hostnames embedded;
	// Eventually it will be safe to remove this check. (2025.03.04)
	if dat.Name.IsZero() {
		return false
	}
	return true
}

func (t *TeamMinder) getOrMakeCert(
	m MetaContext,
	tw *TeamRecord,
) (
	*teamCert,
	error,
) {
	t.certsMu.Lock()
	defer t.certsMu.Unlock()

	if t.certs == nil {
		t.certs = make(map[proto.FQTeam](*teamCert))
	}
	ret := t.certs[tw.FQT()]
	if ret != nil {
		gen, found := tw.Tw().KeyRing().ToKeyGens()[core.AdminRole]
		if found && ret.gen == gen {
			return ret, nil
		}
	}

	ptks := tw.Tw().KeyRing().KeysForRole(core.AdminRole)
	if ptks == nil || !ptks.LastGen().IsValid() {
		return nil, core.KeyNotFoundError{Which: "admin PUK"}
	}

	ptk1 := ptks.At(proto.FirstGeneration)
	ptkCurr := ptks.Current()

	tok, err := t.makeAdminBearerToken(m, tw.FQT(), ptkCurr)
	if err != nil {
		return nil, err
	}

	cli, err := t.au.TeamAdminClient(m)
	if err != nil {
		return nil, err
	}

	certs, err := cli.GetCurrentTeamCerts(m.Ctx(), *tok)
	if err != nil {
		return nil, err
	}

	// Found a current cert on the server, can reuse
	if len(certs) > 0 {
		cert := certs[0]
		if checkCertIsCurrent(cert) {
			ret := &teamCert{
				cert: cert,
				gen:  ptkCurr.Metadata().Gen,
			}
			t.certs[tw.FQT()] = ret
			return ret, nil
		}
	}

	cert, err := team.MakeTeamCert(tw.FQT(), ptk1, ptkCurr, tw.tw.Name())
	if err != nil {
		return nil, err
	}
	err = cli.PutTeamCert(m.Ctx(),
		rem.PutTeamCertArg{
			Cert: *cert,
			Tok:  *tok,
		},
	)
	if err != nil {
		return nil, err
	}
	ret = &teamCert{
		cert: *cert,
		gen:  ptkCurr.Metadata().Gen,
	}
	t.certs[tw.FQT()] = ret
	return ret, nil
}

func (t *TeamMinder) CreateInvite(
	m MetaContext,
	arg proto.FQTeamParsed,
) (
	*proto.TeamInvite,
	error,
) {
	var ret *proto.TeamInvite
	err := t.withLoadedTeam(m, arg,
		LoadTeamOpts{Refresh: true},
		func(m MetaContext, tm *TeamRecord) error {
			tmp, err := t.createInviteWithTeam(m, tm)
			if err != nil {
				return err
			}
			ret = tmp
			return nil
		},
	)
	return ret, err
}

func (t *TeamMinder) makeMembershipChainLink(
	m MetaContext,
	asTeam *proto.TeamID, // == nil means do it for the user
	glp proto.GenericLinkPayload,
	tr *proto.TreeRoot, // if nil, we'll look it up
) (
	*rem.PostGenericLinkArg,
	error,
) {
	au, err := t.activeUser(m)
	host := au.HostID()
	if err != nil {
		return nil, err
	}
	var eid proto.EntityID
	var tmw *TeamMembershipWrapper
	var key core.PrivateSuiter

	if asTeam == nil {
		eid = au.FQU().Uid.EntityID()
		key = au.PrivKeys.GetDevkey()
		tmw, err = t.refreshUserTML(m)
		if err != nil {
			return nil, err
		}
	} else {
		eid = asTeam.EntityID()
		fqt := proto.FQTeam{Host: host, Team: *asTeam}
		tm, err := t.LoadTeamWithFQTeam(m, fqt, LoadTeamOpts{Refresh: true})
		if err != nil {
			return nil, err
		}
		ptk := tm.Tw().KeyRing().CurrentPrivateKeyAtRole(core.AdminRole)
		if ptk == nil {
			return nil, core.KeyNotFoundError{Which: "admin PTK"}
		}
		key = ptk
		tmw, err = t.loadTeamMembership(m, fqt, LoadTeamOpts{Refresh: true})
		if err != nil {
			return nil, err
		}
	}

	if tr == nil {
		ma, err := au.MerkleAgent(m)
		if err != nil {
			return nil, err
		}
		tmp, err := ma.GetLatestTreeRootFromServer(m.Ctx())
		if err != nil {
			return nil, err
		}
		tr = &tmp
	}

	seqno := proto.ChainEldestSeqno
	var lastHash *proto.LinkHash
	if tmw != nil && tmw.Prot != nil {
		seqno = tmw.Prot.Tail.Base.Seqno + 1
		lastHash = &tmw.Prot.LastHash
	}
	gres, err := core.MakeGenericLink(
		eid,
		host,
		key,
		glp,
		seqno,
		lastHash,
		*tr,
	)
	if err != nil {
		return nil, err
	}
	ret := rem.PostGenericLinkArg{
		Link:             *gres.Link,
		NextTreeLocation: *gres.NextTreeLocation,
	}
	return &ret, nil
}

func (t *TeamMinder) makeMembershipInviteAcceptInvite(
	m MetaContext,
	joinerTeam *proto.TeamID,
	joining proto.FQTeam,
	srcRole proto.Role,
) (
	*rem.PostGenericLinkArg,
	error,
) {
	glp := proto.NewGenericLinkPayloadWithTeammembership(
		proto.TeamMembershipLink{
			Team:    joining,
			SrcRole: srcRole,
			State:   proto.NewTeamMembershipDetailsDefault(proto.TeamMembershipLinkState_Requested),
		},
	)
	return t.makeMembershipChainLink(m, joinerTeam, glp, nil)
}

func (t *TeamMinder) acceptInviteForUserLocal(
	m MetaContext,
	i proto.TeamInvite,
	opCert *openedCert,
) error {
	cert := opCert.cert
	srcRole := team.UserSrcRole
	garg, err := t.makeMembershipInviteAcceptInvite(m, nil, cert.Team, srcRole)
	if err != nil {
		return err
	}
	cli, err := t.au.TeamMemberClient(m)
	if err != nil {
		return err
	}
	_, err = cli.AcceptInviteLocal(m.Ctx(), rem.AcceptInviteLocalArg{
		I:                  i,
		SrcRole:            srcRole,
		TeamMembershipLink: garg,
	})
	return err
}

func (t *TeamMinder) acceptInviteForTeamLocal(
	m MetaContext,
	i proto.TeamInvite,
	opCert *openedCert,
	actAsTeam proto.TeamID,
	srcRole proto.Role,
) error {
	cert := opCert.cert
	fqt := proto.FQTeam{Host: t.au.HostID(), Team: actAsTeam}
	tm, err := t.LoadTeamWithFQTeam(m, fqt, LoadTeamOpts{Refresh: true})
	if err != nil {
		return err
	}
	err = cycleCheck(m, tm, opCert)
	if err != nil {
		return err
	}
	cli, err := t.au.TeamMemberClient(m)
	if err != nil {
		return err
	}
	ptks := tm.Tw().KeyRing().KeysForRole(core.AdminRole)
	if ptks == nil || !ptks.LastGen().IsValid() {
		return core.KeyNotFoundError{Which: "admin PUK"}
	}
	ptk := ptks.Current()
	tok, err := t.makeAdminBearerToken(m, fqt, ptk)
	if err != nil {
		return err
	}
	garg, err := t.makeMembershipInviteAcceptInvite(m, &actAsTeam, cert.Team, srcRole)
	if err != nil {
		return err
	}
	_, err = cli.AcceptInviteLocal(m.Ctx(), rem.AcceptInviteLocalArg{
		I:                  i,
		Tok:                tok,
		SrcRole:            srcRole,
		TeamMembershipLink: garg,
	})
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamMinder) remoteGuestCli(
	m MetaContext,
	h proto.HostID,
) (
	*rem.TeamGuestClient,
	func(),
	proto.Hostname,
	error,
) {
	pr, err := m.Probe(chains.ProbeArg{HostID: h})
	if err != nil {
		return nil, nil, "", err
	}
	gcli, err := pr.RegGCli(m)
	if err != nil {
		return nil, nil, "", err
	}
	hn := pr.Chain().Addr().Hostname()
	cli := rem.TeamGuestClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	return &cli, func() { gcli.Shutdown() }, hn, nil
}

func (t *TeamMinder) lookupCert(
	m MetaContext,
	cli *rem.TeamGuestClient,
	i proto.TeamInvite,
) (
	*rem.TeamCertAndMetadata,
	error,
) {
	cert, err := cli.LookupTeamCertByHash(m.Ctx(), i)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func openCert(c *rem.TeamCert, hostID proto.HostID) (*rem.TeamCertV1Payload, error) {
	v, err := c.GetV()
	if err != nil {
		return nil, err
	}
	if v != rem.TeamCertVersion_V1 {
		return nil, core.VersionNotSupportedError("team cert != v1")
	}
	signed := c.V1()
	ret, err := signed.Payload.AllocAndDecode(core.DecoderFactory{})
	if err != nil {
		return nil, err
	}
	if !ret.Team.Host.Eq(hostID) {
		return nil, core.HostMismatchError{}
	}
	var verifiers []core.Verifier
	ep, err := core.ImportEntityPublic(ret.Team.Team.EntityID())
	if err != nil {
		return nil, err
	}
	verifiers = append(verifiers, ep)
	if !ret.Ptk.Gen.IsFirst() {
		ep, err := core.ImportEntityPublic(ret.Ptk.VerifyKey)
		if err != nil {
			return nil, err
		}
		verifiers = append(verifiers, ep)
	}
	err = core.VerifyStackedSignature(&signed, verifiers)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

type openedCert struct {
	cert rem.TeamCertV1Payload
	idx  proto.RationalRange
}

func (t *TeamMinder) lookupAndOpenCert(
	m MetaContext,
	cli *rem.TeamGuestClient,
	i proto.TeamInvite,
) (
	*openedCert,
	error,
) {
	i1, err := openInvite(i)
	if err != nil {
		return nil, err
	}
	cmd, err := t.lookupCert(m, cli, i)
	if err != nil {
		return nil, err
	}
	cert, err := openCert(&cmd.Cert, i1.Host)
	if err != nil {
		return nil, err
	}
	ret := openedCert{
		cert: *cert,
		idx:  cmd.Tir,
	}
	return &ret, nil
}

func (t *TeamMinder) acceptInviteForUserRemote(
	m MetaContext,
	i proto.TeamInvite,
	opCert *openedCert,
) (
	*proto.TeamRSVPRemote,
	error,
) {
	srcRole := team.UserSrcRole
	grant := func(m MetaContext, fqt proto.FQParty) (*proto.PermissionToken, error) {
		return t.au.GrantRemoteViewPermissionTo(m, fqt)
	}
	joiner := t.au.FQU().FQParty()

	puks, err := t.au.RefreshPUKs(m)
	if err != nil {
		return nil, err
	}
	currPuk := puks.Current()
	if currPuk == nil {
		return nil, core.KeyNotFoundError{Which: "current PUK"}
	}

	postLink := func(m MetaContext, fqt proto.FQTeam) error {
		glink, err := t.makeMembershipInviteAcceptInvite(
			m,
			nil,
			fqt,
			srcRole,
		)
		if err != nil {
			return err
		}
		cli, err := t.au.UserClient(m)
		if err != nil {
			return err
		}
		err = cli.PostGenericLink(m.Ctx(), *glink)
		if err != nil {
			return err
		}
		return nil
	}

	return t.acceptInviteRemoteCommon(
		m,
		i,
		opCert,
		joiner,
		currPuk,
		srcRole, // For now, only allow owner source role for users
		grant,
		postLink,
		nil,
	)
}

func cycleCheck(
	m MetaContext,
	tm *TeamRecord,
	opCert *openedCert,
) error {

	joiner := tm.IndexRangeWithOverride(m)
	joinee := core.NewRationalRange(opCert.idx)
	if !joiner.LessThan(joinee) {
		return core.NewTeamCycleError(joiner, joinee)
	}
	return nil
}

func (t *TeamMinder) acceptInviteForTeamRemote(
	m MetaContext,
	i proto.TeamInvite,
	opCert *openedCert,
	actAsTeam proto.TeamID,
	srcRole proto.Role,
) (
	*proto.TeamRSVPRemote,
	error,
) {
	joinerFqt := proto.FQTeam{Host: t.au.HostID(), Team: actAsTeam}
	tm, err := t.LoadTeamWithFQTeam(m, joinerFqt, LoadTeamOpts{Refresh: true})
	if err != nil {
		return nil, err
	}
	err = cycleCheck(m, tm, opCert)
	if err != nil {
		return nil, err
	}
	joinerParty := joinerFqt.FQParty()
	ptkRole := core.AdminRole
	ptks := tm.Tw().KeyRing().KeysForRole(ptkRole)
	if ptks == nil || !ptks.LastGen().IsValid() {
		return nil, core.KeyNotFoundError{Which: "admin PTK"}
	}
	joinerPtk := ptks.Current()

	grant := func(m MetaContext, fqt proto.FQParty) (*proto.PermissionToken, error) {
		payload := rem.GrantRemoteViewPermissionPayload{
			Viewee: joinerParty.Party,
			Viewer: fqt,
			Tm:     proto.Now(),
		}
		sig, err := joinerPtk.Sign(&payload)
		if err != nil {
			return nil, err
		}
		arg := rem.GrantRemoteViewPermissionForTeamArg{
			P: payload,
			Sig: rem.SharedKeySig{
				Role: ptkRole.Export(),
				Gen:  joinerPtk.Metadata().Gen,
				Sig:  *sig,
			},
		}
		cli, err := t.au.TeamMemberClient(m)
		if err != nil {
			return nil, err
		}
		vtok, err := cli.GrantRemoteViewPermissionForTeam(m.Ctx(), arg)
		if err != nil {
			return nil, err
		}
		return &vtok, nil
	}

	postLink := func(m MetaContext, joining proto.FQTeam) error {
		glink, err := t.makeMembershipInviteAcceptInvite(
			m,
			&actAsTeam,
			joining,
			srcRole,
		)
		if err != nil {
			return err
		}
		cli, err := t.au.TeamAdminClient(m)
		if err != nil {
			return err
		}
		tok, err := t.makeAdminBearerToken(m, joinerFqt, joinerPtk)
		if err != nil {
			return err
		}
		err = cli.PostTeamMembershipLink(m.Ctx(), rem.PostTeamMembershipLinkArg{
			Tok:  *tok,
			Link: *glink,
		})
		if err != nil {
			return err
		}
		return nil
	}

	tir := tm.IndexRangeWithOverride(m)

	return t.acceptInviteRemoteCommon(
		m,
		i,
		opCert,
		joinerParty,
		joinerPtk,
		srcRole,
		grant,
		postLink,
		&tir,
	)
}

func (t *TeamMinder) acceptInviteRemoteCommon(
	m MetaContext,
	i proto.TeamInvite,
	opCert *openedCert,
	joiner proto.FQParty,
	boxerPriv core.SharedPrivateSuiter,
	srcRole proto.Role,
	doGrant func(m MetaContext, fqt proto.FQParty) (*proto.PermissionToken, error),
	postLink func(m MetaContext, fqt proto.FQTeam) error,
	joiningTir *core.RationalRange,
) (
	*proto.TeamRSVPRemote,
	error,
) {

	if joiner.Party.IsTeam() && joiningTir == nil {
		return nil, core.InternalError("joiningTir == nil for a team")
	}

	i1, err := openInvite(i)
	if err != nil {
		return nil, err
	}
	cli, closer, _, err := t.remoteGuestCli(m, i1.Host)
	if err != nil {
		return nil, err
	}
	defer closer()

	cert := opCert.cert

	vtok, err := doGrant(m, cert.Team.FQParty())
	if err != nil {
		return nil, err
	}

	var viz rem.TeamRemoteJoinReqVisibleData
	if joiningTir != nil {
		tmp := joiningTir.Export()
		viz.Tir = &tmp
	}

	rjrp := rem.TeamRemoteJoinReqPayload{
		Joiner:  joiner,
		Tok:     *vtok,
		Tm:      proto.Now(),
		SrcRole: srcRole,
		Vd:      viz,
	}

	sps, err := core.ImportSharedPublicSuite(&cert.Ptk, &cert.Hepk)
	if err != nil {
		return nil, err
	}
	spsb := core.SPSBoxer{
		SharedPublicSuite: *sps,
		Parent:            cert.Team.FQParty(),
	}
	box, err := boxerPriv.BoxFor(&rjrp, &spsb, core.BoxOpts{IncludePublicKey: true})
	if err != nil {
		return nil, err
	}

	err = postLink(m, cert.Team)
	if err != nil {
		return nil, err
	}
	fp, err := core.HEPK(&cert.Hepk).Fingerprint()
	if err != nil {
		return nil, err
	}

	arg := rem.AcceptInviteRemoteArg{
		Jr: rem.TeamRemoteJoinReq{
			Box:    *box,
			HepkFp: *fp,
			Vd:     viz,
		},
		I: i,
	}
	jrtok, err := cli.AcceptInviteRemote(m.Ctx(), arg)
	if err != nil {
		return nil, err
	}
	return &jrtok, nil
}

func openInvite(i proto.TeamInvite) (*proto.TeamInviteV1, error) {
	v, err := i.GetV()
	if err != nil {
		return nil, err
	}
	if v != proto.TeamInviteVersion_V1 {
		return nil, core.VersionNotSupportedError("team invite != v1")
	}
	ret := i.V1()
	return &ret, nil
}

func (t *TeamMinder) AcceptInvite(
	m MetaContext,
	arg lcl.TeamAcceptInviteArg,
) (
	*lcl.TeamAcceptInviteRes,
	error,
) {
	i1, err := openInvite(arg.I)
	if err != nil {
		return nil, err
	}

	cli, closer, hn, err := t.remoteGuestCli(m, i1.Host)
	if err != nil {
		return nil, err
	}
	defer closer()

	cert, err := t.lookupAndOpenCert(m, cli, arg.I)
	if err != nil {
		return nil, err
	}

	var actAsTeam *proto.TeamID

	if arg.ActingAs != nil {
		fqt, err := t.ResolveAndReindex(m, arg.ActingAs.Fqtp)
		if err != nil {
			return nil, err
		}
		if fqt == nil {
			return nil, core.TeamNotFoundError{}
		}
		// Can only accept invites for teams on our current host
		if !fqt.Host.Eq(t.au.HostID()) {
			return nil, core.HostMismatchError{}
		}
		actAsTeam = &fqt.Team
	}

	isLocal := i1.Host.Eq(t.au.HostID())
	var tok *proto.TeamRSVPRemote

	switch {
	case isLocal && actAsTeam == nil:
		err = t.acceptInviteForUserLocal(m, arg.I, cert)
	case isLocal && actAsTeam != nil:
		err = t.acceptInviteForTeamLocal(m, arg.I, cert, *actAsTeam, arg.ActingAs.Role)
	case !isLocal && actAsTeam == nil:
		tok, err = t.acceptInviteForUserRemote(m, arg.I, cert)
	case !isLocal && actAsTeam != nil:
		tok, err = t.acceptInviteForTeamRemote(m, arg.I, cert, *actAsTeam, arg.ActingAs.Role)
	default:
		err = core.InternalError("unreachable")
	}

	if err != nil {
		return nil, err
	}

	ret := lcl.TeamAcceptInviteRes{
		Tok: tok,
		Team: lcl.FQNamedTeam{
			Id:   cert.cert.Team,
			Name: cert.cert.Name,
			Host: hn,
		},
	}

	return &ret, nil
}

func (t *TeamMinder) expandInboxRowRemote(
	m MetaContext,
	teamRec *TeamRecord,
	row *lcl.TeamInboxRow,
	trirr rem.TeamRawInboxRowRemote,
) error {
	key, err := teamRec.Tw().KeyRing().FindDecryptKey(core.AdminRole, &trirr.Req.HepkFp)
	if err != nil {
		return err
	}
	var payload rem.TeamRemoteJoinReqPayload
	box := trirr.Req.Box
	_, err = key.UnboxFor(&payload, box, nil)
	if err != nil {
		return err
	}

	joiner := payload.Joiner
	tok := payload.Tok
	row.SrcRole = payload.SrcRole
	row.Nfqp.Fqp = joiner
	row.Ptok = &tok
	var pw PartyWrapper

	eq, err := core.Eq(&trirr.Req.Vd, &payload.Vd)
	if err != nil {
		return err
	}
	if !eq {
		return core.BadServerDataError("visible join req data does not match inside of box")
	}

	uid, tid, err := joiner.Party.Select()
	if err != nil {
		return err
	}
	switch {
	case uid != nil:
		fqu := proto.FQUser{Uid: *uid, HostID: joiner.Host}
		uw, err := LoadUser(m,
			(LoadUserArg{LoadMode: LoadModeOthers}).SetFQU(fqu, tok),
		)
		if err != nil {
			return err
		}
		pw = uw
	case tid != nil:
		arg := LoadTeamArg{
			Team: proto.FQTeam{Host: joiner.Host, Team: *tid},
			Tok:  &tok,
		}
		tw, err := LoadTeam(m, arg)
		if err != nil {
			return err
		}
		pw = tw
	default:
		return core.InternalError("unreachable")
	}

	err = pw.CheckTeamIndexRange(teamRec.IndexRange(), payload.Vd.Tir)
	if err != nil {
		return err
	}

	err = loadPartyWrapperIntoRow(row, pw)
	if err != nil {
		return err
	}
	return nil
}

func loadPartyWrapperIntoRow(row *lcl.TeamInboxRow, pw PartyWrapper) error {
	row.Nfqp.Host = pw.Hostname()
	row.Nfqp.Name = pw.Name()
	srk, err := core.ImportRole(row.SrcRole)
	if err != nil {
		return err
	}
	tmk, hepk, err := pw.TeamMemberKeys(*srk)
	if err != nil {
		return err
	}
	if tmk == nil || hepk == nil {
		return core.KeyNotFoundError{Which: "team member keys"}
	}
	row.Tmk = *tmk
	row.Hepks.Push(*hepk)
	return nil
}

func (t *TeamMinder) expandInboxRowLocal(
	m MetaContext,
	teamRec *TeamRecord,
	row *lcl.TeamInboxRow,
	loc rem.TeamRawInboxRowLocal,
) error {
	row.SrcRole = loc.SrcRole
	joiner := loc.Joiner
	host := t.au.HostID()
	row.Nfqp.Fqp = proto.FQParty{Party: joiner, Host: host}
	uid, tid, err := joiner.Select()
	if err != nil {
		return err
	}
	var pw PartyWrapper
	switch {
	case uid != nil:
		uw, err := LoadUser(m,
			LoadUserArg{
				Uid:               *uid,
				LoadMode:          LoadModeOthers,
				TeamVOBearerToken: teamRec.ldr.Tok(),
			},
		)
		if err != nil {
			return err
		}
		pw = uw
	case tid != nil:
		arg := LoadTeamArg{
			Team:               proto.FQTeam{Host: host, Team: *tid},
			As:                 teamRec.FQT().FQParty(),
			LocalParentTeamTok: teamRec.ldr.Tok(),
		}
		tw, err := LoadTeam(m, arg)
		if err != nil {
			return err
		}

		// The team we're adding has to have an index range less than the
		// team we're adding to.
		if !tw.IndexRange().LessThan(teamRec.IndexRange()) {
			return core.NewTeamCycleError(teamRec.IndexRange(), tw.IndexRange())
		}
		pw = tw
	}
	err = loadPartyWrapperIntoRow(row, pw)
	if err != nil {
		return err
	}
	return nil
}

func (t *TeamMinder) expandInboxRow(
	m MetaContext,
	tw *TeamRecord,
	raw rem.TeamRawInboxRow,
) (
	*lcl.TeamInboxRow,
	error,
) {
	typ, err := raw.Row.GetT()
	if err != nil {
		return nil, err
	}

	tok, err := raw.Row.Token()
	if err != nil {
		return nil, err
	}
	ret := lcl.TeamInboxRow{
		Time: raw.Time,
		Tok:  tok,
	}

	var expandErr error
	switch typ {
	case rem.TeamJoinReqType_Local:
		loc := raw.Row.Local()
		expandErr = t.expandInboxRowLocal(m, tw, &ret, loc)
	case rem.TeamJoinReqType_Remote:
		rem := raw.Row.Remote()
		expandErr = t.expandInboxRowRemote(m, tw, &ret, rem)
	}
	if expandErr != nil {
		ret.Status = core.ErrorToStatus(expandErr)
	}
	return &ret, nil
}

func (t *TeamMinder) cacheInbox(tm proto.FQTeam, rows []lcl.TeamInboxRow) {
	t.inboxMu.Lock()
	defer t.inboxMu.Unlock()
	if t.inbox == nil {
		t.inbox = make(map[proto.TeamRSVP]inboxCacheRow)
	}
	for _, r := range rows {
		t.inbox[r.Tok] = inboxCacheRow{
			team: tm,
			row:  r,
		}
	}
}

func (t *TeamMinder) TeamInbox(
	m MetaContext,
	fqtp proto.FQTeamParsed,
) (
	*lcl.TeamInbox,
	error,
) {
	fqt, err := t.ResolveAndReindex(m, fqtp)
	if err != nil {
		return nil, err
	}
	if fqt == nil {
		return nil, core.TeamNotFoundError{}
	}
	return t.loadTeamInboxWithFQTeam(m, *fqt)
}

// Now send an RPC to the server to reject all of the reject rows
// (since they would have caused a cycle)
func (t *TeamMinder) inboxRowAutoFix(
	m MetaContext,
	tok *rem.TeamBearerToken,
	cli *rem.TeamAdminClient,
	joinee *TeamRecord,
	row *lcl.TeamInboxRow,
) error {

	sc, err := row.Status.GetSc()
	if err != nil {
		return err
	}
	// Only handle team cycle errors.
	if sc != proto.StatusCode_TEAM_CYCLE_ERROR && sc != proto.StatusCode_TEAM_INDEX_RANGE_ERROR {
		return nil
	}

	err = cli.RejectJoinReq(m.Ctx(), rem.RejectJoinReqArg{
		Tok: *tok,
		Req: row.Tok,
	})

	// Return these errors back up to the caller / client. Should normally be fine.
	status := core.ErrorToStatus(err)
	row.AutofixStatus = &status

	return nil
}

func (t *TeamMinder) loadTeamInboxWithFQTeam(
	m MetaContext,
	fqt proto.FQTeam,
) (
	*lcl.TeamInbox,
	error,
) {
	tok, cli, tmw, err := t.adminTokenAndClient(m, fqt, LoadTeamOpts{})
	if err != nil {
		return nil, err
	}

	// For now, no pagination. Just spam everything all at once.
	raw, err := cli.LoadTeamRawInbox(m.Ctx(), rem.LoadTeamRawInboxArg{
		Tok: *tok,
	})
	if err != nil {
		return nil, err
	}
	rows := make([]lcl.TeamInboxRow, 0, len(raw.Rows))
	for _, r := range raw.Rows {
		row, err := t.expandInboxRow(m, tmw, r)
		if err != nil {
			return nil, err
		}
		err = t.inboxRowAutoFix(m, tok, cli, tmw, row)
		if err != nil {
			return nil, err
		}
		rows = append(rows, *row)
	}

	// Cache inbox rows indefinitely, so that attempts to "add" will
	// hit this cache.
	t.cacheInbox(fqt, rows)

	// Mainly for tests we need to plumb this through
	return &lcl.TeamInbox{Rows: rows}, nil
}

func (t *TeamMinder) getOrLoadInboxRow(
	m MetaContext,
	fqt proto.FQTeam,
	tok proto.TeamRSVP,
) (
	*inboxCacheRow,
	error,
) {
	t.inboxMu.Lock()
	defer t.inboxMu.Unlock()
	if t.inbox != nil {
		row, found := t.inbox[tok]
		if found {
			return &row, nil
		}
	}
	_, err := t.loadTeamInboxWithFQTeam(m, fqt)
	if err != nil {
		return nil, err
	}
	row, found := t.inbox[tok]
	if found {
		return &row, nil
	}
	return nil, core.NotFoundError("inbox row")
}

func (t *TeamMinder) TeamAdmit(
	m MetaContext,
	arg lcl.TeamAdmitArg,
) error {
	fqt, err := t.ResolveAndReindex(m, arg.Team)
	if err != nil {
		return err
	}
	if fqt == nil {
		return core.TeamNotFoundError{}
	}
	var rows []proto.MemberRole
	var rtps []RemoteTokenPackage
	var hepks core.HEPKSet
	for _, tr := range arg.Members {
		row, err := t.getOrLoadInboxRow(m, *fqt, tr.Tok)
		if err != nil {
			return err
		}
		if !row.team.Eq(*fqt) {
			return core.InternalError("unexpected team ID mismatch")
		}
		err = hepks.AddSet(row.row.Hepks)
		if err != nil {
			return err
		}
		mr := proto.MemberRole{
			Member: proto.Member{
				Id:      row.row.Nfqp.Fqp.FQEntity().AtHost(fqt.Host),
				SrcRole: row.row.SrcRole,
				Keys: proto.NewMemberKeysWithTeam(
					row.row.Tmk,
				),
			},
			DstRole: tr.Role,
		}
		if row.row.Ptok != nil {
			rtps = append(rtps, RemoteTokenPackage{
				Rmvtbp: proto.TeamRemoteMemberViewTokenBoxPayload{
					Tok:   *row.row.Ptok,
					Party: row.row.Nfqp.Fqp,
					Tm:    proto.Now(),
				},
				Rjtok: row.row.Tok,
			})
		}
		rows = append(rows, mr)
	}

	tok, cli, tr, err := t.adminTokenAndClient(m, *fqt, LoadTeamOpts{Refresh: true})
	if err != nil {
		return err
	}
	cfg, err := t.loadConfig(m, cli)
	if err != nil {
		return err
	}

	tr.Lock()
	defer tr.Unlock()

	editor := TeamEditor{
		tl:      tr.ldr,
		tw:      tr.tw,
		id:      tr.ldr.TeamID(),
		tok:     tok,
		pre:     tr.ldr.rosterPost,
		changes: rows,
		rtps:    rtps,
		cp:      tr.member,
		hepks:   &hepks,
		cfg:     cfg,
	}

	return editor.Run(m)
}

func (t *TeamMinder) TeamChangeRoles(
	m MetaContext,
	arg lcl.TeamChangeRolesArg,
) error {
	fqt, err := t.ResolveAndReindex(m, arg.Team)
	if err != nil {
		return err
	}
	if fqt == nil {
		return core.TeamNotFoundError{}
	}
	tok, cli, tr, err := t.adminTokenAndClient(m, *fqt, LoadTeamOpts{Refresh: true})
	if err != nil {
		return err
	}
	cfg, err := t.loadConfig(m, cli)
	if err != nil {
		return err
	}

	rows, hepks, err := t.teamChangeRolesLoadChanges(m, tr, arg.Changes)
	if err != nil {
		return err
	}

	tr.Lock()
	defer tr.Unlock()

	editor := TeamEditor{
		tl:      tr.ldr,
		tw:      tr.tw,
		id:      tr.ldr.TeamID(),
		tok:     tok,
		pre:     tr.ldr.rosterPost,
		cp:      tr.member,
		hepks:   hepks,
		changes: rows,
		cfg:     cfg,
	}

	return editor.Run(m)
}
