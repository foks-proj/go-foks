// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"testing"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

// Social invite tests (docs/social_signup_spec.md). There is no client
// implementation yet, so the tests play both parties with lib/core crypto
// directly: Alice derives the keys off a random seed, seals the exchange,
// and self-boxes the seed to her PUK; Bob rederives the same keys from the
// seed alone.

type socialInviteKit struct {
	seed proto.SocialInviteSeed
	id   proto.SocialInviteID
	ek   proto.SecretBoxKey
	wk   proto.SocialInviteWriteKey
}

func newSocialInviteKit(t *testing.T) *socialInviteKit {
	var k socialInviteKit
	err := core.RandomFill(k.seed[:])
	require.NoError(t, err)
	id, err := core.DeriveSocialInviteID(k.seed)
	require.NoError(t, err)
	k.id = *id
	ek, err := core.DeriveSocialInviteBoxKey(k.seed)
	require.NoError(t, err)
	k.ek = *ek
	wk, err := core.DeriveSocialInviteWriteKey(k.seed)
	require.NoError(t, err)
	k.wk = *wk
	return &k
}

func (k *socialInviteKit) seal(t *testing.T, p *rem.SocialInviteMsgPayload) proto.SecretBox {
	box, err := core.SealIntoSecretBox(p, &k.ek)
	require.NoError(t, err)
	return *box
}

func (k *socialInviteKit) open(t *testing.T, box proto.SecretBox) rem.SocialInviteMsgPayload {
	var ret rem.SocialInviteMsgPayload
	err := core.OpenSecretBoxInto(&ret, box, &k.ek)
	require.NoError(t, err)
	return ret
}

func (k *socialInviteKit) wkCommit(t *testing.T) proto.SocialInviteWriteKeyCommitment {
	c, err := core.CommitSocialInviteWriteKey(k.wk)
	require.NoError(t, err)
	return *c
}

func makeSocialInviteSeedBox(
	t *testing.T,
	u *TestUser,
	seed proto.SocialInviteSeed,
) proto.SharedKeyBox {
	puk, ok := u.puks[core.OwnerRole]
	require.True(t, ok)
	box, err := core.SelfBox(&puk, &seed, u.host)
	require.NoError(t, err)
	gen := puk.Metadata().Gen
	return proto.SharedKeyBox{
		Gen:  gen,
		Role: proto.OwnerRole,
		Box:  *box,
		Targ: proto.SharedKeyBoxTarget{
			Eid:  u.uid.EntityID(),
			Role: proto.OwnerRole,
			Gen:  gen,
		},
	}
}

func openSocialInviteSeedBox(
	t *testing.T,
	u *TestUser,
	skb proto.SharedKeyBox,
) proto.SocialInviteSeed {
	puk, ok := u.puks[core.OwnerRole]
	require.True(t, ok)
	var seed proto.SocialInviteSeed
	err := core.SelfUnbox(&puk, &seed, skb.Box)
	require.NoError(t, err)
	return seed
}

func (u *TestUser) newSocialInviteClient(
	t *testing.T,
	ctx context.Context,
) (*rem.SocialInviteClient, func()) {
	crt := u.ClientCertRobust(ctx, t)
	m := shared.NewMetaContext(ctx, u.g)
	gcli, closeFn, err := newGenericClient(m, u.env.UserSrv(), crt, u.vhost)
	require.NoError(t, err)
	cli := core.NewSocialInviteClient(gcli, m.G())
	return &cli, closeFn
}

func (w TestEnvWrapper) newSocialInviteGuestClient(
	t *testing.T,
) (*rem.SocialInviteGuestClient, func()) {
	m := w.MetaContext()
	gcli, closeFn, err := newGenericClient(m, w.RegSrv(), nil, nil)
	require.NoError(t, err)
	cli := core.NewSocialInviteGuestClient(gcli, m.G())
	return &cli, closeFn
}

// socialInviteFixture is an owner with a team and the derived key material
// for one invitation, not yet created on the server.
type socialInviteFixture struct {
	tew   *TestEnvWrapper
	alice *TestUser
	tm    *teamObj
	tid   proto.TeamID
	kit   *socialInviteKit
	cli   *rem.SocialInviteClient
}

func newSocialInviteFixture(t *testing.T) *socialInviteFixture {
	tew := testEnvBeta(t)
	alice := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, alice)
	tew.DirectDoubleMerklePokeInTest(t)
	tid, err := tm.id.ToTeamID()
	require.NoError(t, err)
	m := tew.MetaContext()
	cli, closeFn := alice.newSocialInviteClient(t, m.Ctx())
	t.Cleanup(closeFn)
	return &socialInviteFixture{
		tew:   tew,
		alice: alice,
		tm:    tm,
		tid:   tid,
		kit:   newSocialInviteKit(t),
		cli:   cli,
	}
}

func (f *socialInviteFixture) createArg(
	t *testing.T,
	code *rem.InviteCode,
) rem.CreateArg {
	payload := rem.SocialInviteMsgPayload{
		Text:       "hi Bob, join my team?",
		InviteCode: code,
		Team:       &proto.FQTeam{Team: f.tid, Host: f.alice.host},
	}
	return rem.CreateArg{
		Id:         f.kit.id,
		Team:       f.tid,
		SeedBox:    makeSocialInviteSeedBox(t, f.alice, f.kit.seed),
		Msg:        f.kit.seal(t, &payload),
		WkCommit:   f.kit.wkCommit(t),
		InviteCode: code,
	}
}

func (f *socialInviteFixture) create(t *testing.T, code *rem.InviteCode) {
	m := f.tew.MetaContext()
	err := f.cli.Create(m.Ctx(), f.createArg(t, code))
	require.NoError(t, err)
}

func (f *socialInviteFixture) replyArg(
	t *testing.T,
	bob *TestUser,
	inReplyTo uint64,
	text string,
) rem.ReplyArg {
	fqu := bob.FQUser()
	payload := rem.SocialInviteMsgPayload{
		Text: text,
		User: &fqu,
	}
	return rem.ReplyArg{
		Id:        f.kit.id,
		Wk:        f.kit.wk,
		InReplyTo: inReplyTo,
		Msg:       f.kit.seal(t, &payload),
	}
}

func (f *socialInviteFixture) listOne(t *testing.T) rem.SocialInviteRow {
	m := f.tew.MetaContext()
	rows, err := f.cli.List(m.Ctx())
	require.NoError(t, err)
	for _, row := range rows {
		if row.Id == f.kit.id {
			return row
		}
	}
	t.Fatalf("invite %x not in list", f.kit.id)
	return rem.SocialInviteRow{}
}

func (f *socialInviteFixture) close(t *testing.T, st proto.SocialInviteState) error {
	m := f.tew.MetaContext()
	return f.cli.Close(m.Ctx(), rem.CloseArg{Id: f.kit.id, St: st})
}

// setSocialInviteTimes rewrites timestamp columns straight in the DB, to
// simulate expiry and grace-period age without waiting.
func setSocialInviteTime(
	t *testing.T,
	m shared.MetaContext,
	id proto.SocialInviteID,
	col string,
	age time.Duration,
) {
	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	q := `UPDATE social_invites SET ` + col + `=$3
	      WHERE short_host_id=$1 AND id=$2`
	tags, err := db.Exec(m.Ctx(), q,
		m.ShortHostID().ExportToDB(), id[:], time.Now().Add(-age))
	require.NoError(t, err)
	require.Equal(t, int64(1), tags.RowsAffected())
}

func TestSocialInviteHappyPath(t *testing.T) {
	f := newSocialInviteFixture(t)
	tew := f.tew
	m := tew.MetaContext()

	// Alice mints a standard code via the new RPC and checks it's hers.
	ucli, closeFn := f.alice.newUserCertAndClient(t, m.Ctx())
	defer closeFn()
	code, err := ucli.NewInviteCode(m.Ctx())
	require.NoError(t, err)
	typ, err := code.GetT()
	require.NoError(t, err)
	require.Equal(t, rem.InviteCodeType_Standard, typ)

	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	var creator []byte
	err = db.QueryRow(m.Ctx(),
		`SELECT creator FROM invite_codes WHERE short_host_id=$1 AND code=$2`,
		m.ShortHostID().ExportToDB(), code.Standard(),
	).Scan(&creator)
	require.NoError(t, err)
	require.Equal(t, f.alice.uid.ExportToDB(), creator)

	// Step 1: create, with the code both attached and inside M_1.
	f.create(t, &code)

	// Step 3: Bob (no account yet) fetches by the id derived from the seed
	// and reads M_1.
	gcli, closeGuest := tew.newSocialInviteGuestClient(t)
	defer closeGuest()
	view, err := gcli.Fetch(m.Ctx(), f.kit.id)
	require.NoError(t, err)
	require.Equal(t, proto.SocialInviteState_Open, view.State)
	require.Equal(t, 1, len(view.Msgs))
	require.Equal(t, uint64(1), view.Msgs[0].Seq)
	require.Equal(t, proto.SocialInviteParty_Inviter, view.Msgs[0].Sender)
	m1 := f.kit.open(t, view.Msgs[0].Box)
	require.NotNil(t, m1.InviteCode)
	require.NotNil(t, m1.Team)
	require.Equal(t, f.tid, m1.Team.Team)

	// Step 4: Bob signs up with the code he found inside M_1.
	rcli, closeReg, err := newRegClientFromEnv(m, tew.TestEnv)
	require.NoError(t, err)
	defer closeReg()
	err = rcli.CheckInviteCode(m.Ctx(), *m1.InviteCode)
	require.NoError(t, err)
	bob := tew.NewTestUserOpts(t, &TestUserOpts{
		RealTreeRoot: true,
		InviteCode:   m1.InviteCode,
	})
	tew.DirectDoubleMerklePokeInTest(t)

	// Step 5: Bob replies with wk, naming U_B inside the box.
	bcli, closeBob := bob.newSocialInviteClient(t, m.Ctx())
	defer closeBob()
	err = bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "sure, it's me"))
	require.NoError(t, err)

	// Step 6: Alice lists, opens the seed box with her PUK, rederives the
	// keys, and reads the exchange. She holds no local state.
	row := f.listOne(t)
	require.Equal(t, proto.SocialInviteState_Replied, row.State)
	seed := openSocialInviteSeedBox(t, f.alice, row.SeedBox)
	require.Equal(t, f.kit.seed, seed)
	ek, err := core.DeriveSocialInviteBoxKey(seed)
	require.NoError(t, err)
	require.Equal(t, f.kit.ek, *ek)
	require.Equal(t, 2, len(row.Msgs))
	m2 := f.kit.open(t, row.Msgs[1].Box)
	require.NotNil(t, m2.User)
	require.Equal(t, bob.uid, m2.User.Uid)
	// The server's invitee column agrees here, but the box is the assertion
	// that counts.
	require.NotNil(t, row.Invitee)
	require.Equal(t, bob.uid, *row.Invitee)

	// Step 7: M_2 satisfies her; the team edit happens through the existing
	// team machinery, then close(accepted) is the bookkeeping.
	require.NoError(t, f.close(t, proto.SocialInviteState_Accepted))
	row = f.listOne(t)
	require.Equal(t, proto.SocialInviteState_Accepted, row.State)

	// Bob's poll still reads the decision; the consumed code stays as the
	// audit trail.
	view, err = gcli.Fetch(m.Ctx(), f.kit.id)
	require.NoError(t, err)
	require.Equal(t, proto.SocialInviteState_Accepted, view.State)
	var usedBy []byte
	err = db.QueryRow(m.Ctx(),
		`SELECT used_by FROM invite_codes WHERE short_host_id=$1 AND code=$2`,
		m.ShortHostID().ExportToDB(), code.Standard(),
	).Scan(&usedBy)
	require.NoError(t, err)
	require.Equal(t, bob.uid.ExportToDB(), usedBy)
}

func TestSocialInviteGuestFetchUnknown(t *testing.T) {
	tew := testEnvBeta(t)
	m := tew.MetaContext()
	gcli, closeFn := tew.newSocialInviteGuestClient(t)
	defer closeFn()
	kit := newSocialInviteKit(t)
	_, err := gcli.Fetch(m.Ctx(), kit.id)
	require.Error(t, err)
	require.Equal(t, core.SocialInviteNotFoundError{}, err)
}

func TestSocialInviteBadWriteKey(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()
	f.create(t, nil)

	bob := f.tew.NewTestUser(t)
	f.tew.DirectDoubleMerklePokeInTest(t)
	bcli, closeFn := bob.newSocialInviteClient(t, m.Ctx())
	defer closeFn()

	arg := f.replyArg(t, bob, 1, "let me in")
	arg.Wk[0] ^= 0x1
	err := bcli.Reply(m.Ctx(), arg)
	require.Error(t, err)
	require.True(t, core.IsPermissionError(err))

	// The row is unchanged.
	row := f.listOne(t)
	require.Equal(t, proto.SocialInviteState_Open, row.State)
	require.Equal(t, 1, len(row.Msgs))
}

func TestSocialInviteStaleTurn(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()
	f.create(t, nil)

	bob := f.tew.NewTestUser(t)
	f.tew.DirectDoubleMerklePokeInTest(t)
	bcli, closeFn := bob.newSocialInviteClient(t, m.Ctx())
	defer closeFn()

	// A reply must name the current inviter turn.
	err := bcli.Reply(m.Ctx(), f.replyArg(t, bob, 0, "early"))
	require.Error(t, err)
	require.Equal(t, core.SocialInviteStaleTurnError{}, err)

	require.NoError(t, bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "answer")))
	err = f.cli.AskAgain(m.Ctx(), rem.AskAgainArg{
		Id:  f.kit.id,
		Msg: f.kit.seal(t, &rem.SocialInviteMsgPayload{Text: "who is this really?"}),
	})
	require.NoError(t, err)

	// A client that fetched before the ask-again answers turn 1, which is no
	// longer current.
	err = bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "stale"))
	require.Error(t, err)
	require.Equal(t, core.SocialInviteStaleTurnError{}, err)
}

func TestSocialInviteReplyRetryReplaces(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()
	f.create(t, nil)

	bob := f.tew.NewTestUser(t)
	f.tew.DirectDoubleMerklePokeInTest(t)
	bcli, closeFn := bob.newSocialInviteClient(t, m.Ctx())
	defer closeFn()

	require.NoError(t, bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "first answer")))
	// A lost-ack retry of the same turn replaces rather than appends.
	require.NoError(t, bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "second answer")))

	row := f.listOne(t)
	require.Equal(t, proto.SocialInviteState_Replied, row.State)
	require.Equal(t, 2, len(row.Msgs))
	m2 := f.kit.open(t, row.Msgs[1].Box)
	require.Equal(t, "second answer", m2.Text)
}

func TestSocialInviteAskAgainFlow(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()
	f.create(t, nil)

	// Ask-again needs a reply first.
	err := f.cli.AskAgain(m.Ctx(), rem.AskAgainArg{
		Id:  f.kit.id,
		Msg: f.kit.seal(t, &rem.SocialInviteMsgPayload{Text: "hello?"}),
	})
	require.Error(t, err)
	require.Equal(t, core.SocialInviteWrongStateError{}, err)

	bob := f.tew.NewTestUser(t)
	f.tew.DirectDoubleMerklePokeInTest(t)
	bcli, closeBob := bob.newSocialInviteClient(t, m.Ctx())
	defer closeBob()
	require.NoError(t, bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "it's bob")))

	err = f.cli.AskAgain(m.Ctx(), rem.AskAgainArg{
		Id:  f.kit.id,
		Msg: f.kit.seal(t, &rem.SocialInviteMsgPayload{Text: "prove it"}),
	})
	require.NoError(t, err)

	// Bob's original link still works; his next fetch shows the new state
	// and what she asked.
	gcli, closeGuest := f.tew.newSocialInviteGuestClient(t)
	defer closeGuest()
	view, err := gcli.Fetch(m.Ctx(), f.kit.id)
	require.NoError(t, err)
	require.Equal(t, proto.SocialInviteState_AskAgain, view.State)
	require.Equal(t, 3, len(view.Msgs))
	m3 := f.kit.open(t, view.Msgs[2].Box)
	require.Equal(t, "prove it", m3.Text)

	// He answers the new turn; the exchange is append-only with no limit.
	require.NoError(t, bcli.Reply(m.Ctx(), f.replyArg(t, bob, 3, "fine: proof")))
	row := f.listOne(t)
	require.Equal(t, proto.SocialInviteState_Replied, row.State)
	require.Equal(t, 4, len(row.Msgs))
}

func TestSocialInviteWrongStateAndNotFound(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()
	f.create(t, nil)

	bob := f.tew.NewTestUser(t)
	f.tew.DirectDoubleMerklePokeInTest(t)
	bcli, closeBob := bob.newSocialInviteClient(t, m.Ctx())
	defer closeBob()

	// close(accepted) on an open row: the invitee hasn't answered.
	err := f.close(t, proto.SocialInviteState_Accepted)
	require.Equal(t, core.SocialInviteWrongStateError{}, err)

	require.NoError(t, bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "me")))

	// close(canceled) on a replied row: decline is the retraction there.
	err = f.close(t, proto.SocialInviteState_Canceled)
	require.Equal(t, core.SocialInviteWrongStateError{}, err)

	require.NoError(t, f.close(t, proto.SocialInviteState_Accepted))

	// Replying to a decided row fails loudly; the decision is visible anyway.
	err = bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "again"))
	require.Equal(t, core.SocialInviteWrongStateError{}, err)

	// A lost-ack retry of the same close succeeds; a different terminal
	// state is a real wrong-state error.
	require.NoError(t, f.close(t, proto.SocialInviteState_Accepted))
	err = f.close(t, proto.SocialInviteState_Declined)
	require.Equal(t, core.SocialInviteWrongStateError{}, err)

	// Cancel, by contrast, reads as never-existed. Fresh invitation:
	f2 := &socialInviteFixture{
		tew: f.tew, alice: f.alice, tm: f.tm, tid: f.tid,
		kit: newSocialInviteKit(t), cli: f.cli,
	}
	f2.create(t, nil)
	require.NoError(t, f2.close(t, proto.SocialInviteState_Canceled))

	gcli, closeGuest := f.tew.newSocialInviteGuestClient(t)
	defer closeGuest()
	_, err = gcli.Fetch(m.Ctx(), f2.kit.id)
	require.Equal(t, core.SocialInviteNotFoundError{}, err)
	err = bcli.Reply(m.Ctx(), f2.replyArg(t, bob, 1, "hello?"))
	require.Equal(t, core.SocialInviteNotFoundError{}, err)
	// A retry of the cancel is idempotent, but any other close on the
	// canceled row reads it as never-existed.
	require.NoError(t, f2.close(t, proto.SocialInviteState_Canceled))
	err = f2.close(t, proto.SocialInviteState_Accepted)
	require.Equal(t, core.SocialInviteNotFoundError{}, err)
}

func TestSocialInviteCancelReclaimsCode(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()

	code, err := shared.GenerateStandardInviteCode(m, f.alice.uid)
	require.NoError(t, err)
	f.create(t, code)

	// The same code can't back a second invitation: canceling the first
	// would delete the code and silently revoke the second.
	f2 := &socialInviteFixture{
		tew: f.tew, alice: f.alice, tm: f.tm, tid: f.tid,
		kit: newSocialInviteKit(t), cli: f.cli,
	}
	err = f2.cli.Create(m.Ctx(), f2.createArg(t, code))
	require.Equal(t, core.BadInviteCodeError{}, err)

	require.NoError(t, f.close(t, proto.SocialInviteState_Canceled))

	// The code was handed out inside M_1; deleting it is the revocation.
	rcli, closeReg, err := newRegClientFromEnv(m, f.tew.TestEnv)
	require.NoError(t, err)
	defer closeReg()
	err = rcli.CheckInviteCode(m.Ctx(), *code)
	require.Equal(t, core.BadInviteCodeError{}, err)

	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	var tmp int
	err = db.QueryRow(m.Ctx(),
		`SELECT 1 FROM invite_codes WHERE short_host_id=$1 AND code=$2`,
		m.ShortHostID().ExportToDB(), code.Standard(),
	).Scan(&tmp)
	require.Error(t, err)

	// The canceled row reads as never-existed.
	gcli, closeGuest := f.tew.newSocialInviteGuestClient(t)
	defer closeGuest()
	_, err = gcli.Fetch(m.Ctx(), f.kit.id)
	require.Equal(t, core.SocialInviteNotFoundError{}, err)
}

func TestSocialInviteDeclineReclaimsCodeButStaysReadable(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()

	code, err := shared.GenerateStandardInviteCode(m, f.alice.uid)
	require.NoError(t, err)
	f.create(t, code)

	bob := f.tew.NewTestUser(t)
	f.tew.DirectDoubleMerklePokeInTest(t)
	bcli, closeBob := bob.newSocialInviteClient(t, m.Ctx())
	defer closeBob()
	require.NoError(t, bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "me")))

	require.NoError(t, f.close(t, proto.SocialInviteState_Declined))

	// The decline deletes the unused code, but the invitee's poll can
	// still read the decision.
	rcli, closeReg, err := newRegClientFromEnv(m, f.tew.TestEnv)
	require.NoError(t, err)
	defer closeReg()
	err = rcli.CheckInviteCode(m.Ctx(), *code)
	require.Equal(t, core.BadInviteCodeError{}, err)

	gcli, closeGuest := f.tew.newSocialInviteGuestClient(t)
	defer closeGuest()
	view, err := gcli.Fetch(m.Ctx(), f.kit.id)
	require.NoError(t, err)
	require.Equal(t, proto.SocialInviteState_Declined, view.State)

	// The decision outlives the row's own expiry: a decline made just
	// before etime stays readable until the sweeper's grace elapses.
	setSocialInviteTime(t, m, f.kit.id, "etime", time.Hour)
	view, err = gcli.Fetch(m.Ctx(), f.kit.id)
	require.NoError(t, err)
	require.Equal(t, proto.SocialInviteState_Declined, view.State)
}

func TestSocialInviteExpiry(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()
	f.create(t, nil)

	setSocialInviteTime(t, m, f.kit.id, "etime", time.Hour)

	gcli, closeGuest := f.tew.newSocialInviteGuestClient(t)
	defer closeGuest()
	_, err := gcli.Fetch(m.Ctx(), f.kit.id)
	require.Equal(t, core.SocialInviteNotFoundError{}, err)

	rows, err := f.cli.List(m.Ctx())
	require.NoError(t, err)
	for _, row := range rows {
		require.NotEqual(t, f.kit.id, row.Id)
	}

	bob := f.tew.NewTestUser(t)
	f.tew.DirectDoubleMerklePokeInTest(t)
	bcli, closeBob := bob.newSocialInviteClient(t, m.Ctx())
	defer closeBob()
	err = bcli.Reply(m.Ctx(), f.replyArg(t, bob, 1, "too late"))
	require.Equal(t, core.SocialInviteNotFoundError{}, err)
}

func TestSocialInviteSweeper(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()

	// Four invitations from the same inviter: expired past grace with an
	// unused attached code, terminal past grace, terminal within grace, and
	// live.
	expired := f.kit
	code, err := shared.GenerateStandardInviteCode(m, f.alice.uid)
	require.NoError(t, err)
	f.create(t, code)
	setSocialInviteTime(t, m, expired.id, "etime", 30*24*time.Hour)

	mk := func() *socialInviteKit {
		f.kit = newSocialInviteKit(t)
		f.create(t, nil)
		return f.kit
	}
	terminalOld := mk()
	require.NoError(t, f.close(t, proto.SocialInviteState_Canceled))
	setSocialInviteTime(t, m, terminalOld.id, "mtime", 30*24*time.Hour)

	terminalFresh := mk()
	require.NoError(t, f.close(t, proto.SocialInviteState_Canceled))

	live := mk()

	// Freshly expired, inside grace, with an unused code: the row survives
	// the sweep but the code must not. An expired invitation's signup code
	// is reclaimed at etime, not at etime plus grace.
	f.kit = newSocialInviteKit(t)
	expiredFresh := f.kit
	codeFresh, err := shared.GenerateStandardInviteCode(m, f.alice.uid)
	require.NoError(t, err)
	f.create(t, codeFresh)
	setSocialInviteTime(t, m, expiredFresh.id, "etime", time.Hour)

	err = shared.SweepSocialInvites(m)
	require.NoError(t, err)

	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()

	count := func(q string, args ...any) int {
		var n int
		err := db.QueryRow(m.Ctx(), q, args...).Scan(&n)
		require.NoError(t, err)
		return n
	}
	shid := m.ShortHostID().ExportToDB()

	for _, gone := range []*socialInviteKit{expired, terminalOld} {
		require.Equal(t, 0, count(
			`SELECT COUNT(*) FROM social_invites WHERE short_host_id=$1 AND id=$2`,
			shid, gone.id[:]))
		require.Equal(t, 0, count(
			`SELECT COUNT(*) FROM social_invite_msgs WHERE short_host_id=$1 AND id=$2`,
			shid, gone.id[:]))
	}
	// The expired row's unused code was reclaimed with it.
	require.Equal(t, 0, count(
		`SELECT COUNT(*) FROM invite_codes WHERE short_host_id=$1 AND code=$2`,
		shid, code.Standard()))

	for _, kept := range []*socialInviteKit{terminalFresh, live, expiredFresh} {
		require.Equal(t, 1, count(
			`SELECT COUNT(*) FROM social_invites WHERE short_host_id=$1 AND id=$2`,
			shid, kept.id[:]))
	}
	require.Equal(t, 0, count(
		`SELECT COUNT(*) FROM invite_codes WHERE short_host_id=$1 AND code=$2`,
		shid, codeFresh.Standard()))
}

func TestSocialInviteCreateValidation(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()

	// Unknown team.
	arg := f.createArg(t, nil)
	var badTeam proto.TeamID
	err := core.RandomFill(badTeam[:])
	require.NoError(t, err)
	arg.Team = badTeam
	err = f.cli.Create(m.Ctx(), arg)
	require.Equal(t, core.TeamNotFoundError{}, err)

	// Another user's code.
	other := f.tew.NewTestUser(t)
	f.tew.DirectDoubleMerklePokeInTest(t)
	otherCode, err := shared.GenerateStandardInviteCode(m, other.uid)
	require.NoError(t, err)
	err = f.cli.Create(m.Ctx(), f.createArg(t, otherCode))
	require.Equal(t, core.BadInviteCodeError{}, err)

	// A multiuse code never attaches to a row.
	mu := rem.NewInviteCodeWithMultiuse("sekrit-code")
	err = f.cli.Create(m.Ctx(), f.createArg(t, &mu))
	require.Equal(t, core.BadInviteCodeError{}, err)

	// A nonzero etime in the past is a client bug and refused: the row
	// would be born expired, invisible to every reader.
	arg = f.createArg(t, nil)
	arg.Etime = proto.ExportTime(m.Now().Add(-time.Hour))
	err = f.cli.Create(m.Ctx(), arg)
	require.Error(t, err)
	require.IsType(t, core.BadArgsError(""), err)

	// A requested etime past the host cap comes back clamped.
	arg = f.createArg(t, nil)
	farOut := proto.ExportTime(m.Now().Add(365 * 24 * time.Hour))
	arg.Etime = farOut
	require.NoError(t, f.cli.Create(m.Ctx(), arg))
	row := f.listOne(t)
	require.True(t, row.Etime.Import().Before(farOut.Import()))

	// Duplicate id.
	err = f.cli.Create(m.Ctx(), f.createArg(t, nil))
	require.Error(t, err)

	// Open-invite cap; the fixture's row above counts toward it.
	settings, err := m.G().Config().Settings(m.Ctx())
	require.NoError(t, err)
	cap := settings.SocialInviteMaxOpen()
	for i := 1; i < cap; i++ {
		f.kit = newSocialInviteKit(t)
		f.create(t, nil)
	}
	f.kit = newSocialInviteKit(t)
	err = f.cli.Create(m.Ctx(), f.createArg(t, nil))
	require.Equal(t, core.RateLimitError{}, err)
}

func TestNewInviteCodeCap(t *testing.T) {
	tew := testEnvBeta(t)
	m := tew.MetaContext()
	u := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)
	ucli, closeFn := u.newUserCertAndClient(t, m.Ctx())
	defer closeFn()

	settings, err := m.G().Config().Settings(m.Ctx())
	require.NoError(t, err)
	max := settings.MaxUnusedInviteCodes()

	// A user can hold at most max unused codes; the next mint is refused.
	for i := 0; i < max; i++ {
		_, err := ucli.NewInviteCode(m.Ctx())
		require.NoError(t, err)
	}
	_, err = ucli.NewInviteCode(m.Ctx())
	require.Equal(t, core.RateLimitError{}, err)

	// Consuming a code frees a slot.
	db, err := m.G().Db(m.Ctx(), shared.DbTypeUsers)
	require.NoError(t, err)
	defer db.Release()
	_, err = db.Exec(m.Ctx(),
		`UPDATE invite_codes SET used_by=creator, used_on=NOW()
		 WHERE short_host_id=$1 AND code IN (
			SELECT code FROM invite_codes
			WHERE short_host_id=$1 AND creator=$2 AND used_by IS NULL
			LIMIT 1)`,
		m.ShortHostID().ExportToDB(), u.uid.ExportToDB(),
	)
	require.NoError(t, err)
	_, err = ucli.NewInviteCode(m.Ctx())
	require.NoError(t, err)
}

func TestSocialInviteAuthz(t *testing.T) {
	f := newSocialInviteFixture(t)
	m := f.tew.MetaContext()
	f.create(t, nil)

	mallory := f.tew.NewTestUser(t)
	f.tew.DirectDoubleMerklePokeInTest(t)
	mcli, closeFn := mallory.newSocialInviteClient(t, m.Ctx())
	defer closeFn()

	// Rows the caller doesn't own read as absent.
	rows, err := mcli.List(m.Ctx())
	require.NoError(t, err)
	for _, row := range rows {
		require.NotEqual(t, f.kit.id, row.Id)
	}
	err = mcli.AskAgain(m.Ctx(), rem.AskAgainArg{
		Id:  f.kit.id,
		Msg: f.kit.seal(t, &rem.SocialInviteMsgPayload{Text: "mallory asks"}),
	})
	require.Equal(t, core.SocialInviteNotFoundError{}, err)
	err = mcli.Close(m.Ctx(), rem.CloseArg{
		Id: f.kit.id,
		St: proto.SocialInviteState_Canceled,
	})
	require.Equal(t, core.SocialInviteNotFoundError{}, err)

	// Close only takes terminal states.
	err = f.cli.Close(m.Ctx(), rem.CloseArg{
		Id: f.kit.id,
		St: proto.SocialInviteState_Replied,
	})
	require.Error(t, err)
}
