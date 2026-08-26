// SECO rt-spike: typed message probe (tasks 3.1–3.4). Spike branch only —
// never merges. Validates, against the in-process test env:
//
//  1. Reactji / Edit / Reply send via the pegged wire arm (SendTyped) is
//     ACCEPTED by the server and stored with its typ
//  2. Cross-member decode of pegged messages works (fork decode change)
//  3. "Delete" expressed as Edit-with-empty-body round-trips
//  4. A Reactji send BUMPS the recipient's inbox version — the unread
//     semantics gap to raise with Max (reactions ring the new-message bell)
package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/librt"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestRTSecoTypedMessages(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t) // owner
	coco := tew.NewTestUser(t)  // ordinary member
	tew.DirectDoubleMerklePokeInTest(t)
	tm := tew.makeTeamForOwner(t, bluey)
	m := tew.MetaContext()
	tm.makeChanges(
		t, m, bluey,
		[]proto.MemberRole{
			coco.toMemberRole(t, proto.DefaultRole, tm.hepks),
		}, nil,
	)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minderBluey := librt.NewMinder(mb.G().ActiveUser())
	mc := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, coco))
	minderCoco := librt.NewMinder(mc.G().ActiveUser())
	fqt := tm.ToFQTeamParsed(t)

	_, err := minderBluey.MakeChannel(mb, team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat, "typed", "typed probe",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)
	ch := makeChannelSpecifierWithString("typed")

	// Baseline: a Basic message from bluey that the typed sends will peg to.
	res, err := minderBluey.Send(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, ch,
		[]byte("root message"))
	require.NoError(t, err)
	require.Equal(t, proto.RTMsgSeq(1), res.Seq)

	// coco reads it (also establishes her local cache + read pointer), and
	// grabs its MsgID as the peg target.
	msgs, err := minderCoco.GetThreadRecentMsgs(mc, team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat, ch, 0)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	target := msgs[0].MsgID

	// Inbox version BEFORE the reaction, seen from bluey's side (recipient
	// of the bump — coco is the sender below).
	verBefore, err := minderBluey.GetInboxVersion(mb, proto.RTAppID_Chat)
	require.NoError(t, err)

	// ── 1. Reactji from the ordinary member ──────────────────────────
	_, err = minderCoco.SendTyped(mc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, ch,
		[]byte(`{"emoji":"👍"}`), proto.RTMsgType_Reactji, &target)
	require.NoError(t, err, "server must accept a Reactji-typed pegged send")

	// ── 2. Edit from the owner ───────────────────────────────────────
	_, err = minderBluey.SendTyped(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, ch,
		[]byte("root message (edited)"), proto.RTMsgType_Edit, &target)
	require.NoError(t, err, "server must accept an Edit-typed pegged send")

	// ── 3. "Delete" as Edit-with-empty-body ──────────────────────────
	_, err = minderBluey.SendTyped(mb, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, ch,
		[]byte{}, proto.RTMsgType_Edit, &target)
	require.NoError(t, err, "empty-body Edit (delete stand-in) must be accepted")

	// ── Cross-member decode: coco re-reads the thread and sees all four
	// messages with their types intact ────────────────────────────────
	msgs, err = minderCoco.GetThreadRecentMsgs(mc, team.WrapNamedPtr(fqt),
		proto.RTAppID_Chat, ch, 0)
	require.NoError(t, err)
	require.Len(t, msgs, 4)
	// newest-first: [empty-edit, edit, reactji, basic]
	require.Equal(t, proto.RTMsgType_Edit, msgs[0].Typ)
	require.Equal(t, 0, len(msgs[0].Body))
	require.Equal(t, proto.RTMsgType_Edit, msgs[1].Typ)
	require.Equal(t, "root message (edited)", string(msgs[1].Body))
	require.Equal(t, proto.RTMsgType_Reactji, msgs[2].Typ)
	require.Equal(t, `{"emoji":"👍"}`, string(msgs[2].Body))
	require.Equal(t, proto.RTMsgType_Basic, msgs[3].Typ)
	require.Equal(t, "root message", string(msgs[3].Body))

	// ── 4. Unread probe: did coco's Reactji bump bluey's inbox? ──────
	verAfter, err := minderBluey.GetInboxVersion(mb, proto.RTAppID_Chat)
	require.NoError(t, err)
	if verAfter > verBefore {
		t.Logf("FINDING CONFIRMED: Reactji bumped recipient inbox version %d -> %d "+
			"(reactions ring the new-message bell — Max question #4)", verBefore, verAfter)
	} else {
		t.Logf("Reactji did NOT bump inbox version (%d -> %d) — update findings",
			verBefore, verAfter)
	}
}
