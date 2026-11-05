// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/librt"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/team"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

// rtSendGenTest is a team of an owner, a writer and a member who gets removed,
// with one chat channel. The writer's client loads the team before the removal
// and keeps it cached for the whole test (FOKS_TEAM_CACHE_TIMEOUT=1h), so its
// key ring is a generation behind when it sends afterwards. A message sealed
// under that old generation could be opened by the removed member, who holds
// its key.
type rtSendGenTest struct {
	tew    *TestEnvWrapper
	tm     *teamObj
	fqt    *proto.FQTeamParsed
	owner  *TestUser
	writer *TestUser
	gone   *TestUser
	ch     proto.RTChannelName
	chid   proto.RTChannelID
	wMc    librt.MetaContext
	wr     *librt.Minder
}

func setupRTSendGenTest(t *testing.T) *rtSendGenTest {
	t.Setenv("FOKS_TEAM_CACHE_TIMEOUT", "1h")
	tew := testEnvBeta(t)
	owner := tew.NewTestUser(t)
	writer := tew.NewTestUser(t)
	gone := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	tm := tew.makeTeamForOwner(t, owner)
	tm.makeChanges(
		t, tew.MetaContext(), owner,
		[]proto.MemberRole{
			writer.toMemberRole(t, proto.AdminRole, tm.hepks),
			gone.toMemberRole(t, proto.AdminRole, tm.hepks),
		},
		nil,
	)
	fqt := tm.ToFQTeamParsed(t)
	ch := proto.RTChannelName("gen")

	oMc := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, owner))
	chid, err := librt.NewMinder(oMc.G().ActiveUser()).MakeChannel(
		oMc, team.WrapNamedPtr(fqt), proto.RTAppID_Chat, ch, "gen",
		proto.RolePairOpt{Read: &proto.DefaultRole, Write: &proto.DefaultRole})
	require.NoError(t, err)

	wMc := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, writer))
	s := &rtSendGenTest{
		tew: tew, tm: tm, fqt: fqt, owner: owner, writer: writer, gone: gone,
		ch: ch, chid: *chid, wMc: wMc, wr: librt.NewMinder(wMc.G().ActiveUser()),
	}
	// The writer loads the team (and its key ring) before the removal.
	s.send(t, "before")
	return s
}

func (s *rtSendGenTest) send(t *testing.T, body string) *rem.RTSendRes {
	res, err := s.wr.Send(s.wMc, team.WrapNamedPtr(s.fqt), proto.RTAppID_Chat,
		makeChannelSpecifier(s.ch), []byte(body))
	require.NoError(t, err)
	return res
}

// removeGone removes the third member, which rotates the team's keys.
func (s *rtSendGenTest) removeGone(t *testing.T) {
	s.tm.makeChanges(t, s.tew.MetaContext(), s.owner, []proto.MemberRole{
		s.gone.toMemberRole(t, proto.NewRoleDefault(proto.RoleType_NONE), s.tm.hepks),
	}, nil)
	s.tew.DirectDoubleMerklePokeInTest(t)
}

// rawOwner is a fresh owner client talking to the realtime server directly,
// to see messages as stored.
func (s *rtSendGenTest) rawOwner(t *testing.T) (libclient.MetaContext, *rem.RealTimeClient) {
	base := s.tew.NewClientMetaContextWithEracer(t, s.owner)
	cert, err := base.ActiveUserClientCert()
	require.NoError(t, err)
	pr := base.G().ActiveUser().HomeServer()
	require.NotNil(t, pr)
	gcli, err := pr.RPCClient(base, proto.ServerType_RealTime, cert)
	require.NoError(t, err)
	cli := core.NewRealTimeClient(gcli, base)
	return base, &cli
}

// sealedGens returns the key generation each message at seqs was sealed under.
func (s *rtSendGenTest) sealedGens(t *testing.T, seqs ...proto.RTMsgSeq) []proto.Generation {
	base, cli := s.rawOwner(t)
	page, err := cli.RtGetThread(base.Ctx(), rem.RTThreadQuery{ChannelID: s.chid, Seqs: seqs})
	require.NoError(t, err)
	require.Len(t, page.SeqMsgs, len(seqs))
	ret := make([]proto.Generation, len(seqs))
	for i, msg := range page.SeqMsgs {
		typ, err := msg.Mw.GetT()
		require.NoError(t, err)
		require.Equal(t, proto.MsgBodyType_Encrypted, typ)
		ret[i] = msg.Mw.Encrypted().Rg.Gen
	}
	return ret
}

// A writer whose cached team predates the removal must still seal its next
// message under the new generation.
func TestRTSendAfterRekeyWithWarmTeamCache(t *testing.T) {
	s := setupRTSendGenTest(t)
	s.removeGone(t)
	res := s.send(t, "after")
	gens := s.sealedGens(t, 1, res.Seq)
	require.Greater(t, gens[1], gens[0])
}

// A message queued offline before the removal and drained after it is sealed
// under the old generation; the drain must re-seal it under the new one.
func TestRTDrainAfterRekeyResealsQueuedMessage(t *testing.T) {
	s := setupRTSendGenTest(t)

	s.wr.SetTestHooks(&librt.MinderTestHooks{
		SendRPC: func(librt.MetaContext, rem.RTSendArg) (*rem.RTSendRes, error) {
			return nil, simTransportErr()
		},
	})
	_, err := s.wr.Send(s.wMc, team.WrapNamedPtr(s.fqt), proto.RTAppID_Chat,
		makeChannelSpecifier(s.ch), []byte("queued"))
	require.ErrorAs(t, err, &core.RTMsgQueuedError{})
	s.wr.SetTestHooks(nil)

	s.removeGone(t)

	dres, err := s.wr.Drain(s.wMc)
	require.NoError(t, err)
	require.Empty(t, dres.FailedErrs)
	require.Len(t, dres.Acked, 1)
	var seq proto.RTMsgSeq
	for _, ack := range dres.Acked {
		seq = ack.Seq
	}
	gens := s.sealedGens(t, 1, seq)
	require.Greater(t, gens[1], gens[0])
}

// A message that landed before the removal but whose ack was lost stays queued
// under the old generation. Its drain after the removal must resolve as a
// replay of the delivered original, not land a second copy.
func TestRTDrainLostAckAcrossRekeyIsReplay(t *testing.T) {
	s := setupRTSendGenTest(t)

	s.wr.SetTestHooks(&librt.MinderTestHooks{
		MutateSendOutcome: func(*rem.RTSendRes, error) (*rem.RTSendRes, error) {
			return nil, simTransportErr()
		},
	})
	_, err := s.wr.Send(s.wMc, team.WrapNamedPtr(s.fqt), proto.RTAppID_Chat,
		makeChannelSpecifier(s.ch), []byte("landed"))
	require.ErrorAs(t, err, &core.RTMsgQueuedError{})
	s.wr.SetTestHooks(nil)

	s.removeGone(t)

	dres, err := s.wr.Drain(s.wMc)
	require.NoError(t, err)
	require.Empty(t, dres.FailedErrs)
	require.Len(t, dres.Acked, 1)
	for _, ack := range dres.Acked {
		require.Equal(t, proto.RTMsgSeq(2), ack.Seq, "the original delivery")
	}
	// The thread holds the two messages sent before the removal, and nothing
	// re-sealed landed as a second copy.
	base, cli := s.rawOwner(t)
	recents, err := cli.RtGetThreadRecents(base.Ctx(), rem.RtGetThreadRecentsArg{Ch: s.chid, Lim: 10})
	require.NoError(t, err)
	require.Len(t, recents.Lst, 2)
	gens := s.sealedGens(t, 1, 2)
	require.Equal(t, gens[0], gens[1], "the original, sealed before the removal")
}
