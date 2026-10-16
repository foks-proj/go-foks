// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

// Social invites (docs/social_signup_spec.md), client side. The seed is the
// only secret: the id, box key and write key all derive from it, and the host
// keeps a copy sealed to the inviter's PUK, so the inviter needs no local
// state. Callers see plaintext; boxes are sealed and opened here.

type socialInviteKeys struct {
	id proto.SocialInviteID
	ek proto.SecretBoxKey
	wk proto.SocialInviteWriteKey
}

func deriveSocialInviteKeys(s proto.SocialInviteSeed) (*socialInviteKeys, error) {
	id, err := core.DeriveSocialInviteID(s)
	if err != nil {
		return nil, err
	}
	ek, err := core.DeriveSocialInviteBoxKey(s)
	if err != nil {
		return nil, err
	}
	wk, err := core.DeriveSocialInviteWriteKey(s)
	if err != nil {
		return nil, err
	}
	return &socialInviteKeys{id: *id, ek: *ek, wk: *wk}, nil
}

func (k *socialInviteKeys) seal(p *rem.SocialInviteMsgPayload) (*proto.SecretBox, error) {
	return core.SealIntoSecretBox(p, &k.ek)
}

func (k *socialInviteKeys) open(msgs []rem.SocialInviteMsg) ([]lcl.SocialInviteLocalMsg, error) {
	ret := make([]lcl.SocialInviteLocalMsg, 0, len(msgs))
	for _, msg := range msgs {
		var p rem.SocialInviteMsgPayload
		err := core.OpenSecretBoxInto(&p, msg.Box, &k.ek)
		if err != nil {
			return nil, err
		}
		ret = append(ret, lcl.SocialInviteLocalMsg{
			Seq:    msg.Seq,
			Sender: msg.Sender,
			Text:   p.Text,
			Team:   p.Team,
			User:   p.User,
		})
	}
	return ret, nil
}

// openingTeam is the team named in the inviter's opening turn. The inviter
// sealed it, so unlike the row's team column the host cannot change it.
func openingTeam(msgs []lcl.SocialInviteLocalMsg) *proto.FQTeam {
	for _, msg := range msgs {
		if msg.Seq == 1 && msg.Sender == proto.SocialInviteParty_Inviter {
			return msg.Team
		}
	}
	return nil
}

func socialInviteClient(m MetaContext) (*UserContext, *rem.SocialInviteClient, error) {
	au := m.G().ActiveUser()
	if au == nil {
		return nil, nil, core.NoActiveUserError{}
	}
	gcli, err := au.UserGCli(m)
	if err != nil {
		return nil, nil, err
	}
	cli := core.NewSocialInviteClient(gcli, m)
	return au, &cli, nil
}

// SocialInviteCreate opens an invitation into team with text as the opening
// message, and returns the seed to hand to the invitee.
func SocialInviteCreate(m MetaContext, arg lcl.SocialInviteCreateArg) (*lcl.SocialInviteCreateRes, error) {
	au, cli, err := socialInviteClient(m)
	if err != nil {
		return nil, err
	}
	var fqt proto.FQTeam
	err = au.TeamMinder().withLoadedTeam(m, arg.Team, LoadTeamOpts{Refresh: true},
		func(m MetaContext, tr *TeamRecord) error {
			fqt = tr.FQT()
			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	var seed proto.SocialInviteSeed
	err = core.RandomFill(seed[:])
	if err != nil {
		return nil, err
	}
	keys, err := deriveSocialInviteKeys(seed)
	if err != nil {
		return nil, err
	}
	puks, err := au.RefreshPUKs(m)
	if err != nil {
		return nil, err
	}
	puk := puks.Current()
	if puk == nil {
		return nil, core.KeyNotFoundError{Which: "PUK"}
	}
	box, err := core.SelfBox(puk, &seed, au.HostID())
	if err != nil {
		return nil, err
	}
	gen := puk.Metadata().Gen
	role := au.Role()
	msg, err := keys.seal(&rem.SocialInviteMsgPayload{Text: arg.Text, Team: &fqt})
	if err != nil {
		return nil, err
	}
	commit, err := core.CommitSocialInviteWriteKey(keys.wk)
	if err != nil {
		return nil, err
	}
	err = cli.Create(m.Ctx(), rem.CreateArg{
		Id:   keys.id,
		Team: fqt.Team,
		SeedBox: proto.SharedKeyBox{
			Gen:  gen,
			Role: role,
			Box:  *box,
			Targ: proto.SharedKeyBoxTarget{
				Eid:  au.UID().EntityID(),
				Role: role,
				Gen:  gen,
			},
		},
		Msg:      *msg,
		WkCommit: *commit,
		Etime:    arg.Etime,
	})
	if err != nil {
		return nil, err
	}
	return &lcl.SocialInviteCreateRes{Id: keys.id, Seed: seed}, nil
}

// SocialInviteList returns the active user's invitations, each seed opened
// with the PUK generation its box was sealed to, so a rotation since creation
// strands nothing.
func SocialInviteList(m MetaContext) ([]lcl.SocialInviteLocalRow, error) {
	au, cli, err := socialInviteClient(m)
	if err != nil {
		return nil, err
	}
	rows, err := cli.List(m.Ctx())
	if err != nil {
		return nil, err
	}
	pm := NewPUKMinder(au)
	ret := make([]lcl.SocialInviteLocalRow, 0, len(rows))
	for _, row := range rows {
		puk, err := pm.GetPUKAtRoleAndGeneration(m, row.SeedBox.Role, row.SeedBox.Gen)
		if err != nil {
			return nil, err
		}
		var seed proto.SocialInviteSeed
		err = core.SelfUnbox(puk, &seed, row.SeedBox.Box)
		if err != nil {
			return nil, err
		}
		keys, err := deriveSocialInviteKeys(seed)
		if err != nil {
			return nil, err
		}
		// The host chooses which box goes with which row; the seed must
		// derive the row it came with.
		if keys.id != row.Id {
			return nil, core.BadServerDataError("social invite seed does not match its row")
		}
		msgs, err := keys.open(row.Msgs)
		if err != nil {
			return nil, err
		}
		team := openingTeam(msgs)
		if team == nil || !team.Team.Eq(row.Team) || !team.Host.Eq(au.HostID()) {
			return nil, core.BadServerDataError("social invite team does not match its opening message")
		}
		ret = append(ret, lcl.SocialInviteLocalRow{
			Id:    row.Id,
			Seed:  seed,
			Team:  *team,
			State: row.State,
			Msgs:  msgs,
			Ctime: row.Ctime,
			Mtime: row.Mtime,
			Etime: row.Etime,
		})
	}
	return ret, nil
}

// SocialInviteFetch reads an invitation from the host behind prb. It needs no
// account, so an invitee can read the opening message before signing up.
func SocialInviteFetch(m MetaContext, prb *chains.Probe, seed proto.SocialInviteSeed) (*lcl.SocialInviteLocalView, error) {
	keys, err := deriveSocialInviteKeys(seed)
	if err != nil {
		return nil, err
	}
	gcli, err := prb.RegGCli(m)
	if err != nil {
		return nil, err
	}
	defer gcli.Shutdown()
	cli := core.NewSocialInviteGuestClient(gcli, m)
	view, err := cli.Fetch(m.Ctx(), keys.id)
	if err != nil {
		return nil, err
	}
	msgs, err := keys.open(view.Msgs)
	if err != nil {
		return nil, err
	}
	return &lcl.SocialInviteLocalView{Id: keys.id, State: view.State, Msgs: msgs}, nil
}

// SocialInviteReply answers the inviter turn arg.InReplyTo as the active user,
// naming them in the reply. If the opening message names a team, it first
// grants that team local view of the active user: on a closed-viewership host
// that grant is what lets the inviter load, and so add, the invitee.
func SocialInviteReply(m MetaContext, arg lcl.SocialInviteReplyArg) error {
	au, cli, err := socialInviteClient(m)
	if err != nil {
		return err
	}
	keys, err := deriveSocialInviteKeys(arg.Seed)
	if err != nil {
		return err
	}
	view, err := SocialInviteFetch(m, au.HomeServer(), arg.Seed)
	if err != nil {
		return err
	}
	// Refuse a decided invitation here rather than at the host, so the grant
	// below never reaches a team that has already declined or admitted.
	switch view.State {
	case proto.SocialInviteState_Open, proto.SocialInviteState_Replied, proto.SocialInviteState_AskAgain:
	default:
		return core.SocialInviteWrongStateError{}
	}
	if team := openingTeam(view.Msgs); team != nil {
		if !team.Host.Eq(au.HostID()) {
			return core.HostMismatchError{}
		}
		ucli, err := au.UserClient(m)
		if err != nil {
			return err
		}
		_, err = ucli.GrantLocalViewPermissionForUser(m.Ctx(), rem.GrantLocalViewPermissionPayload{
			Viewee: au.UID().ToPartyID(),
			Viewer: team.Team.ToPartyID(),
		})
		if err != nil {
			return err
		}
	}
	fqu := au.FQU()
	msg, err := keys.seal(&rem.SocialInviteMsgPayload{Text: arg.Text, User: &fqu})
	if err != nil {
		return err
	}
	return cli.Reply(m.Ctx(), rem.ReplyArg{
		Id:        keys.id,
		Wk:        keys.wk,
		InReplyTo: arg.InReplyTo,
		Msg:       *msg,
	})
}

// SocialInviteAskAgain appends the inviter's next turn.
func SocialInviteAskAgain(m MetaContext, arg lcl.SocialInviteAskAgainArg) error {
	_, cli, err := socialInviteClient(m)
	if err != nil {
		return err
	}
	keys, err := deriveSocialInviteKeys(arg.Seed)
	if err != nil {
		return err
	}
	msg, err := keys.seal(&rem.SocialInviteMsgPayload{Text: arg.Text})
	if err != nil {
		return err
	}
	return cli.AskAgain(m.Ctx(), rem.AskAgainArg{Id: keys.id, Msg: *msg})
}

// SocialInviteClose records the inviter's decision. Accepting is bookkeeping:
// the team edit that admits the invitee happens separately, before this.
func SocialInviteClose(m MetaContext, arg lcl.SocialInviteCloseArg) error {
	_, cli, err := socialInviteClient(m)
	if err != nil {
		return err
	}
	return cli.Close(m.Ctx(), rem.CloseArg{Id: arg.Id, St: arg.St})
}
