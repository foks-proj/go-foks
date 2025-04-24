// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EvilUserLoaderHooks struct {
	PostLoadTreeLocations func(u *UserLoader)
	PostMerkle            func(u *UserLoader)
	PreMerkle             func(u *UserLoader, k *([]proto.MerkleTreeRFOutput))
	PreUsernameMerkleKeys func(u *UserLoader) func()
}

type UserLoader struct {
	db            *pgxpool.Conn
	Arg           rem.LoadUserChainArg
	loggedInUID   *proto.UID
	Res           rem.UserChain
	Locs          map[int]proto.TreeLocation
	Un            proto.Name
	usernameSeqno proto.NameSeqno
	cl            *ChainLoader
	Evil          *EvilUserLoaderHooks
}

func (u *UserLoader) checkArgs(m MetaContext) error {
	if !u.Arg.Start.IsValid() {
		return core.BadArgsError("invalid start seqno; need >=1")
	}
	return nil
}

func (u *UserLoader) Run(m MetaContext, arg rem.LoadUserChainArg) (err error) {
	u.Arg = arg
	err = u.init(m)
	if err != nil {
		return err
	}
	defer func() {
		tmp := u.cleanup(m)
		if err == nil && tmp != nil {
			err = tmp
		}
	}()

	err = u.checkArgs(m)
	if err != nil {
		return err
	}

	err = u.checkPerms(m)
	if err != nil {
		return err
	}

	err = u.loadUsername(m)
	if err != nil {
		return err
	}

	err = u.loadTreeLocations(m)
	if err != nil {
		return err
	}

	err = u.loadChain(m)
	if err != nil {
		return err
	}

	err = u.loadCommittedData(m)
	if err != nil {
		return err
	}

	err = u.loadMerkle(m)
	if err != nil {
		return err
	}

	err = u.loadHEPKs(m)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserLoader) loadUsername(m MetaContext) error {
	nb, err := u.cl.LoadName(m, u.Arg.Uid.ToPartyID())
	if err != nil {
		return err
	}
	u.Res.UsernameUtf8 = nb.B.NameUtf8
	u.Un = nb.B.Name
	u.usernameSeqno = nb.S
	return nil
}

func (u *UserLoader) usernameMerkleKeys(m MetaContext) ([]proto.MerkleTreeRFOutput, error) {

	if u.Evil != nil && u.Evil.PreUsernameMerkleKeys != nil {
		undo := u.Evil.PreUsernameMerkleKeys(u)
		defer undo()
	}

	return nameMerkleKeys(
		m.HostID().Id,
		u.Arg.Username,
		rem.NameSeqnoPair{
			N: u.Un,
			S: u.usernameSeqno,
		},
	)
}

func (u *UserLoader) uidMerkleKeys(m MetaContext) ([]proto.MerkleTreeRFOutput, error) {
	return u.cl.MakeMerkleKeys(m, u.Locs, u.Res.Links)
}

func (u *UserLoader) loadMerkle(m MetaContext) error {

	keys, err := u.usernameMerkleKeys(m)
	if err != nil {
		return err
	}
	u.Res.NumUsernameLinks = uint64(len(keys))

	tmp, err := u.uidMerkleKeys(m)
	if err != nil {
		return err
	}
	keys = append(keys, tmp...)

	if u.Evil != nil && u.Evil.PreMerkle != nil {
		u.Evil.PreMerkle(u, &keys)
	}

	res, err := u.cl.LoadMerkle(m, keys)
	if err != nil {
		return err
	}

	u.Res.Merkle = *res

	if u.Evil != nil && u.Evil.PostMerkle != nil {
		u.Evil.PostMerkle(u)
	}
	return nil
}

func (u *UserLoader) loadTreeLocations(m MetaContext) error {

	var err error
	u.Locs, u.Res.Locations, err = u.cl.LoadTreeLocations(m)
	if err != nil {
		return err
	}
	if u.Evil != nil && u.Evil.PostLoadTreeLocations != nil {
		u.Evil.PostLoadTreeLocations(u)
	}
	return nil
}

func (u *UserLoader) loadHEPKs(m MetaContext) error {
	set, err := u.cl.LoadHEPKs(m, u.Res.Links)
	if err != nil {
		return err
	}
	u.Res.Hepks = *set
	return nil
}

func (u *UserLoader) loadChain(m MetaContext) error {

	var err error
	u.Res.Links, err = u.cl.LoadChain(m)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserLoader) isSelfLoad() bool { return u.loggedInUID != nil && u.loggedInUID.Eq(u.Arg.Uid) }

func (u *UserLoader) loadCommittedData(m MetaContext) error {

	return iterateOverChangeMetadata(u.Res.Links, func(c proto.ChangeMetadata) error {
		t, err := c.GetT()
		if err != nil {
			return err
		}
		switch t {
		case proto.ChangeType_Username:
			comm := c.Username()
			var res rem.NameCommitmentAndKey
			res.Key, err = LoadCommitment(m.Ctx(), u.db, m.ShortHostID(), comm, &res.Unc, nil)
			if err != nil {
				return err
			}
			u.Res.Usernames = append(u.Res.Usernames, res)
		case proto.ChangeType_DeviceName:
			if u.isSelfLoad() {
				comm := c.Devicename()
				var res rem.DeviceLabelNameAndCommitmentKey
				var aux proto.DeviceNameNormalizationPreimage
				res.CommitmentKey, err = LoadCommitment(
					m.Ctx(),
					u.db,
					m.ShortHostID(),
					comm,
					&res.Dln.Label,
					&aux,
				)
				if err != nil {
					return err
				}
				res.Dln.Nv = aux.Nv
				res.Dln.Name = aux.Name
				u.Res.DeviceNames = append(u.Res.DeviceNames, res)
			}
		}
		return nil
	})
}

func (u *UserLoader) checkPerms(m MetaContext) error {

	var q string
	var args []any

	if u.isSelfLoad() {
		return nil
	}

	atyp, err := u.Arg.Auth.GetT()
	if err != nil {
		return err
	}

	switch atyp {
	case rem.LoadUserChainAuthType_Token:
		tok := u.Arg.Auth.Token()
		q = `SELECT 1 FROM remote_view_permissions
		     WHERE short_host_id=$1
			 AND token=$2 AND target_eid=$3 AND state='valid'`
		args = []any{
			m.ShortHostID().ExportToDB(),
			tok.ExportToDB(),
			u.Arg.Uid.ExportToDB(),
		}
	case rem.LoadUserChainAuthType_SelfToken:
		tok := u.Arg.Auth.Selftoken()
		q = `SELECT 1 FROM self_view_tokens
			 WHERE short_host_id=$1
			 AND uid=$2
			 AND view_token=$3`
		args = []any{
			int(m.ShortHostID()),
			u.Arg.Uid.ExportToDB(),
			tok.ExportToDB(),
		}
	case rem.LoadUserChainAuthType_AsLocalTeam:
		creds, err := CheckTeamVOBearerToken(m, u.db, u.Arg.Auth.Aslocalteam(), 0)
		if err != nil {
			return err
		}
		if !creds.Req.Member.Host.Eq(m.HostID().Id) {
			return core.HostMismatchError{}
		}
		isId, err := creds.Req.Team.IdOrName.GetId()
		if err != nil {
			return err
		}
		if !isId {
			return core.BadArgsError("team id must be an ID")
		}
		teamID := creds.Req.Team.IdOrName.True()
		q = `SELECT 1 FROM local_view_permissions 
			 WHERE short_host_id=$1
			 AND viewer_eid=$2
			 AND target_eid=$3
			 AND state='valid'`
		args = []any{
			m.ShortHostID().ExportToDB(),
			teamID.ExportToDB(),
			u.Arg.Uid.ExportToDB(),
		}
	case rem.LoadUserChainAuthType_AsLocalUser:
		if u.loggedInUID != nil {
			q = `SELECT 1 FROM local_view_permissions
		     WHERE short_host_id=$1 
			 AND viewer_eid=$2 
			 AND target_eid=$3
			 AND state='valid'`
			args = []any{
				m.ShortHostID().ExportToDB(),
				u.loggedInUID.ExportToDB(),
				u.Arg.Uid.ExportToDB(),
			}
		} else {
			return core.PermissionError("no logged in UID available")
		}
	case rem.LoadUserChainAuthType_OpenVHost:
		if u.loggedInUID == nil {
			return core.PermissionError("no logged in UID available for open vhost")
		}
		cfg, err := m.G().HostIDMap().Config(m, m.ShortHostID())
		if err != nil {
			return err
		}
		switch cfg.Viewership.User {
		case proto.ViewershipMode_OpenToAll:
			return nil
		default:
			return core.PermissionError("no open viewership mode")
		}
	default:
		return core.PermissionError("no token or logged in UID available")
	}

	var dummy int
	err = u.db.QueryRow(m.Ctx(), q, args...).Scan(&dummy)
	if err == pgx.ErrNoRows || dummy != 1 {
		return core.PermissionError("no view permission")
	}
	if err != nil {
		return err
	}
	return nil
}

func (u *UserLoader) init(m MetaContext) error {
	db, err := m.G().Db(m.Ctx(), DbTypeUsers)
	if err != nil {
		return err
	}
	u.db = db
	u.cl = NewChainLoader(u.Arg.Uid.EntityID(), proto.ChainType_User, u.Arg.Start, u.db)
	return nil
}

func (u *UserLoader) cleanup(m MetaContext) error {
	u.db.Release()
	return nil
}

func NewUserLoader(loggedInUID *proto.UID) *UserLoader {
	return &UserLoader{loggedInUID: loggedInUID}
}

func LoadUserChain(m MetaContext, loggedInUUID *proto.UID, arg rem.LoadUserChainArg) (rem.UserChain, error) {
	var zed rem.UserChain
	u := NewUserLoader(loggedInUUID)
	err := u.Run(m, arg)
	if err != nil {
		return zed, err
	}
	return u.Res, nil
}
