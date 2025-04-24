// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

func CheckGenericLinkPayload(
	m MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	link proto.GenericLink,
) (
	proto.ChainType,
	error,
) {
	typ, err := link.Payload.GetT()
	if err != nil {
		return typ, err
	}
	switch typ {
	case proto.ChainType_UserSettings:
		uid, err := pid.UID()
		if err != nil {
			return typ, err
		}

		us := link.Payload.Usersettings()
		subtyp, err := us.GetT()
		if err != nil {
			return typ, err
		}
		switch subtyp {
		case proto.UserSettingsType_Passphrase:
			var ppgen int
			var salt []byte
			pp := us.Passphrase()
			err := tx.QueryRow(m.Ctx(),
				`SELECT ppgen, salt FROM passphrase_boxes
	             JOIN user_salts USING(short_host_id, uid)
	             WHERE short_host_id=$1 AND uid=$2
	             ORDER BY ppgen DESC LIMIT 1`,
				int(m.ShortHostID()),
				uid.ExportToDB(),
			).Scan(&ppgen, &salt)
			if errors.Is(err, pgx.ErrNoRows) {
				return typ, core.PassphraseNotFoundError{}
			}
			if err != nil {
				return typ, err
			}
			if pp.Gen != proto.PassphraseGeneration(ppgen) {
				return typ, core.LinkError("wrong passphrase generation")
			}
			if pp.Salt != nil && !bytes.Equal(salt, pp.Salt[:]) {
				return typ, core.LinkError("wrong passphrase salt")
			}
			return typ, nil
		default:
			return typ, core.LinkError("unsupported user settings type")
		}
	case proto.ChainType_TeamMembership:
		return typ, nil
	default:
		return typ, core.LinkError("unsupported payload type for generic link")
	}
}

func VerifyGenericLink(
	m MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	ovgl *core.OpenAndVerifyGenericLinkRes,
) (
	*core.PublicSuiterWithSeqno,
	error,
) {

	if !pid.EntityID().Eq(ovgl.Link.Entity.Entity) {
		return nil, core.PermissionError("generic link not for this user")
	}

	if !m.HostID().Id.Eq(ovgl.Link.Entity.Host) {
		return nil, core.HostMismatchError{}
	}

	var keys map[proto.FQEntityFixed]core.PublicSuiterWithSeqno
	uidp, tidp, err := pid.Select()
	switch {
	case err != nil:
		return nil, err
	case uidp != nil:
		keys, err = ReadDevicesForUser(m, tx, *uidp, m.HostID())
		if err != nil {
			return nil, err
		}
	case tidp != nil:
		keys, err = ReadTeamAdminKeys(m, tx, *tidp)
		if err != nil {
			return nil, err
		}
	default:
		return nil, core.InternalError("invalid party id")
	}

	fed, err := ovgl.Verifier.GetEntityID().Fixed()
	if err != nil {
		return nil, err
	}
	fqef := proto.FQEntityFixed{
		Entity: fed,
		Host:   m.HostID().Id,
	}
	signer, found := keys[fqef]
	if !found {
		return nil, core.VerifyError("key not authorized to sign for party")
	}
	sep := signer.Ps.GetStartEpno()
	if sep == nil {
		return nil, core.SigningKeyNotFullyProvisionedError{}
	}
	if *sep > ovgl.Link.Chainer.Base.Root.Epno {
		return nil, core.VerifyError(
			fmt.Sprintf("signing key too new to sign for this link (%d > %d)",
				*sep, ovgl.Link.Chainer.Base.Root.Epno),
		)
	}

	return &signer, nil
}

func PostGenericLinkTryTx(
	m MetaContext,
	tx pgx.Tx,
	arg rem.PostGenericLinkArg,
	pid proto.PartyID,
	stopper *core.TestStopper,
) error {

	ovgl, err := core.OpenAndVerifyGenericLink(arg.Link)
	if err != nil {
		return err
	}

	typ, err := CheckGenericLinkPayload(m, tx, pid, ovgl.Link)
	if err != nil {
		return err
	}

	err = LockEntity(m, tx, pid.EntityID(), typ, ovgl.Link.Chainer.Base.Seqno)
	if err != nil {
		m.Warnw("postGenericLink", "stage", "LockEntity", "err", err)
		return err
	}

	signer, err := VerifyGenericLink(m, tx, pid, ovgl)
	if err != nil {
		m.Warnw("postGenericLink", "stage", "verifyGenericLink", "err", err)
		return err
	}

	// See `TestTeamMembershipChainRaces` -- we want to interleave a team rotation
	// and a post to the membership chain in a controlled way. Stop after authentication
	// but before the link is posting. This should cause us to die on the revoke_key_locks
	// acquisition.
	if stopper != nil {
		stopper.Wait()
	}

	eid := ovgl.Link.Entity.Entity

	prev, err := ReadChainTail(m, tx, typ, eid)
	if err != nil {
		m.Warnw("postGenericLink", "stage", "readChainTail", "err", err)
		return err
	}

	eidp, err := eid.ToPartyID()
	if err != nil {
		m.Warnw("postGenericLink", "stage", "eid.ToPartyID", "err", err)
		return err
	}

	err = InsertLink(
		m, tx, typ, eidp, signer.ToSignerPair(),
		prev, ovgl.Link.Chainer.Base, arg.Link,
		proto.NewUpdateTriggerDefault(proto.UpdateTriggerType_None),
		nil,
	)
	if err != nil {
		m.Warnw("postGenericLink", "stage", "InsertLink", "err", err)
		return err
	}

	chainer := ovgl.Link.Chainer
	err = InsertTreeLocationMachinery(m, tx, typ,
		pid.EntityID(), chainer.Base.Seqno, nil,
		arg.NextTreeLocation, chainer.NextLocationCommitment)
	if err != nil {
		m.Warnw("rotatePUK", "stage", "insertTreeLocationMachiner", "err", err)
		return err
	}
	return nil

}

func InsertSubchainTreeLocationSeed(
	m MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	seed proto.TreeLocation,
	commitment proto.TreeLocationCommitment,
) error {
	err := core.VerifyTreeLocationCommitment(seed, commitment)
	if err != nil {
		return err
	}
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO subchain_tree_location_seeds(short_host_id, entity_id, seed, ctime)
		 VALUES($1, $2, $3, NOW())`,
		m.ShortHostID().ExportToDB(),
		pid.ExportToDB(),
		seed.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("failed to insert subchain tree location seed")
	}
	return nil

}
