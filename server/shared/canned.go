// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
)

// "Canned" hosts are those for which we manage a wildcard domain and allow the users choice
// of a subdomain.  Like max.geocities.com, where *.geocties.com is managed by the service.
type CannedMinder struct {
	// Specify for Run()
	Hostname proto.Hostname // What the user picked
	// Specify For Run()
	CannedDomain proto.Hostname // What the service provides
	// Specify for Recheck or Abort
	VHostID *proto.VHostID

	InviteCode rem.MultiUseInviteCode // If we want to create an invite code with the host
	Metering   proto.Metering         // Metering for the host
	Beacon     *GlobalService         // In test, we might need to pass the Beacon service through

	// Internal state
	vm *VanityMinder
}

func (c *CannedMinder) dbInsStage1(m MetaContext, tx pgx.Tx) error {
	c.VHostID = c.vm.VHostID
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO canned_vhost_build(vhost_id, short_host_id, uid, hostname, canned_domain, cancel_id)
		 VALUES($1, $2, $3, $4, $5, $6)`,
		c.VHostID.ExportToDB(),
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		c.Hostname.String(),
		c.CannedDomain.String(),
		proto.NilCancelID(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("canned_vhost_build")
	}
	return nil
}

func (c *CannedMinder) autosetDNS(m MetaContext) error {
	hlp := m.G().VanityHelper()
	if hlp == nil {
		return core.InternalError("no vanity helper")
	}
	if c.vm == nil {
		return core.InternalError("no vanity minder")
	}
	err := hlp.SetCNAME(m, c.vm.Vstem, c.vm.HostedStem)
	if err != nil {
		return err
	}
	return nil
}

func (c *CannedMinder) initVanityMinder(m MetaContext) error {
	vm := VanityMinder{
		Vstem:      c.Hostname.Join(c.CannedDomain),
		InviteCode: c.InviteCode,
		Metering:   c.Metering,
		Beacon:     c.Beacon,
		IsCanned:   true,
		VHostID:    c.VHostID,
		dbInsStage1TxHook: func(m MetaContext, tx pgx.Tx) error {
			return c.dbInsStage1(m, tx)
		},
		autosetDNSHook: func(m MetaContext) error {
			// SetDNS can only be called after the VHostID and stem are loaded from
			// the DB in vanity stage2. So we provide a hook here to hook into
			// that flow.
			return c.autosetDNS(m)
		},
	}
	c.vm = &vm
	return nil
}

func (c *CannedMinder) Run(m MetaContext) error {
	return c.run(m, true)
}

func (c *CannedMinder) HostIDAndName() (*core.HostIDAndName, error) {
	return c.vm.HostIDAndName()
}

func (c *CannedMinder) run(m MetaContext, stage1 bool) error {
	m.Infow("CannedMinder", "stage", "run")

	err := c.initVanityMinder(m)
	if err != nil {
		return err
	}

	if stage1 {
		m.Infow("CannedMinder", "stage", "1")
		err = c.vm.Stage1(m)
		if err != nil {
			return err
		}
	}

	// Is either set by the caller or inside of dbInsStage1 on successful stage1.
	if c.VHostID == nil {
		return core.InternalError("no VHostID")
	}

	m.Infow("CannedMinder", "stage", "2")
	err = c.vm.Stage2(m)
	if err != nil {
		return err
	}
	return nil
}

// Recheck is used if we failed to get a cert from let's encrypt, or we failed to update our
// DNS records via Route53, etc.
func (c *CannedMinder) Recheck(m MetaContext) error {
	return c.run(m, false)
}

func (c *CannedMinder) Abort(m MetaContext, uid proto.UID, vhid proto.VHostID) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	return RetryTxUserDB(m, "CannedCreator.Abort", func(m MetaContext, tx pgx.Tx) error {
		err := abortVanityBuildTx(m, tx, uid, vhid)
		if err != nil {
			return err
		}
		canc, err := proto.NewCancelID()
		if err != nil {
			return err
		}
		tag, err := tx.Exec(m.Ctx(),
			`UPDATE canned_vhost_build
			 SET cancel_id=$1
			 WHERE vhost_id=$2 AND short_host_id=$3 AND uid=$4`,
			canc.ExportToDB(),
			vhid.ExportToDB(),
			m.ShortHostID().ExportToDB(),
			uid.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("canned_vhost_build")
		}
		return nil
	})
}
