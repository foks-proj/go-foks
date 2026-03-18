// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"fmt"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type DumpSigchain struct {
	CLIAppBase
	partyID string
}

func (d *DumpSigchain) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "dump-sigchain <party-id>",
		Short: "Dump all sigchain links for a given party (user or team) in human-readable form",
	}
	return ret
}

func (d *DumpSigchain) CheckArgs(args []string) error {
	if len(args) != 1 {
		return core.BadArgsError("must supply a party ID via positional arg")
	}
	d.partyID = args[0]
	return nil
}

func (d *DumpSigchain) Run(m shared.MetaContext) error {
	eid, err := proto.ImportEntityIDFromString(d.partyID)
	if err != nil {
		return fmt.Errorf("parsing party ID: %w", err)
	}
	pid, err := eid.ToPartyID()
	if err != nil {
		return fmt.Errorf("converting to party ID: %w", err)
	}

	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	rows, err := db.Query(
		m.Ctx(),
		`SELECT chain_type, seqno, body, hash, ctime
		 FROM links
		 WHERE short_host_id=$1 AND entity_id=$2
		 ORDER BY chain_type ASC, seqno ASC`,
		m.ShortHostID().ExportToDB(),
		pid.ExportToDB(),
	)
	if err != nil {
		return fmt.Errorf("querying links: %w", err)
	}
	defer rows.Close()

	pidStr, _ := pid.StringErr()
	fmt.Printf("=== Sigchain dump for party %s ===\n\n", pidStr)

	count := 0
	var lastChainType proto.ChainType = -1

	for rows.Next() {
		var chainType int
		var seqno int64
		var body []byte
		var hash []byte
		var ctime time.Time

		if err := rows.Scan(&chainType, &seqno, &body, &hash, &ctime); err != nil {
			return fmt.Errorf("scanning row: %w", err)
		}

		ct := proto.ChainType(chainType)
		if ct != lastChainType {
			ctName := proto.ChainTypeRevMap[ct]
			if ctName == "" {
				ctName = fmt.Sprintf("unknown(%d)", chainType)
			}
			fmt.Printf("--- Chain: %s (type=%d) ---\n\n", ctName, chainType)
			lastChainType = ct
		}

		var linkHash proto.LinkHash
		if len(hash) == len(linkHash) {
			copy(linkHash[:], hash)
		}

		fmt.Printf("Link #%d  hash=%s  ctime=%s\n",
			seqno,
			linkHash.String(),
			ctime.UTC().Format(time.RFC3339),
		)

		var link proto.LinkOuter
		if err := core.DecodeFromBytes(&link, body); err != nil {
			fmt.Printf("  ERROR decoding LinkOuter: %v\n\n", err)
			continue
		}

		v, err := link.GetV()
		if err != nil {
			fmt.Printf("  ERROR getting link version: %v\n\n", err)
			continue
		}
		fmt.Printf("  version: %d\n", int(v))

		if v != proto.LinkVersion_V1 {
			fmt.Printf("  (unsupported link version, skipping inner decode)\n\n")
			continue
		}

		lov1 := link.V1()
		printSignatures(lov1.Signatures)

		inner, err := lov1.Inner.AllocAndDecode(core.DecoderFactory{})
		if err != nil {
			fmt.Printf("  ERROR decoding inner blob: %v\n\n", err)
			continue
		}

		lt, err := inner.GetT()
		if err != nil {
			fmt.Printf("  ERROR getting link type: %v\n\n", err)
			continue
		}

		switch lt {
		case proto.LinkType_GROUP_CHANGE:
			printGroupChange(inner.GroupChange())
		case proto.LinkType_GENERIC:
			printGenericLink(inner.Generic())
		default:
			fmt.Printf("  link type: unknown(%d)\n", int(lt))
		}

		fmt.Println()
		count++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating rows: %w", err)
	}

	fmt.Printf("=== Total: %d links ===\n", count)
	return nil
}

func (d *DumpSigchain) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*DumpSigchain)(nil)

func init() {
	AddCmd(&DumpSigchain{})
}

func entityStr(eid proto.EntityID) string {
	s, err := eid.StringErr()
	if err != nil {
		return fmt.Sprintf("<error: %v>", err)
	}
	return s
}

func hostStr(hid proto.HostID) string {
	s, err := hid.StringErr()
	if err != nil {
		return fmt.Sprintf("<error: %v>", err)
	}
	return s
}

func roleStr(r proto.Role) string {
	name, ok := proto.RoleTypeRevMap[r.T]
	if !ok {
		return fmt.Sprintf("unknown(%d)", int(r.T))
	}
	return name
}

func printChainer(c proto.HidingChainer) {
	b := c.Base
	fmt.Printf("  chainer:\n")
	fmt.Printf("    seqno: %d\n", int(b.Seqno))
	if b.Prev != nil {
		fmt.Printf("    prev:  %s\n", b.Prev.String())
	} else {
		fmt.Printf("    prev:  <nil> (eldest)\n")
	}
	fmt.Printf("    time:  %s\n", b.Time.Import().Format(time.RFC3339))
}

func printSignatures(sigs []proto.Signature) {
	for i, sig := range sigs {
		typName, ok := proto.SignatureTypeRevMap[sig.T]
		if !ok {
			typName = fmt.Sprintf("unknown(%d)", int(sig.T))
		}
		fmt.Printf("  sig[%d]: type=%s\n", i, typName)
	}
}

func printGroupChange(gc proto.GroupChange) {
	fmt.Printf("  type: GROUP_CHANGE\n")
	printChainer(gc.Chainer)
	fmt.Printf("  entity: %s @ %s\n", entityStr(gc.Entity.Entity), hostStr(gc.Entity.Host))
	fmt.Printf("  signer: key=%s\n", entityStr(gc.Signer.Key))
	if gc.Signer.KeyOwner != nil {
		ko := gc.Signer.KeyOwner
		pid, _ := ko.Party.StringErr()
		fmt.Printf("    key-owner: party=%s src-role=%s\n", pid, roleStr(ko.SrcRole))
	}

	if len(gc.Changes) > 0 {
		fmt.Printf("  changes:\n")
		for i, mr := range gc.Changes {
			mem := mr.Member
			fmt.Printf("    [%d] dst-role=%s\n", i, roleStr(mr.DstRole))
			fmt.Printf("        member: %s\n", entityStr(mem.Id.Entity))
			if mem.Id.Host != nil {
				fmt.Printf("        host:   %s\n", hostStr(*mem.Id.Host))
			}
			fmt.Printf("        src-role=%s\n", roleStr(mem.SrcRole))
		}
	}

	if len(gc.SharedKeys) > 0 {
		fmt.Printf("  shared-keys: %d key(s)\n", len(gc.SharedKeys))
	}

	if len(gc.Metadata) > 0 {
		fmt.Printf("  metadata:\n")
		for i, cm := range gc.Metadata {
			ctName, ok := proto.ChangeTypeRevMap[cm.T]
			if !ok {
				ctName = fmt.Sprintf("unknown(%d)", int(cm.T))
			}
			fmt.Printf("    [%d] type=%s\n", i, ctName)
		}
	}
}

func printGenericLink(gl proto.GenericLink) {
	fmt.Printf("  type: GENERIC\n")
	printChainer(gl.Chainer)
	fmt.Printf("  entity: %s @ %s\n", entityStr(gl.Entity.Entity), hostStr(gl.Entity.Host))
	fmt.Printf("  signer: %s\n", entityStr(gl.Signer.Entity))
	if gl.Signer.Host != nil {
		fmt.Printf("    host: %s\n", hostStr(*gl.Signer.Host))
	}

	pt, err := gl.Payload.GetT()
	if err != nil {
		fmt.Printf("  payload: ERROR getting type: %v\n", err)
		return
	}

	ctName := proto.ChainTypeRevMap[pt]
	fmt.Printf("  payload-type: %s\n", ctName)

	switch pt {
	case proto.ChainType_UserSettings:
		us := gl.Payload.Usersettings()
		usName, ok := proto.UserSettingsTypeRevMap[us.T]
		if !ok {
			usName = fmt.Sprintf("unknown(%d)", int(us.T))
		}
		fmt.Printf("  user-settings: %s\n", usName)
	case proto.ChainType_TeamMembership:
		tm := gl.Payload.Teammembership()
		fmt.Printf("  team-membership:\n")
		fmt.Printf("    team: %s @ %s\n",
			entityStr(tm.Team.Team.EntityID()),
			hostStr(tm.Team.Host),
		)
		fmt.Printf("    src-role: %s\n", roleStr(tm.SrcRole))
		stateName, ok := proto.TeamMembershipLinkStateRevMap[tm.State.T]
		if !ok {
			stateName = fmt.Sprintf("unknown(%d)", int(tm.State.T))
		}
		fmt.Printf("    state: %s\n", stateName)
	}
}
