// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jedib0t/go-pretty/v6/table"
)

type tableRow interface {
	toTableRow() table.Row
	headers() table.Row
	lessThan(other tableRow) bool
}

type userRow struct {
	active          bool
	username        string
	hostname        string
	role            string
	dev             string
	locked          string
	connected       string
	devname         string
	mode            userListTableMode
	showDeviceNames bool
}

func (u userRow) toTableRow() table.Row {
	sActive := ""
	if u.active {
		sActive = "*"
	}
	ret := table.Row{sActive, u.username, u.hostname, u.dev}
	if u.showDeviceNames {
		ret = append(ret, u.devname)
	}
	if u.mode == userListTableModeMem {
		ret = append(ret, u.locked, u.connected)
	}
	return ret
}

func cicmp(s1 string, s2 string) int {
	return strings.Compare(strings.ToLower(s1), strings.ToLower(s2))
}

func (u userRow) lessThan(other tableRow) bool {
	ou := other.(userRow)

	cmp := cicmp(u.hostname, ou.hostname)
	if cmp != 0 {
		return (cmp < 0)
	}
	cmp = cicmp(u.username, ou.username)
	if cmp != 0 {
		return (cmp < 0)
	}
	cmp = cicmp(u.role, ou.role)
	if cmp != 0 {
		return (cmp < 0)
	}
	cmp = cicmp(u.devname, ou.devname)
	return (cmp < 0)
}

func (u userRow) headers() table.Row {
	ret := table.Row{
		"Active",
		"Username",
		"Hostname",
		"Key Type",
	}
	if u.showDeviceNames {
		ret = append(ret, "Key Name")
	}

	if u.mode == userListTableModeMem {
		ret = append(ret, "Locked", "Connected")

	}
	return ret
}

var _ tableRow = userRow{}

type outputTableOpts struct {
	headers bool
	title   string
}

func outputTable(
	m libclient.MetaContext,
	opts outputTableOpts,
	list []tableRow,
	doSep func(a, b tableRow) bool,
) error {
	t := table.NewWriter()
	if len(list) > 0 && opts.headers {
		t.AppendHeader(list[0].headers())
	}
	if opts.title != "" {
		t.SetTitle(opts.title)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].lessThan(list[j])
	})
	var prev tableRow
	for _, row := range list {
		curr := row.toTableRow()
		if doSep != nil && doSep(prev, row) {
			t.AppendSeparator()
		}
		t.AppendRow(curr)
		prev = row
	}
	t.SetStyle(table.StyleLight)
	dat := t.Render()
	_, err := os.Stdout.Write([]byte(dat + "\n"))
	return err

}

func convertRows[T any](
	list []T,
	conv func(i int, t T) (tableRow, error),
) (
	[]tableRow,
	error,
) {
	ret := make([]tableRow, len(list))
	for i, v := range list {
		tmp, err := conv(i, v)
		if err != nil {
			return nil, err
		}
		ret[i] = tmp
	}
	return ret, nil
}

func convertAndOutputRows[T any](
	m libclient.MetaContext,
	opts outputTableOpts,
	list []T,
	conv func(i int, t T) (tableRow, error),
	doSep func(a, b tableRow) bool,
) error {
	tmp, err := convertRows(list, conv)
	if err != nil {
		return err
	}
	return outputTable(m, opts, tmp, doSep)
}

type userListTableMode int

const (
	userListTableModeDisk userListTableMode = iota
	userListTableModeMem
)

func networkStatusToString(s proto.Status) string {
	err := core.StatusToError(s)
	if err == nil {
		return "✅"
	}
	return "❌"
}

func lockStatusToString(s proto.Status) string {
	locked := ""
	lockErr := core.StatusToError(s)
	switch lockErr.(type) {
	case nil:
		locked = ""
	case core.PassphraseLockedError:
		locked = "🔒 (passphrase)"
	case core.YubiLockedError:
		locked = "🔒 (yubikey)"
	case core.SSOIdPLockedError:
		locked = "🔒 (SSO/IdP)"
	default:
		locked = "🔒 (other)"
	}
	return locked
}

func deviceTypeToString(t proto.DeviceType) string {
	switch t {
	case proto.DeviceType_YubiKey:
		return "YubiKey"
	case proto.DeviceType_Computer:
		return "device"
	case proto.DeviceType_Backup:
		return "backup"
	default:
		return "other"
	}
}

func outputUserListTable(
	m libclient.MetaContext,
	opts outputTableOpts,
	list []proto.UserInfoAndStatus,
	mode userListTableMode,
) error {

	showDeviceNames := core.Find(list, func(u proto.UserInfoAndStatus) bool {
		return len(u.Info.Devname) > 0
	})

	uctxToRow := func(_ int, u proto.UserInfoAndStatus) (tableRow, error) {
		ret := userRow{
			active:          u.Info.Active,
			mode:            mode,
			showDeviceNames: showDeviceNames,
		}
		username := string(u.Info.Username.NameUtf8)
		if len(username) == 0 {
			tmp, err := u.Info.Fqu.Uid.StringErr()
			if err != nil {
				return ret, err
			}
			username = "[" + tmp + "]"
		}
		ret.username = username
		hostname, err := u.Info.HostAddr.ProbeHostStringErr()
		if err != nil {
			return ret, err
		}
		if len(hostname) == 0 {
			tmp, err := u.Info.Fqu.HostID.StringErr()
			if err != nil {
				return ret, err
			}
			hostname = "[" + tmp + "]"
		}
		ret.hostname = hostname

		dev := ""

		switch u.Info.KeyGenus {
		case proto.KeyGenus_Yubi:
			if u.Info.YubiInfo != nil {
				x := *u.Info.YubiInfo
				dev = fmt.Sprintf("%s <0x%x/%d>", x.Card.Name, x.Card.Serial, x.Key.Slot)
			} else {
				dev = "YubiKey"
			}
		case proto.KeyGenus_Device:
			dev = "device"
		case proto.KeyGenus_Backup:
			dev = "backup"
		}
		ret.dev = dev

		ret.locked = lockStatusToString(u.LockStatus)
		role, err := u.Info.Role.ShortStringErr()
		if err != nil {
			return ret, err
		}
		ret.role = role
		ret.connected = networkStatusToString(u.NetworkStatus)
		ret.devname = string(u.Info.Devname)
		return ret, nil
	}

	return convertAndOutputRows(m, opts, list, uctxToRow, nil)
}

type deviceRow struct {
	name        string
	typ         proto.DeviceType
	created     time.Time
	serial      int
	role        string
	active      bool
	key         string
	revoked     bool
	showSerial  bool
	showRevoked bool
}

func (d deviceRow) toTableRow() table.Row {
	sActive := ""
	if d.active {
		sActive = "*"
	}
	sTime := d.created.Local().Format("2006-01-02")
	sTyp := deviceTypeToString(d.typ)
	sSerial := fmt.Sprintf("%d", d.serial)
	row := table.Row{sActive, d.name}
	if d.showSerial {
		row = append(row, sSerial)
	}
	row = append(row, sTyp, sTime, d.key)
	if d.showRevoked {
		revoked := ""
		if d.revoked {
			revoked = "❌"
		}
		row = append(row, revoked)
	}
	return row
}

func (d deviceRow) headers() table.Row {
	row := table.Row{
		"Active",
		"Name",
	}
	if d.showSerial {
		row = append(row, "Serial")
	}
	row = append(row,
		"Type",
		"Created",
		"ID",
	)
	if d.showRevoked {
		row = append(row, "Revoked")
	}
	return row
}

func (d deviceRow) lessThan(other tableRow) bool {
	od := other.(deviceRow)
	if d.revoked != od.revoked {
		return od.revoked
	}
	cmp := cicmp(d.name, od.name)
	if cmp != 0 {
		return (cmp < 0)
	}
	return d.serial < od.serial
}

var _ tableRow = deviceRow{}

func outputKeyListTable(m libclient.MetaContext, opts outputTableOpts, lst []lcl.ActiveDeviceInfo) error {

	repeatDevice := core.Find(lst, func(d lcl.ActiveDeviceInfo) bool {
		return !d.Di.Dn.Label.Serial.IsFirst()
	})
	revoked := core.Find(lst, func(d lcl.ActiveDeviceInfo) bool {
		return d.Di.Status == proto.DeviceStatus_REVOKED
	})

	conv := func(_ int, d lcl.ActiveDeviceInfo) (tableRow, error) {
		ret := deviceRow{
			name:        string(d.Di.Dn.Name),
			typ:         d.Di.Dn.Label.DeviceType,
			serial:      int(d.Di.Dn.Label.Serial),
			created:     d.Di.Ctime.Import(),
			active:      d.Active,
			revoked:     d.Di.Status == proto.DeviceStatus_REVOKED,
			showSerial:  repeatDevice,
			showRevoked: revoked,
		}
		role, err := d.Di.Key.DstRole.ShortStringErr()
		if err != nil {
			return ret, err
		}
		ret.role = role
		key, err := d.Di.Key.Member.Id.Entity.StringErr()
		if err != nil {
			return ret, err
		}
		ret.key = key
		return ret, nil
	}
	doSep := func(a, b tableRow) bool {
		if a == nil || b == nil {
			return false
		}
		oa := a.(deviceRow)
		ob := b.(deviceRow)
		return (oa.revoked != ob.revoked)
	}
	return convertAndOutputRows(m, opts, lst, conv, doSep)
}

type teamRosterRow struct {
	member       string
	memberIsTeam bool
	memberID     string
	host         string // "" if local
	hostID       string // "" if local
	srcRole      string
	dstRole      core.RoleKey
	dstRoleStr   string
	gen          int
	addedTime    time.Time
	addedSeqno   int // when added
}

func (t teamRosterRow) toTableRow() table.Row {
	sTime := t.addedTime.Local().Format("2006-01-02")
	sMember := t.member
	if t.memberIsTeam {
		sMember += " (team)"
	}
	sGen := fmt.Sprintf("%d", t.gen)
	return table.Row{
		sMember,
		t.host,
		t.memberID,
		t.hostID,
		t.srcRole,
		t.dstRoleStr,
		sGen,
		sTime,
		t.addedSeqno,
	}
}

func (t teamRosterRow) headers() table.Row {
	return table.Row{
		"Member",
		"Host",
		"Member ID",
		"Host ID",
		"Src Role",
		"Dst Role",
		"PTK Gen",
		"Added (time)",
		"Added (seqno)",
	}
}

func (t teamRosterRow) lessThan(other tableRow) bool {
	ot := other.(teamRosterRow)
	cmp := t.dstRole.Cmp(ot.dstRole)
	// Output the hisghest roles first (owners, admins, etc)
	if cmp > 0 {
		return true
	}
	if cmp < 0 {
		return false
	}
	cmp = cicmp(t.host, ot.host)
	if cmp != 0 {
		return (cmp < 0)
	}
	cmp = cicmp(t.member, ot.member)
	return (cmp <= 0)
}

var _ tableRow = teamRosterRow{}

func outputTeamListTable(m libclient.MetaContext, opts outputTableOpts, roster lcl.TeamRoster) error {

	conv := func(_ int, t lcl.TeamRosterMember) (tableRow, error) {
		isLocal := roster.Fqp.Fqp.Host.Eq(t.Mem.Fqp.Host)
		hostID := "-"
		if !isLocal {
			var err error
			hostID, err = t.Mem.Fqp.Host.StringErr()
			if err != nil {
				return nil, err
			}
		}
		srcRole, err := t.SrcRole.ShortStringErr()
		if err != nil {
			return nil, err
		}
		dstRole, err := t.DstRole.ShortStringErr()
		if err != nil {
			return nil, err
		}
		dstRoleKey, err := core.ImportRole(t.DstRole)
		if err != nil {
			return nil, err
		}
		memId, err := t.Mem.Fqp.Party.EntityID().StringErr()
		if err != nil {
			return nil, err
		}
		ret := teamRosterRow{
			member:       string(t.Mem.Name),
			memberID:     memId,
			memberIsTeam: t.Mem.Fqp.Party.IsTeam(),
			host:         core.Sel(isLocal, "-", string(t.Mem.Host)),
			hostID:       hostID,
			srcRole:      srcRole,
			dstRoleStr:   dstRole,
			dstRole:      *dstRoleKey,
			gen:          int(t.PtkGen),
			addedTime:    t.Added.Time.Import(),
			addedSeqno:   int(t.Added.Seqno),
		}
		return ret, nil
	}

	return convertAndOutputRows(m, opts, roster.Members, conv, nil)
}

type teamInboxRow struct {
	member       string
	memberIsTeam bool
	memberID     string
	host         string // "" if local
	hostID       string // "" if local
	srcRole      string
	rsvp         string
	rsvpTime     time.Time
}

var _ tableRow = teamInboxRow{}

func (t teamInboxRow) lessThan(other tableRow) bool {
	return t.rsvpTime.After(other.(teamInboxRow).rsvpTime)
}

func (t teamInboxRow) toTableRow() table.Row {
	sTime := t.rsvpTime.Local().Format("2006-01-02")
	sMember := t.member
	if t.memberIsTeam {
		sMember += " (team)"
	}
	return table.Row{
		sMember,
		t.host,
		t.memberID,
		t.hostID,
		t.srcRole,
		t.rsvp,
		sTime,
	}
}

func (t teamInboxRow) headers() table.Row {
	return table.Row{
		"Member",
		"Host",
		"Member ID",
		"Host ID",
		"Src Role",
		"RSVP",
		"RSVP (time)",
	}
}

func outputTeamInboxTable(m libclient.MetaContext, opts outputTableOpts, inbox lcl.TeamInbox) error {
	var myHostID proto.HostID
	au := m.G().ActiveUser()
	if au != nil {
		myHostID = au.HostID()
	}
	conv := func(_ int, t lcl.TeamInboxRow) (tableRow, error) {
		isLocal := t.Nfqp.Fqp.Host.Eq(myHostID)
		hostID := "-"
		if !isLocal {
			var err error
			hostID, err = t.Nfqp.Fqp.Host.StringErr()
			if err != nil {
				return nil, err
			}
		}
		srcRole, err := t.SrcRole.ShortStringErr()
		if err != nil {
			return nil, err
		}
		rsvp, err := t.Tok.StringErr()
		if err != nil {
			return nil, err
		}
		memId, err := t.Nfqp.Fqp.Party.EntityID().StringErr()
		if err != nil {
			return nil, err
		}
		ret := teamInboxRow{
			member:       string(t.Nfqp.Name),
			memberIsTeam: t.Nfqp.Fqp.Party.IsTeam(),
			memberID:     memId,
			host:         core.Sel(isLocal, "-", string(t.Nfqp.Host)),
			hostID:       hostID,
			srcRole:      srcRole,
			rsvp:         rsvp,
			rsvpTime:     t.Time.Import(),
		}
		return ret, nil
	}
	return convertAndOutputRows(m, opts, inbox.Rows, conv, nil)
}

type teamMembershipsRow struct {
	idx     int
	srcRole string
	team    string
	dstRole string
	via     string
	tir     string
}

func (t teamMembershipsRow) toTableRow() table.Row {
	return table.Row{t.srcRole, t.team, t.dstRole, t.via, t.tir}
}

func (t teamMembershipsRow) headers() table.Row {
	return table.Row{"Src Role", "Team", "Dst Role", "Via", "Index Range"}
}

func (t teamMembershipsRow) lessThan(other tableRow) bool {
	return t.idx < other.(teamMembershipsRow).idx
}

var _ tableRow = teamMembershipsRow{}

func outputTeamListMembershipsTable(
	m libclient.MetaContext,
	opts outputTableOpts,
	lst lcl.ListMembershipsRes,
) error {

	conv := func(i int, t lcl.TeamMembership) (tableRow, error) {

		srcRole, err := t.SrcRole.ShortStringErr()
		if err != nil {
			return nil, err
		}
		dstRole, err := t.DstRole.ShortStringErr()
		if err != nil {
			return nil, err
		}

		teamName := func(t lcl.NamedFQParty) string {
			if lst.HomeHost.Eq(t.Fqp.Host) {
				return string(t.Name)
			}
			return fmt.Sprintf("%s@%s", string(t.Name), t.Host)
		}
		rr := core.RationalRange{
			RationalRange: t.Tir,
		}
		ret := teamMembershipsRow{
			idx:     i,
			srcRole: srcRole,
			dstRole: dstRole,
			team:    teamName(t.Team),
			tir:     rr.String(),
		}
		if t.Via != nil {
			ret.via = teamName(*t.Via)
		}
		return ret, nil
	}

	return convertAndOutputRows(m, opts, lst.Teams, conv, nil)
}
