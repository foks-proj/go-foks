// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"slices"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ViewershipMode struct {
	proto.ViewershipMode
	Desc string
}

var ValidUserViewershipModes = []ViewershipMode{
	{proto.ViewershipMode_Open, "open"},
	{proto.ViewershipMode_Closed, "closed"},
}

type VHostUsage struct {
	Users uint64
	Disk  proto.Size
}

func (v VHostUsage) IsEmpty() bool {
	return v.Users == 0 && v.Disk == 0
}

type VHostRowDetails struct {
	MultiUseInvites   []shared.MultiUseInviteCode
	Config            proto.HostConfig
	SSO               *proto.SSOConfig
	OAuth2CallbackURL proto.URLString // this is known regardless of SSO configuration
}

func (d *VHostRowDetails) HasOAuth2SSO() bool {
	return d != nil && d.SSO != nil && d.SSO.Active == proto.SSOProtocolType_Oauth2 && d.SSO.Oauth2 != nil
}

func (d *VHostRowDetails) OAuth2SSOConfigURL() string {
	if !d.HasOAuth2SSO() {
		return ""
	}
	return d.SSO.Oauth2.ConfigURI.String()
}

func (d *VHostRowDetails) OAuth2SSOClientID() string {
	if !d.HasOAuth2SSO() {
		return ""
	}
	return d.SSO.Oauth2.ClientID.String()
}

func (d *VHostRowDetails) OAuth2SSOClientSecret() string {
	if !d.HasOAuth2SSO() {
		return ""
	}
	return d.SSO.Oauth2.ClientSecret.String()
}

func (d *VHostRowDetails) OAuth2SSORedirectURI() proto.URLString {
	if !d.HasOAuth2SSO() {
		return ""
	}
	return d.SSO.Oauth2.RedirectURI
}

type VHostRow struct {
	Id            core.HostID // might be =0 if not yet complete
	VHostID       proto.VHostID
	Name          proto.Hostname
	Usage         VHostUsage
	IsClaimed     bool
	IsClaimedByMe bool
	IsCanned      bool
	Stem          proto.Hostname // If a vanity host, the CNAME stem
	Stage         proto.HostBuildStage
	Details       *VHostRowDetails
}

func (r *VHostRow) LoadDetails(m shared.MetaContext) error {
	var details VHostRowDetails
	var err error
	m = m.WithHostID(&r.Id)
	details.MultiUseInvites, err = shared.LoadAllMultiuseInviteCodes(m)
	if err != nil {
		return err
	}
	r.Details = &details
	cfg, err := m.G().HostIDMap().Config(m, r.Id.Short)
	if err != nil {
		return err
	}
	r.Details.Config = *cfg

	// If host ID is 0 (i.e., host isn't constructed yet), no need to
	// load SSO config.
	if m.HostID().IsZero() {
		return nil
	}

	sso, err := shared.LoadSSOConfig(m, nil)
	if err != nil {
		return err
	}
	r.Details.SSO = sso
	r.Details.OAuth2CallbackURL, err = shared.OAuth2CallbackURL(m)
	if err != nil {
		return err
	}
	return nil
}

func (r *VHostRowDetails) FindMultiUseInviteCode(c rem.MultiUseInviteCode) *shared.MultiUseInviteCode {
	for _, i := range r.MultiUseInvites {
		if i.Code == c {
			return &i
		}
	}
	return nil
}

type VHostData struct {
	myRows        []VHostRow
	theirRows     []VHostRow
	CannedDomains []proto.Hostname
}

func (v *VHostData) FindVHostRow(id proto.VHostID) *VHostRow {
	for _, r := range v.myRows {
		if r.VHostID == id {
			return &r
		}
	}
	return nil
}

func (v *VHostData) Mine() []VHostRow {
	if v == nil {
		return nil
	}
	return v.myRows
}

func (v *VHostData) Theirs() []VHostRow {
	if v == nil {
		return nil
	}
	return v.theirRows
}

func (v *VHostData) HasTheirs() bool {
	if v == nil {
		return false
	}
	return len(v.theirRows) > 0
}

func (v *VHostData) TotalDiskUsage() proto.Size {
	if v == nil {
		return 0
	}
	var ret proto.Size
	for _, r := range v.myRows {
		ret += r.Usage.Disk
	}
	return ret
}

func (v *VHostData) TotalUsers() uint64 {
	if v == nil {
		return 0
	}
	var ret uint64
	for _, r := range v.myRows {
		ret += r.Usage.Users
	}
	return ret
}

func (v *VHostData) NumHosts() int {
	if v == nil {
		return 0
	}
	return len(v.myRows)
}

func (v *vhostDataLoader) vhostRecord(id proto.VHostID) *VHostRow {
	ret, ok := v.rawMap[id]
	if ok {
		return ret
	}
	ret = &VHostRow{
		VHostID: id,
	}
	v.rawMap[id] = ret
	return ret
}

func (v *vhostDataLoader) loadMine(
	m shared.MetaContext,
) error {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	rows, err := db.Query(
		m.Ctx(),
		`SELECT vhost_id
		FROM vhost_quota_masters
		WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var vhidRaw []byte
		err = rows.Scan(&vhidRaw)
		if err != nil {
			return err
		}
		var vhid proto.VHostID
		err = vhid.ImportFromDB(vhidRaw)
		if err != nil {
			return err
		}
		vhr := v.vhostRecord(vhid)
		vhr.IsClaimedByMe = true
		vhr.IsClaimed = true
	}
	return nil
}

func (v *vhostDataLoader) loadSeatUsage(
	m shared.MetaContext,
) error {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	rows, err := db.Query(
		m.Ctx(),
		`SELECT COUNT(*), short_host_id
		FROM users
		WHERE short_host_id = ANY($1)
		GROUP BY short_host_id`,
		v.all,
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	himp := m.G().HostIDMap()
	for rows.Next() {
		var count uint64
		var shidRaw int
		err = rows.Scan(&count, &shidRaw)
		if err != nil {
			return err
		}
		shid := core.ShortHostID(shidRaw)
		chid, err := himp.LookupByShortID(m, shid)
		if err != nil {
			return err
		}
		v.vhostRecord(chid.VId).Usage.Users = count
	}
	return nil
}

func (v *vhostDataLoader) loadDiskUsages(
	m shared.MetaContext,
) error {
	doShard := func(db *pgxpool.Conn) error {
		rows, err := db.Query(
			m.Ctx(),
			`SELECT short_host_id, 
			    COALESCE(SUM(sum_small+sum_large),0) 
			FROM usage_vhost
			WHERE short_host_id = ANY($1)
			GROUP BY short_host_id`,
			v.all,
		)
		if err != nil {
			return err
		}
		himp := m.G().HostIDMap()
		defer rows.Close()
		for rows.Next() {
			var shidRaw int
			var size int64
			err = rows.Scan(&shidRaw, &size)
			if err != nil {
				return err
			}
			shid := core.ShortHostID(shidRaw)
			chid, err := himp.LookupByShortID(m, shid)
			if err != nil {
				return err
			}
			v.vhostRecord(chid.VId).Usage.Disk += proto.Size(size)
		}
		return nil
	}
	err := m.ForAllShards(doShard)
	if err != nil {
		return err
	}
	return nil
}

func (v *vhostDataLoader) loadRows(
	m shared.MetaContext,
) error {
	hidmap := m.G().HostIDMap()
	for key, val := range v.rawMap {
		chid, err := hidmap.LookupByVHostID(m, key)
		if err != nil || chid == nil {
			continue
		}
		val.Id = *chid
		hn, err := hidmap.Hostname(m, chid.Short)
		if err != nil {
			return err
		}
		val.Name = hn
	}
	return nil
}

type vhostDataLoader struct {
	ret      *VHostData
	all      []int
	usageMap map[core.ShortHostID]*VHostUsage
	rawMap   map[proto.VHostID]*VHostRow
}

func LoadVHostData(
	m shared.MetaContext,
) (*VHostData, error) {
	loader := vhostDataLoader{
		rawMap: make(map[proto.VHostID]*VHostRow),
	}

	err := loader.run(m)
	if err != nil {
		return nil, err
	}
	return loader.ret, nil
}

func (v *vhostDataLoader) loadBuilds(
	m shared.MetaContext,
) error {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	rows, err := db.Query(
		m.Ctx(),
		`SELECT stem, vanity_host, stage, vhost_id, is_canned
		 FROM vanity_host_build
		 WHERE short_host_id = $1 AND uid = $2 AND stage != $3`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
		proto.HostBuildStage_Aborted.String(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var stem, name string
		var stageRaw string
		var vhidRaw []byte
		var isCanned bool
		err = rows.Scan(&stem, &name, &stageRaw, &vhidRaw, &isCanned)
		if err != nil {
			return err
		}
		var stage proto.HostBuildStage
		err = stage.ImportFromString(stageRaw)
		if err != nil {
			return err
		}
		var vhid proto.VHostID
		err = vhid.ImportFromDB(vhidRaw)
		if err != nil {
			return err
		}
		vhr := v.vhostRecord(vhid)
		vhr.Stem = proto.Hostname(stem)
		vhr.Stage = stage
		vhr.Name = proto.Hostname(name)
		vhr.IsCanned = isCanned
	}
	return nil
}

func (v *vhostDataLoader) loadAllVHosts(
	m shared.MetaContext,
) error {
	db, err := m.Db(shared.DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()

	rows, err := db.Query(
		m.Ctx(),
		`SELECT vhost_id FROM vhost_admins
		WHERE short_host_id=$1 AND uid=$2`,
		m.ShortHostID().ExportToDB(),
		m.UID().ExportToDB(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var vhidRaw []byte
		err = rows.Scan(&vhidRaw)
		if err != nil {
			return err
		}
		var vhid proto.VHostID
		err = vhid.ImportFromDB(vhidRaw)
		if err != nil {
			return err
		}
		// Post an empty record
		v.vhostRecord(vhid)

		chid, err := m.G().HostIDMap().LookupByVHostID(m, vhid)
		if err != nil {
			return err
		}
		v.all = append(v.all, chid.Short.ExportToDB())
	}
	return nil
}

func (v *vhostDataLoader) loadCannedDomains(
	m shared.MetaContext,
) error {
	vcfg, err := m.G().Config().VHostsConfig(m.Ctx())
	if err != nil {
		return err
	}
	v.ret.CannedDomains = core.Map(
		vcfg.CannedDomains(),
		func(h shared.DNSZoner) proto.Hostname { return h.Domain() },
	)
	return nil
}

func (v *vhostDataLoader) makeRet(
	m shared.MetaContext,
) error {
	rows := core.Map(core.Values(v.rawMap), func(r *VHostRow) VHostRow { return *r })
	slices.SortFunc(rows, func(a, b VHostRow) int { return a.Name.Cmp(b.Name) })
	v.ret.myRows = rows
	return nil
}

func (v *vhostDataLoader) run(m shared.MetaContext) error {

	err := v.loadAllVHosts(m)
	if err != nil {
		return err
	}

	v.ret = &VHostData{}

	err = v.loadCannedDomains(m)
	if err != nil {
		return err
	}

	err = v.loadMine(m)
	if err != nil {
		return err
	}

	v.usageMap = make(map[core.ShortHostID]*VHostUsage)

	err = v.loadSeatUsage(m)
	if err != nil {
		return err
	}
	err = v.loadDiskUsages(m)
	if err != nil {
		return err
	}
	err = v.loadBuilds(m)
	if err != nil {
		return err
	}
	err = v.loadRows(m)
	if err != nil {
		return err
	}

	err = v.makeRet(m)
	if err != nil {
		return err
	}

	return nil
}

type VHostAddArgs struct {
	IsBYOD bool // can toggle on or off
	Err    *VHostSetupError
}

func AbortVanityBuild(
	m shared.MetaContext,
	user *User,
	vhr *VHostRow,
) error {
	return shared.AbortVanityBuild(m, m.UID(), vhr.VHostID)
}

func RandomMultiUseInviteCode() (*rem.MultiUseInviteCode, error) {
	ic, err := core.RandomBase36String(9)
	if err != nil {
		return nil, err
	}
	ret := rem.MultiUseInviteCode(ic)
	return &ret, nil
}

func CheckVanityHost(
	m shared.MetaContext,
	user *User,
	vhr *VHostRow,
) error {
	ic, err := RandomMultiUseInviteCode()
	if err != nil {
		return err
	}
	met := proto.Metering{
		PerVHostDisk: true,
		Users:        true,
	}
	if vhr.IsCanned {
		cc := shared.CannedMinder{
			VHostID:    &vhr.VHostID,
			InviteCode: *ic,
			Metering:   met,
		}
		err = cc.Recheck(m)
	} else {
		vm := shared.VanityMinder{
			VHostID:    &vhr.VHostID,
			InviteCode: *ic,
			Metering:   met,
		}
		err = vm.Stage2(m)
	}
	if err != nil {
		return err
	}
	return nil
}

type VHostCheckError struct {
	Err error
}

func (e VHostCheckError) Error() string {
	return e.Err.Error()
}

type VHostSetupError struct {
	Err error
}

func (e VHostSetupError) Error() string {
	return e.Err.Error()
}

func MakeCannedVHost(
	m shared.MetaContext,
	host proto.Hostname,
	domain proto.Hostname,
) error {
	ic, err := RandomMultiUseInviteCode()
	if err != nil {
		return err
	}
	cm := shared.CannedMinder{
		Hostname:     host,
		CannedDomain: domain,
		InviteCode:   *ic,
		Metering: proto.Metering{
			PerVHostDisk: true,
			Users:        true,
		},
	}
	m = m.WithLogTag("canned")

	err = cm.Run(m)
	if err == nil {
		return nil
	}

	switch err.(type) {
	case core.NoActivePlanError,
		core.OverQuotaError,
		core.HostInUseError:
		m.Infow("MakeCannedVHost", "action", "early-exit", "err", err)
		return err
	default:
		m.Warnw("MakeCannedVHost", "err", err)
	}

	settings, err := m.G().Config().Settings(m.Ctx())
	if err != nil {
		return err
	}
	for i := 0; i < 10; i++ {
		if !settings.Testing {
			m.Warnw("MakeCannedVHost", "sleep", 3)
			time.Sleep(3 * time.Second)
		}
		err = cm.Recheck(m)
		if err == nil {
			return nil
		}
		m.Warnw("MakeCannedVHost", "err", err, "attempt", i)
	}

	return err
}
