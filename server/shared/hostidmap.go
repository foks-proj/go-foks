// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ShortCache[K comparable, V any] struct {
	sync.Mutex
	m map[K](struct {
		v V
		t time.Time
	})
	dur time.Duration
}

func NewShortCache[K comparable, V any](dur time.Duration) *ShortCache[K, V] {
	return &ShortCache[K, V]{m: make(map[K](struct {
		v V
		t time.Time
	})), dur: dur}
}

func (s *ShortCache[K, V]) Get(m MetaContext, k K) (V, bool) {
	s.Lock()
	defer s.Unlock()
	var blank V
	tup, ok := s.m[k]
	if !ok {
		return blank, false
	}
	now := m.Now()
	if now.Sub(tup.t) > s.dur {
		delete(s.m, k)
		return blank, false
	}
	return tup.v, true
}

func (s *ShortCache[K, V]) Put(m MetaContext, k K, v V) {
	s.Lock()
	defer s.Unlock()
	s.m[k] = struct {
		v V
		t time.Time
	}{v: v, t: m.Now()}
}

type HostIDMap struct {
	sync.Mutex
	m2shid map[core.ShortHostID]*core.HostID
	m2hid  map[proto.HostID]*core.HostID
	m2vid  map[proto.VHostID]*core.HostID

	// Don't cache hostnames forever, since they do sometimes change.
	hn2Fwd *ShortCache[core.ShortHostID, proto.Hostname]
	hn2Rev *ShortCache[proto.Hostname, core.ShortHostID]

	// Aliases are used when looking up HostIDs during TLS handshakes (via SNI).
	// They are typically hidden from the user, but visible in Zones. Useful
	// for server deployments where different service processes run on different
	// machines.
	aliases *ShortCache[proto.Hostname, core.ShortHostID]

	sso *ShortCache[core.ShortHostID, proto.SSOProtocolType]

	// Filter machinery
	all        map[core.ShortHostID]struct{}
	misses     map[core.ShortHostID]struct{}
	lastLookup time.Time

	configMu sync.Mutex
	config   map[core.ShortHostID]proto.HostConfig
}

func (h *HostIDMap) ins(i *core.HostID) {
	h.Lock()
	defer h.Unlock()
	h.m2hid[i.Id] = i
	h.m2shid[i.Short] = i
	h.all[i.Short] = struct{}{}
	if !i.VId.IsZero() {
		h.m2vid[i.VId] = i
	}
}

func NewHostIDMap() *HostIDMap {
	return &HostIDMap{
		all:    make(map[core.ShortHostID]struct{}),
		misses: make(map[core.ShortHostID]struct{}),
		config: make(map[core.ShortHostID]proto.HostConfig),

		m2hid:  make(map[proto.HostID]*core.HostID),
		m2shid: make(map[core.ShortHostID]*core.HostID),
		m2vid:  make(map[proto.VHostID]*core.HostID),

		aliases: NewShortCache[proto.Hostname, core.ShortHostID](15 * time.Second),
		hn2Fwd:  NewShortCache[core.ShortHostID, proto.Hostname](15 * time.Second),
		hn2Rev:  NewShortCache[proto.Hostname, core.ShortHostID](15 * time.Second),
		sso:     NewShortCache[core.ShortHostID, proto.SSOProtocolType](15 * time.Second),
	}
}

// check that the given hostID is either the main hostID for this server
// (as seen in m.G()) or a virtual host on top of it. We shouldn't be
// doing lookups on other hosts that might be resident on this DB.
func (h *HostIDMap) checkHostID(m MetaContext, db *pgxpool.Conn, id core.ShortHostID) error {
	mainId := m.G().ShortHostID()
	if id == mainId {
		return nil
	}
	var found bool
	h.Lock()
	_, found = h.all[id]
	h.Unlock()
	if found {
		return nil
	}

	var unit int
	err := db.QueryRow(
		m.Ctx(),
		`SELECT 1 FROM hosts WHERE short_host_id=$1 AND root_short_host_id=$2`,
		id.ExportToDB(),
		mainId.ExportToDB(),
	).Scan(&unit)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && unit != 1) {
		return core.NotFoundError("vhost")
	} else if err != nil {
		return err
	}

	h.Lock()
	h.all[id] = struct{}{}
	h.Unlock()

	return nil
}

func (h *HostIDMap) dbLookup(
	m MetaContext,
	field string,
	val any,
) (
	*core.HostID,
	error,
) {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	var shidRaw int
	var hidRaw, vidRaw []byte
	err = db.QueryRow(
		m.Ctx(),
		`SELECT short_host_id, host_id, vhost_id FROM hosts WHERE `+field+`=$1 AND root_short_host_id=$2`,
		val,
		m.G().ShortHostID().ExportToDB(),
	).Scan(&shidRaw, &hidRaw, &vidRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.HostIDNotFoundError{}
	}
	if err != nil {
		return nil, err
	}
	ret := core.HostID{
		Short: core.ShortHostID(shidRaw),
	}
	err = ret.Id.ImportFromBytes(hidRaw)
	if err != nil {
		return nil, err
	}
	var vhid proto.VHostID
	err = vhid.ImportFromDB(vidRaw)
	if err != nil {
		return nil, err
	}
	ret.VId = vhid

	h.ins(&ret)

	return &ret, nil
}

func (h *HostIDMap) LookupByVHostID(m MetaContext, vhid proto.VHostID) (*core.HostID, error) {
	h.Lock()
	v, ok := h.m2vid[vhid]
	h.Unlock()
	if ok {
		return v, nil
	}
	ret, err := h.dbLookup(m, "vhost_id", vhid.ExportToDB())
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (h *HostIDMap) LookupByShortID(m MetaContext, shid core.ShortHostID) (*core.HostID, error) {
	h.Lock()
	v, ok := h.m2shid[shid]
	h.Unlock()
	if ok {
		return v, nil
	}
	ret, err := h.dbLookup(m, "short_host_id", shid.ExportToDB())
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (h *HostIDMap) LookupByHostID(m MetaContext, hid proto.HostID) (*core.HostID, error) {
	h.Lock()
	v, ok := h.m2hid[hid]
	h.Unlock()
	if ok {
		return v, nil
	}
	ret, err := h.dbLookup(m, "host_id", hid.ExportToDB())
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (h *HostIDMap) LookupByAlias(m MetaContext, hn proto.Hostname) (*core.HostID, error) {
	err := hn.AssertNoPort()
	if err != nil {
		return nil, err
	}
	hn = hn.Normalize()

	h.Lock()
	shid, ok := h.aliases.Get(m, hn)
	h.Unlock()
	if ok {
		return h.LookupByShortID(m, shid)
	}

	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	var i int
	err = db.QueryRow(
		m.Ctx(),
		`SELECT short_host_id FROM server_aliases WHERE root_short_host_id=$1 AND alias=$2`,
		m.G().ShortHostID().ExportToDB(),
		hn.String(),
	).Scan(&i)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.HostIDNotFoundError{}
	} else if err != nil {
		return nil, err
	}
	shid = core.ShortHostID(i)
	h.Lock()
	h.aliases.Put(m, hn, shid)
	h.Unlock()

	return h.LookupByShortID(m, shid)
}

type HostnameLookupFallbackBehavior int

const (
	HostnameLookupFallbackNone    HostnameLookupFallbackBehavior = 0
	HostnameLookupFallbackDefault HostnameLookupFallbackBehavior = 1
)

func (h *HostIDMap) LookupByHostname(m MetaContext, hn proto.Hostname) (*core.HostID, error) {
	return h.LookupByHostnameWithFallbackBehavior(m, hn, HostnameLookupFallbackDefault)
}

func (h *HostIDMap) LookupByHostnameWithFallbackBehavior(
	m MetaContext,
	hn proto.Hostname,
	fallbackBehavior HostnameLookupFallbackBehavior,
) (
	*core.HostID,
	error,
) {
	err := hn.AssertNoPort()
	if err != nil {
		return nil, err
	}
	hn = hn.Normalize()

	h.Lock()
	shid, ok := h.hn2Rev.Get(m, hn)
	h.Unlock()
	if ok {
		return h.LookupByShortID(m, shid)
	}

	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	var i int
	err = db.QueryRow(
		m.Ctx(),
		`SELECT short_host_id FROM hostnames WHERE hostname=$1 AND cancel_id=$2`,
		hn,
		proto.NilCancelID(),
	).Scan(&i)

	// If not found, the default to the primary hostname
	if errors.Is(err, pgx.ErrNoRows) {
		if fallbackBehavior == HostnameLookupFallbackDefault {
			shid = m.G().ShortHostID()
		} else {
			return nil, core.HostIDNotFoundError{}
		}
	} else if err != nil {
		return nil, err
	} else {
		shid = core.ShortHostID(i)
	}

	h.Lock()
	h.hn2Fwd.Put(m, shid, hn)
	h.hn2Rev.Put(m, hn, shid)
	h.Unlock()

	return h.LookupByShortID(m, shid)
}

func (h *HostIDMap) Config(m MetaContext, shid core.ShortHostID) (*proto.HostConfig, error) {

	h.configMu.Lock()
	defer h.configMu.Unlock()
	ret, ok := h.config[shid]
	if ok {
		return &ret, nil
	}
	config, err := SelectHostConfig(m, shid)
	if err != nil {
		return nil, err
	}
	h.config[shid] = config
	return &config, nil
}

func (h *HostIDMap) SSO(
	m MetaContext,
	shid core.ShortHostID,
) (
	proto.SSOProtocolType,
	error,
) {
	none := proto.SSOProtocolType_None
	if res, ok := h.sso.Get(m, shid); ok {
		return res, nil
	}
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return none, err
	}
	defer db.Release()
	err = h.checkHostID(m, db, shid)
	if err != nil {
		return none, err
	}
	var tmp string
	err = db.QueryRow(
		m.Ctx(),
		`SELECT active FROM sso_config WHERE short_host_id=$1`,
		shid,
	).Scan(&tmp)
	if errors.Is(err, pgx.ErrNoRows) {
		return none, nil
	}
	if err != nil {
		return none, err
	}
	var typ proto.SSOProtocolType
	err = typ.ImportFromDB(tmp)
	if err != nil {
		return none, err
	}
	h.sso.Put(m, shid, typ)
	return typ, nil
}

func (h *HostIDMap) ClearConfig(m MetaContext, shid core.ShortHostID) {
	h.configMu.Lock()
	defer h.configMu.Unlock()
	delete(h.config, shid)
}

func (h *HostIDMap) Hostname(m MetaContext, shid core.ShortHostID) (proto.Hostname, error) {

	h.Lock()
	hn, ok := h.hn2Fwd.Get(m, shid)
	h.Unlock()

	if ok {
		return hn, nil
	}

	var zed proto.Hostname
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return zed, err
	}
	defer db.Release()
	err = h.checkHostID(m, db, shid)
	if err != nil {
		return zed, err
	}

	var raw string
	err = db.QueryRow(
		m.Ctx(),
		`SELECT hostname 
		 FROM hostnames 
		 WHERE short_host_id=$1
		   AND cancel_id=$2`,
		shid,
		proto.NilCancelID(),
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return zed, core.HostIDNotFoundError{}
	}
	if err != nil {
		return zed, err
	}
	ret := proto.Hostname(raw).Normalize()

	h.Lock()
	h.hn2Fwd.Put(m, shid, ret)
	h.hn2Rev.Put(m, ret, shid)
	h.Unlock()

	return ret, nil
}

// Given a list of ShortHostIDs, filter down to the ones that this host (and its virtual hosts)
// are aware of.  Use cached-in-memory lookups but revert back to a table scan if we miss at all.
// But the table scan is very greedy, so we should be primed very quickly. Also cache misses,
// since we might be spamming the same virtual host ID over and over again if not.
func (h *HostIDMap) Filter(m MetaContext, hostIDs []core.ShortHostID) ([]core.ShortHostID, error) {

	var res []core.ShortHostID
	var needDbLookup bool
	var misses []core.ShortHostID
	var ll time.Time

	mainId := m.G().ShortHostID()

	pass1 := func() {
		h.Lock()
		defer h.Unlock()
		ll = h.lastLookup

		// Initialize the list with the main server.
		if len(h.all) == 0 {
			h.all[mainId] = struct{}{}
		}

		for _, v := range hostIDs {
			if _, ok := h.all[v]; ok {
				res = append(res, v)
			} else if _, ok := h.m2shid[v]; ok {
				res = append(res, v)
				h.all[v] = struct{}{}
			} else {
				misses = append(misses, v)
				if _, ok := h.misses[v]; !ok {
					needDbLookup = true
				}
			}
		}
	}

	pass1()

	if !needDbLookup {
		return res, nil
	}

	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	rows, err := db.Query(
		m.Ctx(),
		`SELECT short_host_id, ctime FROM hosts WHERE root_short_host_id=$1 AND ctime >= $2`,
		mainId.ExportToDB(),
		ll,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var newShortIds []core.ShortHostID

	for rows.Next() {
		var i int
		var t time.Time
		err = rows.Scan(&i, &t)
		if err != nil {
			return nil, err
		}
		shid := core.ShortHostID(i)
		if t.After(ll) {
			ll = t
		}
		newShortIds = append(newShortIds, shid)
	}

	pass2 := func() {
		h.Lock()
		defer h.Unlock()

		for _, shid := range newShortIds {
			h.all[shid] = struct{}{}
		}

		for _, shid := range misses {
			if _, ok := h.all[shid]; ok {
				res = append(res, shid)
			} else {
				h.misses[shid] = struct{}{}
			}
		}
		h.lastLookup = ll
	}

	pass2()

	return res, nil
}
