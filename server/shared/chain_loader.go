// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ChainLoader struct {
	eid   proto.EntityID
	typ   proto.ChainType
	db    *pgxpool.Conn
	start proto.Seqno
}

func NewChainLoader(eid proto.EntityID, typ proto.ChainType, start proto.Seqno, db *pgxpool.Conn) *ChainLoader {
	return &ChainLoader{
		eid:   eid,
		typ:   typ,
		start: start,
		db:    db,
	}
}

func (c *ChainLoader) LoadHEPKs(
	m MetaContext,
	links []proto.LinkOuter,
) (
	*proto.HEPKSet,
	error,
) {
	var empty proto.HEPKSet
	if len(links) == 0 {
		return &empty, nil
	}
	fps, err := collectHEPKFingerprints(links)
	if err != nil {
		return nil, err
	}
	if len(fps) == 0 {
		return &empty, nil
	}
	gepFPs := make([][]byte, len(fps))
	for i, f := range fps {
		f := f
		gepFPs[i] = f.ExportToDB()
	}

	rows, err := c.db.Query(
		m.Ctx(),
		`SELECT hepk_fp, hepk FROM hepks
		 WHERE short_host_id=$1 AND hepk_fp = ANY($2)`,
		m.ShortHostID().ExportToDB(),
		gepFPs,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.BadServerDataError("no hepk found for links")
	}
	if err != nil {
		return nil, err
	}
	ret := proto.HEPKSet{
		V: make([]proto.HEPK, 0, len(fps)),
	}
	defer rows.Close()
	for rows.Next() {
		var fpRaw []byte
		var hepkRaw []byte
		err = rows.Scan(&fpRaw, &hepkRaw)
		if err != nil {
			return nil, err
		}
		var fp proto.HEPKFingerprint
		err = fp.ImportFromDB(fpRaw)
		if err != nil {
			return nil, err
		}
		var hepk proto.HEPK
		err = core.DecodeFromBytes(&hepk, hepkRaw)
		if err != nil {
			return nil, err
		}
		fpComputed, err := core.HEPK(&hepk).Fingerprint()
		if err != nil {
			return nil, err
		}
		if !fpComputed.Eq(&fp) {
			return nil, core.BadServerDataError("HEPK fingerprint mismatch")
		}
		ret.V = append(ret.V, hepk)
	}
	if len(ret.V) != len(fps) {
		return nil, core.BadServerDataError("missing HEPKs")
	}
	return &ret, nil
}

func (c *ChainLoader) LoadMerkle(
	m MetaContext,
	keys []proto.MerkleTreeRFOutput,
) (
	*proto.MerklePathsCompressed,
	error,
) {
	marg := rem.MerkleMLookupArg{
		HostID: m.HostID().IDp(),
		Keys:   keys,
		Signed: true,
	}

	cli, err := m.G().MerkleCli(m.Ctx())
	if err != nil {
		return nil, err
	}

	res, err := cli.MLookup(m.Ctx(), marg)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c *ChainLoader) LoadTreeLocations(
	m MetaContext,
) (
	map[int]proto.TreeLocation,
	[]proto.TreeLocation,
	error,
) {
	rMap := make(map[int]proto.TreeLocation)
	var rList []proto.TreeLocation

	rows, err := c.db.Query(
		m.Ctx(),
		`SELECT loc,seqno FROM tree_locations
	      WHERE short_host_id=$1
		  AND chain_type=$2
		  AND entity_id=$3
		  AND seqno >= $4
		  ORDER BY seqno ASC`,
		m.ShortHostID().ExportToDB(),
		int(c.typ),
		c.eid.ExportToDB(),
		int(c.start),
	)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var loc []byte
		var seqno int64
		err = rows.Scan(&loc, &seqno)
		if err != nil {
			return nil, nil, err
		}
		var treeLoc proto.TreeLocation
		err = treeLoc.ImportFromBytes(loc)
		if err != nil {
			return nil, nil, err
		}
		rList = append(rList, treeLoc)
		rMap[int(seqno)] = treeLoc
	}

	if c.start.IsEldest() && c.typ.IsSubchain() {
		loc, err := lookupComputeZeroethTreeLocation(m, c.db, c.typ, c.eid)
		if err != nil {
			return nil, nil, err
		}
		rMap[int(proto.ChainEldestSeqno)] = loc
	}

	return rMap, rList, nil
}

func (c *ChainLoader) LoadChain(
	m MetaContext,
) (
	[]proto.LinkOuter,
	error,
) {
	var ret []proto.LinkOuter

	q := `SELECT body, seqno
	      FROM links
		  WHERE short_host_id=$1 AND chain_type=$2 AND entity_id=$3 AND seqno >= $4
		  ORDER BY seqno ASC`
	args := []any{m.ShortHostID().ExportToDB(), c.typ, c.eid.ExportToDB(), c.start}
	rows, err := c.db.Query(m.Ctx(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var body []byte
		var seqno int64

		err = rows.Scan(&body, &seqno)
		if err != nil {
			return nil, err
		}

		var link proto.LinkOuter
		err = core.DecodeFromBytes(&link, body)
		if err != nil {
			return nil, err
		}
		ret = append(ret, link)
	}
	return ret, nil
}

func (c *ChainLoader) MakeMerkleKeys(
	m MetaContext,
	lmap map[int]proto.TreeLocation,
	links []proto.LinkOuter,
) (
	[]proto.MerkleTreeRFOutput,
	error,
) {
	var ret []proto.MerkleTreeRFOutput
	start := int(c.start)

	// Go one past the end to prove absense of a leaf
	end := start + len(links) + 1

	for i := start; i < end; i++ {

		inp := proto.MerkleTreeRFInput{
			Seqno:  proto.Seqno(i),
			Entity: c.eid,
			Ct:     c.typ,
		}
		var key proto.MerkleTreeRFOutput

		if loc, found := lmap[i]; found {
			inp.Location = &loc
		}

		err := merkle.KeyHash(&key, inp)
		if err != nil {
			return nil, err
		}

		var locString string
		if inp.Location != nil {
			locString = core.B62Encode(inp.Location[:])
		}
		m.Infow("userLoader::uidMerkleKeys", "key", key, "id", inp.Entity, "seqno", inp.Seqno, "loc", locString)
		ret = append(ret, key)
	}
	return ret, nil
}

func (c *ChainLoader) LoadSubchainSeed(
	m MetaContext,
) (
	*proto.TreeLocation,
	error,
) {
	var seed []byte
	err := c.db.QueryRow(
		m.Ctx(),
		`SELECT seed FROM subchain_tree_location_seeds 
		 WHERE short_host_id=$1 AND entity_id=$2`,
		m.ShortHostID().ExportToDB(),
		c.eid.ExportToDB(),
	).Scan(&seed)
	if err != nil {
		return nil, err
	}
	var ret proto.TreeLocation
	err = ret.ImportFromBytes(seed)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (c *ChainLoader) LoadName(
	m MetaContext,
	eid proto.PartyID,
) (
	*proto.NameAndSeqnoBundle,
	error,
) {
	var raw, raw8 string
	var seqno int

	var tab, col string
	if eid.IsUser() {
		tab = "users"
		col = "uid"
	} else {
		tab = "teams"
		col = "team_id"
	}

	err := c.db.QueryRow(m.Ctx(),
		`SELECT name_utf8, name_ascii, reuse_id
		 FROM names
		 JOIN `+tab+` USING(short_host_id, name_ascii)
		 WHERE short_host_id=$1
		 AND `+col+`=$2
		 AND state='in_use'`,
		m.ShortHostID().ExportToDB(),
		eid.ExportToDB(),
	).Scan(&raw8, &raw, &seqno)
	if err == pgx.ErrNoRows {
		return nil, core.NameError("name not found")
	}
	if err != nil {
		return nil, err
	}

	ret := &proto.NameAndSeqnoBundle{
		B: proto.NameBundle{
			Name:     proto.Name(raw),
			NameUtf8: proto.NameUtf8(raw8),
		},
		S: proto.NameSeqno(seqno),
	}

	return ret, nil
}

func LoadGenericChain(
	m MetaContext,
	typ proto.ChainType,
	authenticatedEntity proto.EntityID,
	start proto.Seqno,
) (
	*rem.GenericChain,
	error,
) {
	db, err := m.G().Db(m.Ctx(), DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	u := NewChainLoader(authenticatedEntity, typ, start, db)

	treeLocMap, treeLocList, err := u.LoadTreeLocations(m)
	if err != nil {
		return nil, err
	}
	links, err := u.LoadChain(m)
	if err != nil {
		return nil, err
	}
	merkleKeys, err := u.MakeMerkleKeys(m, treeLocMap, links)
	if err != nil {
		return nil, err
	}

	merkle, err := u.LoadMerkle(m, merkleKeys)
	if err != nil {
		return nil, err
	}

	seed, err := u.LoadSubchainSeed(m)
	if err != nil {
		return nil, err
	}

	return &rem.GenericChain{
		Links:        links,
		Locations:    treeLocList,
		Merkle:       *merkle,
		LocationSeed: seed,
	}, nil
}

func collectHEPKFingerprints(links []proto.LinkOuter) ([]proto.HEPKFingerprint, error) {
	m := make(map[proto.HEPKFingerprint]struct{})
	for _, link := range links {
		v, err := link.GetV()
		if err != nil {
			return nil, err
		}
		if v != proto.LinkVersion_V1 {
			return nil, core.VersionNotSupportedError("link from future")
		}
		l1 := link.V1()
		inner, err := l1.Inner.AllocAndDecode(core.DecoderFactory{})
		if err != nil {
			return nil, err
		}
		t, err := inner.GetT()
		if err != nil {
			return nil, err
		}
		if t != proto.LinkType_GROUP_CHANGE {
			continue
		}
		gc := inner.GroupChange()
		for _, mr := range gc.Changes {
			mk := mr.Member.Keys
			typ, err := mk.GetT()
			if err != nil {
				return nil, err
			}
			switch typ {
			case proto.MemberKeysType_Team:
				tm := mk.Team()
				m[tm.HepkFp] = struct{}{}
			case proto.MemberKeysType_User:
				usr := mk.User()
				m[usr.HepkFp] = struct{}{}
			}
		}
		for _, sk := range gc.SharedKeys {
			m[sk.HepkFp] = struct{}{}
		}
	}
	ret := make([]proto.HEPKFingerprint, 0, len(m))
	for k := range m {
		ret = append(ret, k)
	}
	return ret, nil

}

func iterateOverChangeMetadata(links []proto.LinkOuter, f func(c proto.ChangeMetadata) error) error {
	for _, link := range links {
		v, err := link.GetV()
		if err != nil {
			return err
		}
		if v != proto.LinkVersion_V1 {
			return core.VersionNotSupportedError("link from future")
		}
		l1 := link.V1()
		inner, err := l1.Inner.AllocAndDecode(core.DecoderFactory{})
		if err != nil {
			return err
		}
		t, err := inner.GetT()
		if err != nil {
			return err
		}
		if t != proto.LinkType_GROUP_CHANGE {
			continue
		}
		gc := inner.GroupChange()
		for _, cm := range gc.Metadata {
			err = f(cm)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func nameMerkleKeys(
	host proto.HostID,
	arg *rem.NameSeqnoPair,
	curr rem.NameSeqnoPair,
) (
	[]proto.MerkleTreeRFOutput,
	error,
) {
	var ret []proto.MerkleTreeRFOutput

	// If the user didn't switch name, then just send the new links, always including
	// the terminal absense. If the user is new, then send all the links.
	start := proto.FirstNameSeqno
	if arg != nil && arg.N == curr.N {
		start = arg.S
	}
	end := curr.S + 1

	eid, err := merkle.NameToEntityID(curr.N, host)
	if err != nil {
		return nil, err
	}

	for i := start; i <= end; i++ {
		key, err := merkle.HashName(eid, i)
		if err != nil {
			return nil, err
		}
		ret = append(ret, *key)
	}

	return ret, nil
}
