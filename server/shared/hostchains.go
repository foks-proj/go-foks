// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"errors"
	"fmt"

	"github.com/foks-proj/go-foks/lib/cks"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
)

func lastElem[T any](s []*T) *T {
	return core.Last(s)
}

func MakeHostConfig(t proto.HostType) proto.HostConfig {
	ret := proto.HostConfig{
		Typ: t,
	}
	switch t {
	case proto.HostType_VHostManagement:
		ret.Metering.VHosts = true
	case proto.HostType_VHost:
		ret.Metering.Users = true
		ret.Metering.PerVHostDisk = true
	}
	return ret
}

type EvilHostChainTester struct {
	MutateLink    func(*proto.HostchainChange)
	MutateSigners func([]core.Signer) []core.Signer
}

type HostChain struct {
	hostID     core.HostID
	keys       map[proto.EntityType][](*HostKey)
	certs      map[proto.HostTLSCAID][]byte
	links      []proto.HostchainLinkOuter
	parent     *HostChain
	hostname   proto.Hostname // Must always be set
	cfg        proto.HostConfig
	evilTester *EvilHostChainTester

	// For now, it's here temporarily, but eventually, we might retire
	// the rest and keep just this
	newCert *CertGenerator
}

func NewHostChain() *HostChain {
	return &HostChain{
		keys:  make(map[proto.EntityType][](*HostKey)),
		certs: make(map[proto.HostTLSCAID][]byte),
		cfg: proto.HostConfig{
			Typ: proto.HostType_BigTop,
		},
	}
}

func (h *HostChain) WithEvilTester(t *EvilHostChainTester) *HostChain {
	h.evilTester = t
	return h
}

func (h *HostChain) WithConfig(cfg proto.HostConfig) *HostChain {
	h.cfg = cfg
	return h
}

func (h *HostChain) WithHostname(hn proto.Hostname) *HostChain {
	h.hostname = hn
	return h
}

func (h *HostChain) WithMetering(m proto.Metering) *HostChain {
	h.cfg.Metering = m
	return h
}

func (h *HostChain) WithVHostID(v proto.VHostID) *HostChain {
	h.hostID.VId = v
	return h
}

func (h *HostChain) WithHostType(t proto.HostType) *HostChain {
	h.cfg.Typ = t
	return h
}

func (h *HostChain) MetadataSigner() *HostKey {
	v := h.keys[proto.EntityType_HostMetadataSigner]
	if len(v) == 0 {
		return nil
	}
	return lastElem(v)
}

func (h *HostChain) WithParentVanity(p *HostChain, hn proto.Hostname) *HostChain {
	h.parent = p
	h.hostname = hn
	return h
}

func (h *HostChain) LoadKeyIntoState(hk *HostKey) error {
	eid, err := hk.EntityID()
	if err != nil {
		return err
	}
	typ := eid.Type()
	h.keys[typ] = append(h.keys[typ], hk)
	return nil
}

func (h *HostChain) loadCertsFromDB(m MetaContext) error {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	rows, err := db.Query(m.Ctx(),
		`SELECT key_id, cert_chain
		 FROM x509_assets
		 WHERE short_host_id=$1 
		 AND active=true
		 AND typ=$2`,
		int(h.hostID.Short),
		proto.CKSAssetType_HostchainFrontendCA.String(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key, certRaw []byte
		err = rows.Scan(&key, &certRaw)
		if err != nil {
			return err
		}
		var ret proto.HostTLSCAID
		err = ret.ImportFromBytes(key)
		if err != nil {
			return err
		}
		m.Infow("loadCertsFromDB", "key", ret.Hex())

		var cert proto.CKSCertChain
		err = core.DecodeFromBytes(&cert, certRaw)
		if err != nil {
			return err
		}
		leaf := cert.Leaf()
		if leaf == nil {
			return core.BadServerDataError("no leaf for hostchain cert")
		}
		h.certs[ret] = leaf
	}
	return nil
}

func (h *HostChain) LoadFromDB(m MetaContext) error {
	h.hostID = m.HostID()
	links, err := LoadHostchainRange(m, 0, nil)
	if err != nil {
		return err
	}
	h.links = links

	err = h.loadCertsFromDB(m)
	if err != nil {
		return err
	}
	return nil
}

func (h *HostChain) HostID() core.HostID {
	return h.hostID
}

func (h *HostChain) HostIDp() *core.HostID {
	return &h.hostID
}

func (h *HostChain) Key(typ proto.EntityType) *HostKey {
	v, ok := h.keys[typ]
	if !ok {
		return nil
	}
	if len(v) == 0 {
		return nil
	}
	return core.Last(v)
}

// Grabs the most recent cert avaialble, and its corresponding key.
func (h *HostChain) CA() (*HostKey, []byte, error) {
	key := h.Key(proto.EntityType_HostTLSCA)
	if key == nil {
		return nil, nil, core.HostchainError("no host tls CA key")
	}
	eid, err := key.EntityID()
	if err != nil {
		return nil, nil, err
	}
	id, err := eid.ToHostTLSCAID()
	if err != nil {
		return nil, nil, err
	}
	ret := h.certs[id]
	if ret == nil {
		return nil, nil, core.HostchainError("no host tls CA cert")
	}
	return key, ret, nil
}

func (h *HostChain) Links() []proto.HostchainLinkOuter {
	return h.links
}

// Forge a new hostchain, on initial server configuration, or on vhost creation.
// This might be done before a merkle server even starts up! So just load it with
// an empty merkle root.
func (h *HostChain) Forge(m MetaContext, d core.Path) error {
	err := h.generate(m, d)
	if err != nil {
		return err
	}
	return h.initWithKeys(m)
}

func (h *HostChain) initVHostID(m MetaContext) error {
	// if no vhost was supplied, it's fine to make a random one
	if !h.hostID.VId.IsZero() {
		return nil
	}
	vhid, err := proto.NewVHostID()
	if err != nil {
		return err
	}
	h.hostID.VId = *vhid
	return nil
}

func (h *HostChain) initWithKeys(m MetaContext) error {

	err := h.initVHostID(m)
	if err != nil {
		return err
	}
	link, seqno, err := h.makeEldestLink(m)
	if err != nil {
		return err
	}
	err = h.writeChainToDB(m, *link, seqno)
	if err != nil {
		return err
	}
	h.links = append(h.links, *link)
	return nil

}

func (h *HostChain) writeRevokesToDB(m MetaContext, tx pgx.Tx, keys []proto.EntityID) error {

	for _, key := range keys {
		tag, err := tx.Exec(
			m.Ctx(),
			`UPDATE host_keys
			SET state='revoked'
			WHERE short_host_id=$1 AND type=$2 AND key_id=$3 AND state='valid'`,
			int(h.hostID.Short),
			int(key.Type()),
			key.ExportToDB(),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("failed to update all key revokes")
		}

		if key.Type() == proto.EntityType_HostTLSCA {
			tag, err = tx.Exec(
				m.Ctx(),
				`UPDATE x509_assets
				 SET active=false
				 WHERE short_host_id=$1 AND key_id=$2`,
				h.hostID.Short.ExportToDB(),
				key.ExportToDB(),
			)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return core.UpdateError("failed to update all cert revokes")
			}
		}
	}

	// Can't go down to 0 master keys
	var cnt int
	err := tx.QueryRow(
		m.Ctx(),
		`SELECT COUNT(*) FROM host_keys WHERE short_host_id=$1 AND type=$2 AND state='valid'`,
		int(h.hostID.Short),
		int(proto.EntityType_Host),
	).Scan(&cnt)

	if err != nil {
		return err
	}

	if cnt < 1 {
		return core.UpdateError("can't revoke all host keys")
	}

	return nil
}

func (h *HostChain) pruneState(keys []proto.EntityID) error {
	for _, k1 := range keys {
		typ := k1.Type()
		v := h.keys[typ]
		var newV []*HostKey
		for _, k2 := range v {
			eid, err := k2.EntityID()
			if err != nil {
				return err
			}
			if !eid.Eq(k1) {
				newV = append(newV, k2)
			} else if typ == proto.EntityType_HostTLSCA {
				caid, err := eid.ToHostTLSCAID()
				if err != nil {
					return err
				}
				delete(h.certs, caid)
			}
		}
		h.keys[typ] = newV
	}
	return nil
}

func (h *HostChain) Revoke(m MetaContext, keys []proto.EntityID) (err error) {

	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	tx, err := db.Begin(m.Ctx())
	if err != nil {
		return err
	}
	defer func() {
		err = TxRollback(m.Ctx(), tx, err)
	}()

	link, seqno, err := h.makeRevokeLink(m, keys)
	if err != nil {
		return err
	}

	err = h.writeChainLinkToDB(m, tx, *link, seqno)
	if err != nil {
		return err
	}

	err = h.writeRevokesToDB(m, tx, keys)
	if err != nil {
		return err
	}

	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}

	h.links = append(h.links, *link)
	err = h.pruneState(keys)
	if err != nil {
		return err
	}

	return nil
}

func (h *HostChain) NewKey(m MetaContext, fn core.Path, typ proto.EntityType) (err error) {

	var newCert []byte
	var newKey *HostKey

	if typ == proto.EntityType_HostTLSCA {
		newKey, newCert, err = h.generateCA(m)
	} else {
		newKey, err = NewHostKeyGenerate(m.Ctx(), fn, typ)
	}

	if err != nil {
		return err
	}

	db, err := m.G().Db(m.Ctx(), DbTypeServerConfig)
	if err != nil {
		return err
	}

	defer db.Release()
	tx, err := db.Begin(m.Ctx())
	if err != nil {
		return err
	}
	defer func() {
		err = TxRollback(m.Ctx(), tx, err)
	}()

	link, seqno, err := h.makeNewKeyLink(m, newKey, newCert)
	if err != nil {
		return err
	}

	err = h.writeChainLinkToDB(m, tx, *link, seqno)
	if err != nil {
		return err
	}

	err = newKey.txWritePubToDB(m, tx, typ, seqno, &h.hostID)
	if err != nil {
		return err
	}

	err = h.writeNewCertToDB(m, tx)
	if err != nil {
		return err
	}

	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}

	h.links = append(h.links, *link)
	v := h.keys[typ]
	v = append(v, newKey)
	h.keys[typ] = v
	return nil
}

func (k *HostKey) MakeX509Cert() ([]byte, error) {
	priv := k.PrivateKey()
	pub := k.PublicKey()
	cert, err := core.GenCAFromKeyPair(pub, priv)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (h *HostChain) keypair(t proto.EntityType) (*HostKey, *proto.EntityID, error) {
	v := h.keys[t]
	if len(v) == 0 {
		return nil, nil, nil
	}
	key := lastElem(v)
	eid, err := key.EntityID()
	if err != nil {
		return nil, nil, err
	}
	return key, eid, nil
}

func (h *HostChain) makeNewKeyLink(
	m MetaContext,
	new *HostKey,
	cert []byte,
) (
	*proto.HostchainLinkOuter,
	proto.Seqno,
	error,
) {
	newEid, err := new.EntityID()
	if err != nil {
		return nil, 0, err
	}

	if (len(cert) > 0) != (newEid.Type() == proto.EntityType_HostTLSCA) {
		return nil, 0, core.HostKeyError("invalid cert")
	}

	var newLink proto.HostchainChangeItem
	if len(cert) > 0 {
		id, err := newEid.ToHostTLSCAID()
		if err != nil {
			return nil, 0, err
		}
		newLink = proto.NewHostchainChangeItemWithTlsca(
			proto.HostTLSCA{
				Cert: cert,
				Id:   id,
			},
		)
	} else {
		newLink = proto.NewHostchainChangeItemWithKey(*newEid)
	}
	items := []proto.HostchainChangeItem{newLink}

	return h.makeChangeLink(m, items, []core.Signer{new})
}

func (h *HostChain) makeRevokeLink(
	m MetaContext,
	keys []proto.EntityID,
) (
	*proto.HostchainLinkOuter,
	proto.Seqno,
	error,
) {
	var items []proto.HostchainChangeItem
	for _, key := range keys {
		items = append(items, proto.NewHostchainChangeItemWithRevoke(key))
	}
	return h.makeChangeLink(m, items, nil)
}

func (h *HostChain) merkleRoot(m MetaContext) (*proto.TreeRoot, error) {
	connector := NewBackendClient(m.G(), proto.ServerType_MerkleQuery, proto.ServerType_Tools, nil)
	defer connector.Close()
	gcli, err := connector.Cli(m.Ctx())
	if err != nil {
		return nil, err
	}
	cli := core.NewMerkleQueryClient(gcli, m)
	root, err := cli.GetCurrentRootHash(m.Ctx(), &h.hostID.Id)
	if err != nil {
		return nil, err
	}
	return &root, nil
}

func (h *HostChain) makeChangeLink(
	m MetaContext,
	items []proto.HostchainChangeItem,
	signers []core.Signer,
) (
	*proto.HostchainLinkOuter,
	proto.Seqno,
	error,
) {

	var seqno proto.Seqno = 0
	if len(h.links) == 0 {
		return nil, seqno, core.HostchainError("no links found")
	}
	last := h.links[len(h.links)-1]
	chng, err := core.OpenHostchainChangeLink(last)
	if err != nil {
		return nil, seqno, err
	}
	v := h.keys[proto.EntityType_Host]
	if len(v) == 0 {
		return nil, seqno, core.HostchainError("no host key found")
	}
	signer := lastElem(v)
	signerId, err := signer.HostID()
	if err != nil {
		return nil, seqno, err
	}

	seqno = chng.Change.Chainer.Seqno + 1

	link := proto.HostchainChange{
		Chainer: proto.BaseChainer{
			Seqno: seqno,
			Prev:  &chng.Hash,
			Time:  proto.Now(),
		},
		Host:    h.hostID.Id,
		Signer:  *signerId,
		Changes: items,
	}

	root, err := h.merkleRoot(m)
	if err != nil {
		return nil, seqno, err
	}
	link.Chainer.Root = *root

	if h.evilTester != nil && h.evilTester.MutateLink != nil {
		h.evilTester.MutateLink(&link)
	}

	signers = append(signers, signer)

	if h.evilTester != nil && h.evilTester.MutateSigners != nil {
		signers = h.evilTester.MutateSigners(signers)
	}

	ret, err := sealLink(&link, signers)
	if err != nil {
		return nil, seqno, err
	}
	return ret, seqno, nil
}

func (h *HostChain) makeEldestLink(m MetaContext) (*proto.HostchainLinkOuter, proto.Seqno, error) {
	seqno := proto.HostchainEldestSeqno

	var items []proto.HostchainChangeItem
	var keys []core.Signer

	// send back multiple certs if we have them

	for _, key := range h.keys[proto.EntityType_HostTLSCA] {
		eid, err := key.EntityID()
		if err != nil {
			return nil, seqno, err
		}
		if eid == nil {
			continue
		}
		tlscaid, err := eid.ToHostTLSCAID()
		if err != nil {
			return nil, seqno, err
		}
		cert := h.certs[tlscaid]
		if cert == nil {
			return nil, seqno, core.HostKeyError("no cert found")
		}
		tlsca := proto.HostTLSCA{
			Id:   tlscaid,
			Cert: cert,
		}
		items = append(items, proto.NewHostchainChangeItemWithTlsca(tlsca))
		keys = append(keys, key)
	}

	priv, eid, err := h.keypair(proto.EntityType_HostMerkleSigner)
	if err != nil {
		return nil, seqno, err
	}
	if eid != nil {
		items = append(items, proto.NewHostchainChangeItemWithKey(*eid))
		keys = append(keys, priv)
	}

	priv, eid, err = h.keypair(proto.EntityType_HostMetadataSigner)
	if err != nil {
		return nil, seqno, err
	}
	if eid != nil {
		items = append(items, proto.NewHostchainChangeItemWithKey(*eid))
		keys = append(keys, priv)
	}

	// Note that we leave the Merkle Root pointer nil here. We're going to get 0/000000
	// because the merkle server can't really start up without a host ID.
	chng := proto.HostchainChange{
		Chainer: proto.BaseChainer{
			Seqno: seqno,
			Time:  proto.Now(),
		},
		Host:    h.hostID.Id,
		Signer:  h.hostID.Id,
		Changes: items,
	}

	v := h.keys[proto.EntityType_Host]
	if len(v) == 0 {
		return nil, seqno, core.HostKeyError("no host key found")
	}
	host := lastElem(v)
	keys = append(keys, host)

	ret, err := sealLink(&chng, keys)
	if err != nil {
		return nil, seqno, err
	}
	return ret, seqno, nil
}

func sealLink(chng *proto.HostchainChange, keys []core.Signer) (*proto.HostchainLinkOuter, error) {

	inner := proto.NewHostchainLinkInnerWithChange(*chng)
	blob, err := core.EncodeToBytes(&inner)
	if err != nil {
		return nil, err
	}
	v1 := proto.HostchainLinkOuterV1{Inner: blob}

	err = core.SignStacked(&v1, keys)
	if err != nil {
		return nil, err
	}
	ret := proto.NewHostchainLinkOuterWithV1(v1)
	return &ret, nil
}

func (h *HostChain) addGeneratedKey(typ proto.EntityType, key *HostKey) error {
	curr := h.keys[typ]
	curr = append(curr, key)
	h.keys[typ] = curr

	// Hold onto the hostID
	if typ == proto.EntityType_Host {
		pub, err := key.EntityPrivateEd25519.EntityPublic()
		if err != nil {
			return err
		}
		hid, err := pub.GetEntityID().HostID()
		if err != nil {
			return err
		}
		h.hostID.Id = hid
	}
	return nil
}

func (h *HostChain) genkey(m MetaContext, d core.Path, typ proto.EntityType) (*HostKey, error) {
	switch {
	case len(d) > 0:
		fn := d.JoinStrings(hostKeyFilename(typ))
		return NewHostKeyGenerate(m.Ctx(), fn, typ)
	case typ == proto.EntityType_Host:
		return NewVHostKeyGen(m)
	default:
		return NewVHostKeyGenSub(m, h.hostID.Id, typ)
	}
}

func (h *HostChain) generateCA(m MetaContext) (*HostKey, []byte, error) {
	typ := proto.EntityType_HostTLSCA
	cg, err := NewCertGenerator(typ)
	if err != nil {
		return nil, nil, err
	}
	err = cg.GenCA(m)
	if err != nil {
		return nil, nil, err
	}
	h.newCert = cg
	v1 := cg.ToV1()
	err = h.addGeneratedKey(typ, v1)
	if err != nil {
		return nil, nil, err
	}
	cert := cg.Cert()

	caid, err := v1.HostTLSCAID()
	if err != nil {
		return nil, nil, err
	}
	h.certs[*caid] = cert

	return v1, cert, nil
}

func (h *HostChain) generate(m MetaContext, d core.Path) error {
	types := core.AllHostKeyTypes
	for _, typ := range types {
		if typ == proto.EntityType_HostTLSCA {
			_, _, err := h.generateCA(m)
			if err != nil {
				return err
			}
		} else {
			key, err := h.genkey(m, d, typ)
			if err != nil {
				return err
			}
			err = h.addGeneratedKey(typ, key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *HostChain) writeNewCertToDB(m MetaContext, tx pgx.Tx) error {
	if h.newCert == nil {
		return nil
	}
	eng := m.G().CertMgr()
	dat, err := h.newCert.CKSData(true)
	if err != nil {
		return err
	}
	err = eng.PutCert(m, tx, cks.Index{HostID: h.hostID, Type: proto.CKSAssetType_HostchainFrontendCA}, dat)
	if err != nil {
		return err
	}
	h.newCert = nil
	return nil
}

func (h *HostChain) writeChainToDB(m MetaContext, eld proto.HostchainLinkOuter, seqno proto.Seqno) (err error) {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	tx, err := db.Begin(m.Ctx())
	if err != nil {
		return err
	}
	defer func() {
		err = TxRollback(m.Ctx(), tx, err)
	}()

	// important: we need to write the host ID first, so that we can get our
	// short host ID. It's a function of what's already in the database.
	err = h.writeHostIDToDB(m, tx)
	if err != nil {
		return err
	}
	err = h.writeHostnameToDB(m, tx)
	if err != nil {
		return err
	}
	err = h.writeConfigToDB(m, tx)
	if err != nil {
		return err
	}
	err = h.writePubToDB(m, tx, seqno)
	if err != nil {
		return err
	}
	err = h.writeChainLinkToDB(m, tx, eld, seqno)
	if err != nil {
		return err
	}
	err = h.writeNewCertToDB(m, tx)
	if err != nil {
		return err
	}
	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}
	return nil
}

func (h *HostChain) writeConfigToDB(m MetaContext, tx pgx.Tx) error {
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO host_config (short_host_id, user_metering,
		  vhost_metering, per_vhost_disk_metering, host_type, user_viewing,
		  invite_code_regime)
		VALUES($1, $2, $3, $4, $5, $6, $7)`,
		int(h.hostID.Short),
		h.cfg.Metering.Users,
		h.cfg.Metering.VHosts,
		h.cfg.Metering.PerVHostDisk,
		h.cfg.Typ.String(),
		proto.ViewershipMode_Closed.String(),
		proto.InviteCodeRegime_CodeRequired.String(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("host config")
	}
	return nil
}

func (h *HostChain) writeHostnameToDB(m MetaContext, tx pgx.Tx) error {
	if h.hostname.IsZero() {
		return core.InternalError("empty hostname in hostchain create")
	}
	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO hostnames(short_host_id, hostname, cancel_id, ctime)
		VALUES($1, $2, $3, NOW())`,
		h.hostID.Short.ExportToDB(),
		h.hostname.Normalize().String(),
		proto.NilCancelID(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("hostnames")
	}
	return nil
}

func (h *HostChain) writeHostIDToDB(m MetaContext, tx pgx.Tx) error {

	if h.hostID.VId.IsZero() {
		return core.InternalError("empty vhost ID")
	}

	var shortId int
	err := tx.QueryRow(m.Ctx(),
		`SELECT short_host_id FROM hosts ORDER by short_host_id DESC LIMIT 1`,
	).Scan(&shortId)
	if errors.Is(err, pgx.ErrNoRows) {
		shortId = 0
	} else if err != nil {
		return err
	}
	shortId++

	root := m.G().ShortHostID()
	if root == 0 {
		root = core.ShortHostID(shortId)
	}
	parent := root
	if h.parent != nil {
		parent = h.parent.HostID().Short
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO hosts (short_host_id, host_id,
		    vhost_id, root_short_host_id,
			parent_short_host_id, ctime) 
		VALUES ($1, $2, $3, $4, $5, NOW())`,
		shortId,
		h.hostID.Id.ExportToDB(),
		h.hostID.VId.ExportToDB(),
		root.ExportToDB(),
		parent.ExportToDB(),
	)
	if err != nil {
		return err
	}

	if tag.RowsAffected() != 1 {
		return core.InsertError("cannot insert into hosts")
	}

	h.hostID.Short = core.ShortHostID(shortId)

	return err
}

func (h *HostChain) writePubToDB(m MetaContext, tx pgx.Tx, seqno proto.Seqno) error {
	for typ, keyVec := range h.keys {
		for _, key := range keyVec {
			err := key.txWritePubToDB(m, tx, typ, seqno, &h.hostID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *HostChain) writeChainLinkToDB(m MetaContext, tx pgx.Tx, link proto.HostchainLinkOuter, seqno proto.Seqno) error {
	return WriteChainLinkToDB(m, tx, link, seqno, &h.hostID, &h.hostID.Id)
}

func WriteChainLinkToDB(
	m MetaContext,
	tx pgx.Tx,
	link proto.HostchainLinkOuter,
	seqno proto.Seqno,
	hostid *core.HostID,
	signer *proto.HostID,
) error {
	b, err := core.EncodeToBytes(&link)
	if err != nil {
		return err
	}
	hsh, err := core.HostchainLinkHash(&link)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(m.Ctx(),
		`INSERT INTO hostchain_links (short_host_id, seqno, signing_key_id, body, hash, ctime, merkle_state)
		 VALUES($1, $2, $3, $4, $5, NOW(), 'staged')`,
		int(hostid.Short),
		seqno,
		signer.ExportToDB(),
		b,
		hsh.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("hostchain link")
	}
	return nil
}

func LoadHostchain(
	m MetaContext,
	start proto.Seqno,
	root proto.SignedMerkleRoot,
) (
	[]proto.HostchainLinkOuter,
	error,
) {
	v1, err := merkle.OpenMerkleRootNoSigCheck(root.Inner)
	if err != nil {
		return nil, err
	}
	end := v1.Hostchain.Seqno

	return LoadHostchainRange(
		m, start, &end,
	)
}

func LoadHostchainRange(
	m MetaContext,
	start proto.Seqno,
	end *proto.Seqno,
) (
	[]proto.HostchainLinkOuter,
	error,
) {

	if end != nil && start > *end {
		return nil, core.HostchainError(fmt.Sprintf("start %d > end %d for hostchain", start, *end))
	}
	if end != nil && start == *end {
		return nil, nil
	}

	db, err := m.G().Db(m.Ctx(), DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	var args = []any{
		m.ShortHostID().ExportToDB(),
		int(start),
	}
	q := `SELECT body FROM hostchain_links
		 WHERE short_host_id = $1
		 AND seqno > $2`
	if end != nil {
		q += ` AND seqno <= $3`
		args = append(args, int(*end))
	}
	q += ` ORDER BY seqno ASC`

	rows, err := db.Query(m.Ctx(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []proto.HostchainLinkOuter

	for rows.Next() {
		var body []byte
		err = rows.Scan(&body)
		if err != nil {
			return nil, err
		}
		var link proto.HostchainLinkOuter
		err = core.DecodeFromBytes(&link, body)
		if err != nil {
			return nil, err
		}
		ret = append(ret, link)
	}

	return ret, nil
}

func LoadHostChain(m MetaContext, keys []proto.EntityType) (
	*HostChain,
	error,
) {
	hkc := NewHostChain()
	for _, typ := range keys {
		ioer, err := m.PrivateHostKeyIOer(m.HostID().Id, typ)
		if err != nil {
			return nil, err
		}
		key, err := ReadHostKey(m.Ctx(), ioer)
		if err != nil {
			return nil, err
		}
		err = hkc.LoadKeyIntoState(key)
		if err != nil {
			return nil, err
		}
	}

	err := hkc.LoadFromDB(m)
	if err != nil {
		return nil, err
	}
	return hkc, nil
}
