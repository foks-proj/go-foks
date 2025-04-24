// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"bytes"
	"context"
	"flag"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/jackc/pgx/v5"
)

type MerkleSignerVHostState struct {
	shid core.ShortHostID

	key *shared.HostKey
	kid proto.HostMerkleSignerID

	// If the last time we signed, we used a different key, we need to write a new
	// row saying we're using a different key.
	needSigningKeyTableUpdate bool
}

type MerkleSignerServer struct {
	MerklePipelineBaseServer
	vhosts map[core.ShortHostID]*MerkleSignerVHostState
}

func NewMerkleSignerServer() *MerkleSignerServer {
	ret := &MerkleSignerServer{
		vhosts: make(map[core.ShortHostID]*MerkleSignerVHostState),
	}
	ret.sub = ret
	ret.serverType = proto.ServerType_MerkleSigner
	return ret
}

func (b *MerkleSignerServer) ConfigureCLIOptions(fs *flag.FlagSet) {}
func (b *MerkleSignerServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &MerkleSignerClientConn{
		srv:            b,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(b.G(), uhc),
	}
}

func (b *MerkleSignerServer) Setup(m shared.MetaContext) error {
	err := b.MerklePipelineBaseServer.Setup(m)
	if err != nil {
		return err
	}
	return nil
}

func (v *MerkleSignerVHostState) readSigningKey(m shared.MetaContext, s *MerkleSignerServer) error {
	var ioer shared.HostKeyIOer
	var err error
	if m.IsPrimaryHost() {
		ioer, err = s.cfg.SigningKey()
	} else {
		ioer, err = m.PrivateHostKeyIOer(m.HostID().Id, proto.EntityType_HostMerkleSigner)
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	if ioer == nil {
		return core.ConfigError("Signing key not configured")
	}
	v.key, err = shared.ReadHostKey(m.Ctx(), ioer)
	if err != nil {
		return err
	}
	eid, err := v.key.EntityID()
	if err != nil {
		return err
	}
	v.kid, err = eid.ToHostMerkleSignerID()
	if err != nil {
		return err
	}
	return nil
}

func (s *MerkleSignerServer) initBackgroundLoop(m shared.MetaContext) error {
	return nil
}

func (v *MerkleSignerVHostState) readLastSigningKey(m shared.MetaContext, s *MerkleSignerServer) error {
	db, err := m.Db(shared.DbTypeMerkleTree)
	if err != nil {
		return err
	}
	defer db.Release()

	var tmp []byte
	err = db.QueryRow(
		m.Ctx(),
		`SELECT key_id FROM merkle_signing_keys
		 WHERE short_host_id=$1
		 ORDER BY epno DESC LIMIT 1`,
		m.ShortHostID().ExportToDB(),
	).Scan(&tmp)
	if err != nil && err == pgx.ErrNoRows {
		// Need to write epno=0
		v.needSigningKeyTableUpdate = true
		return nil
	}
	if err != nil {
		return err
	}
	eid, err := proto.ImportEntityIDFromBytes(tmp)
	if err != nil {
		return err
	}
	mid, err := eid.ToHostMerkleSignerID()
	if err != nil {
		return err
	}
	if !mid.Eq(v.kid) {
		v.needSigningKeyTableUpdate = true
	}
	return nil
}

func (v *MerkleSignerVHostState) init(m shared.MetaContext, s *MerkleSignerServer) error {
	err := v.readSigningKey(m, s)
	if err != nil {
		return err
	}
	err = v.readLastSigningKey(m, s)
	if err != nil {
		return err
	}
	return nil
}

func (s *MerkleSignerServer) pollReadyHosts(m shared.MetaContext) ([]core.ShortHostID, error) {
	db, err := m.Db(shared.DbTypeMerkleTree)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	rows, err := db.Query(
		m.Ctx(),
		`SELECT DISTINCT(short_host_id) FROM merkle_roots WHERE sig IS NULL`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ret, err := scanShortHostIDs(rows)
	if err != nil {
		return nil, err
	}
	m.Infow("pollReadyHosts", "shortHostID", m.ShortHostID(), "ret", ret)

	return ret, nil
}

func (s *MerkleSignerServer) initVhostState(m shared.MetaContext) (*MerkleSignerVHostState, error) {
	shid := m.ShortHostID()
	vh, ok := s.vhosts[shid]
	if ok {
		return vh, nil
	}
	vh = &MerkleSignerVHostState{shid: shid}
	err := vh.init(m, s)
	if err != nil {
		return nil, err
	}
	s.vhosts[shid] = vh
	return vh, nil

}

func (s *MerkleSignerServer) doOnePollForHost(m shared.MetaContext) (err error) {

	vhs, err := s.initVhostState(m)
	if err != nil {
		return err
	}

	db, err := m.Db(shared.DbTypeMerkleTree)
	if err != nil {
		return nil
	}
	defer db.Release()
	rows, err := db.Query(m.Ctx(),
		`SELECT epno,body
 		 FROM merkle_roots
		 WHERE short_host_id=$1
		 AND sig IS NULL
		 ORDER BY epno ASC LIMIT $2`,
		m.ShortHostID().ExportToDB(),
		s.cfg.BatchSize(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	type rootAndEpno struct {
		Epno proto.MerkleEpno
		root proto.MerkleRoot
		raw  []byte
	}
	var roots []rootAndEpno
	for rows.Next() {
		var epno int
		var root rootAndEpno
		err = rows.Scan(&epno, &root.raw)
		if err != nil {
			return err
		}
		root.Epno = proto.MerkleEpno(epno)
		err = core.DecodeFromBytes(&root.root, root.raw)
		if err != nil {
			return err
		}
		roots = append(roots, root)
	}
	if err = rows.Err(); err != nil {
		return err
	}

	if len(roots) == 0 {
		return nil
	}

	tx, err := db.Begin(m.Ctx())
	if err != nil {
		return err
	}

	m.Infow("doOnePollForHost", "shortHostID", m.ShortHostID(), "roots", roots)

	defer func() {
		err = shared.TxRollback(m.Ctx(), tx, err)
	}()

	var lst *rootAndEpno
	for _, root := range roots {
		sig, blob, err := core.Sign2(vhs.key, &root.root)
		if err != nil {
			return err
		}
		sigRaw, err := core.EncodeToBytes(sig)
		if err != nil {
			return err
		}

		tag, err := tx.Exec(
			m.Ctx(),
			`UPDATE merkle_roots SET sig=$1
			 WHERE short_host_id=$2 AND epno=$3`,
			sigRaw,
			m.ShortHostID().ExportToDB(),
			int(root.Epno),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("failed to update merkle signatures table")
		}

		// It's possible that we just updated the representation while this root was in
		// flight, so let's make sure we write down exactly what we signed.
		if !bytes.Equal(root.raw, blob.Bytes()) {

			tag, err := tx.Exec(
				m.Ctx(),
				`UPDATE merkle_roots SET body=$1
   			     WHERE short_host_id=$2 AND epno=$3`,
				blob.Bytes(),
				m.ShortHostID().ExportToDB(),
				int(root.Epno),
			)

			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return core.UpdateError("failed to update merkle signatures table")
			}
		}
		lst = &root
	}

	m.Infow("doOnePollForHost", "shortHostID", m.ShortHostID(), "signUpTo", lst.Epno)

	tag, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO merkle_last_sig (short_host_id, epno, mtime)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (short_host_id)
		 DO UPDATE SET epno=$2, mtime=NOW()`,
		m.ShortHostID().ExportToDB(),
		int(lst.Epno),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("failed to update merkle last signature table")
	}

	if vhs.needSigningKeyTableUpdate {
		tag, err := tx.Exec(
			m.Ctx(),
			`INSERT INTO merkle_signing_keys(short_host_id, key_id, epno, ctime)
			 VALUES ($1, $2, $3, NOW())`,
			m.ShortHostID().ExportToDB(),
			vhs.kid.ExportToDB(),
			int(lst.Epno),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return core.UpdateError("failed to update merkle signing key table")
		}
		vhs.needSigningKeyTableUpdate = false
	}

	err = tx.Commit(m.Ctx())
	if err != nil {
		return err
	}
	return nil
}

type MerkleSignerClientConn struct {
	shared.BaseClientConn
	srv *MerkleSignerServer
	xp  rpc.Transporter
}

func (c *MerkleSignerClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(proto.MerkleSignerProtocol(c))
}

func (c *MerkleSignerClientConn) Poke(ctx context.Context) error {
	return c.srv.Poke(ctx)
}

func (c *MerkleSignerClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (s *MerkleSignerServer) ToRPCServer() shared.RPCServer { return s }

var _ proto.MerkleSignerInterface = (*MerkleSignerClientConn)(nil)
var _ shared.ClientConn = (*MerkleSignerClientConn)(nil)
var _ shared.RPCServer = (*MerkleSignerServer)(nil)
