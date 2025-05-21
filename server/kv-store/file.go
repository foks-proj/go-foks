// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kvStore

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/kv"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/nacl/secretbox"
)

func fileRef(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	id proto.FileID,
	v int,
) error {
	tag, err := tx.Exec(
		m.Ctx(),
		`UPDATE large_file SET refcount=refcount+$1, mtime=NOW()
		WHERE short_host_id=$2 AND short_party_id=$3 AND file_id=$4`,
		v, int(m.HostID().Short), pid.Shorten().ExportToDB(), id.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("large_file")
	}
	return nil
}

func smallFileRef(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	id proto.KVNodeID,
	v int,
) error {
	tag, err := tx.Exec(
		m.Ctx(),
		`UPDATE small_file_or_symlink SET refcount=refcount+$1, mtime=NOW()
		WHERE short_host_id=$2 AND short_party_id=$3 AND node_id=$4`,
		v, int(m.HostID().Short), pid.Shorten().ExportToDB(), id.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("small_file")
	}
	return nil
}

type SimpleLargeFileStream struct {
	data []byte
	done bool
}

func NewSimpleLargeFileStream(data []byte) *SimpleLargeFileStream {
	return &SimpleLargeFileStream{
		data: data,
	}
}

func (s *SimpleLargeFileStream) Next() ([]byte, error) {
	if s.done {
		return nil, nil
	}
	s.done = true
	return s.data, nil
}

func (s *SimpleLargeFileStream) Len() int {
	return len(s.data)
}

func putSmallFileOrSymlink(
	m shared.MetaContext,
	tx pgx.Tx,
	pid proto.PartyID,
	role proto.Role,
	arg rem.KvPutSmallFileOrSymlinkArg,
) error {
	err := assertAtOrAbove(role, arg.Sfb.Rg.Role, proto.KVOp_Read, proto.KVNodeType_Symlink)
	if err != nil {
		return err
	}

	rk, err := core.ImportRole(arg.Sfb.Rg.Role)
	if err != nil {
		return err
	}

	// Max length of small file is 2k + size of Poly1305
	lim := kv.SmallFileSize + secretbox.Overhead
	if len(arg.Sfb.DataBox) > lim {
		return core.TooBigError{
			Actual: len(arg.Sfb.DataBox),
			Limit:  lim,
			Desc:   "small file",
		}
	}

	err = usageCheckAndInc(
		m,
		tx,
		pid,
		proto.KVNodeType_SmallFile,
		len(arg.Sfb.DataBox),
		true,
	)
	if err != nil {
		return err
	}

	tag, err := tx.Exec(
		m.Ctx(),
		`INSERT INTO small_file_or_symlink(short_host_id, short_party_id, node_id, 
			ptk_gen, read_role_type, read_role_viz_level,
			size, box, ctime, mtime, refcount 
		) VALUES($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), 0)`,
		int(m.HostID().Short),
		pid.Shorten().ExportToDB(),
		arg.Id.ExportToDB(),
		int(arg.Sfb.Rg.Gen),
		int(rk.Typ),
		int(rk.Lev),
		len(arg.Sfb.DataBox),
		arg.Sfb.DataBox.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("large_file")
	}
	return nil
}

type LargeFileStatus int

const (
	LargeFileStatusNone      LargeFileStatus = 0
	LargeFileStatusActive    LargeFileStatus = 1
	LargeFileStatusDead      LargeFileStatus = 2
	LargeFileStatusUploading LargeFileStatus = 3
)

func (l LargeFileStatus) ExportToDB() string {
	switch l {
	case LargeFileStatusActive:
		return "active"
	case LargeFileStatusDead:
		return "dead"
	case LargeFileStatusUploading:
		return "uploading"
	default:
		return "unknown"
	}
}

func ParseLargeFileStatus(s string) (LargeFileStatus, error) {
	switch s {
	case "active":
		return LargeFileStatusActive, nil
	case "dead":
		return LargeFileStatusDead, nil
	case "uploading":
		return LargeFileStatusUploading, nil
	default:
		return LargeFileStatusNone, core.BadServerDataError("bad file status")
	}
}

type fileUploader struct {
	tx   pgx.Tx
	lfe  LargeFileStorageEngine
	pid  proto.PartyID
	role proto.Role
	fid  proto.FileID
	chnk proto.UploadChunk
	md   proto.LargeFileMetadata
}

func (f *fileUploader) assertUploading(m shared.MetaContext) error {
	var status string
	err := f.tx.QueryRow(
		m.Ctx(),
		`SELECT status FROM large_file
		WHERE short_host_id=$1 AND short_party_id=$2 AND file_id=$3`,
		int(m.HostID().Short), f.pid.Shorten().ExportToDB(), f.fid.ExportToDB(),
	).Scan(&status)
	if err != nil {
		return err
	}
	if status != LargeFileStatusUploading.ExportToDB() {
		return core.UploadError("file not in uploading state")
	}
	return nil
}

func (f *fileUploader) doChunk(m shared.MetaContext) error {
	err := f.assertUploading(m)
	if err != nil {
		return err
	}
	err = f.insChunk(m)
	if err != nil {
		return err
	}
	err = f.finalize(m)
	if err != nil {
		return err
	}
	return nil
}

func (f *fileUploader) run(m shared.MetaContext) error {
	err := f.checkPerms(m)
	if err != nil {
		return err
	}
	err = f.insLargeFile(m)
	if err != nil {
		return err
	}
	err = f.insKey(m)
	if err != nil {
		return err
	}
	err = f.insChunk(m)
	if err != nil {
		return err
	}
	err = f.finalize(m)
	if err != nil {
		return err
	}
	return nil
}

func fileUploadInit(
	m shared.MetaContext,
	lfe LargeFileStorageEngine,
	tx pgx.Tx,
	pid proto.PartyID,
	role proto.Role,
	arg rem.KvFileUploadInitArg,
) error {
	ful := fileUploader{tx: tx, pid: pid, role: role, fid: arg.FileID, md: arg.Md, chnk: arg.Chunk, lfe: lfe}
	return ful.run(m)
}

func fileUploadChunk(
	m shared.MetaContext,
	lfe LargeFileStorageEngine,
	tx pgx.Tx,
	pid proto.PartyID,
	role proto.Role,
	arg rem.KvFileUploadChunkArg,
) error {
	ful := fileUploader{tx: tx, pid: pid, role: role, fid: arg.FileID, chnk: arg.Chunk, lfe: lfe}
	return ful.doChunk(m)
}

func (f *fileUploader) checkPerms(m shared.MetaContext) error {
	err := assertAtOrAbove(f.role, f.md.Rg.Role, proto.KVOp_Read, proto.KVNodeType_File)
	if err != nil {
		return err
	}
	return nil
}

func (f *fileUploader) insLargeFile(m shared.MetaContext) error {
	tag, err := f.tx.Exec(
		m.Ctx(),
		`INSERT INTO large_file(
			short_host_id, short_party_id, file_id, size, 
			ctime, mtime, refcount, status, storage_type
		) VALUES($1, $2, $3, $4, NOW(), NOW(), 0, $5, $6)`,
		int(m.HostID().Short),
		f.pid.Shorten().ExportToDB(),
		f.fid.ExportToDB(),
		0, // will update later
		LargeFileStatusUploading.ExportToDB(),
		f.lfe.Strategy().ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("large_file")
	}
	return nil
}

func (f *fileUploader) insKey(m shared.MetaContext) error {
	rk, err := core.ImportRole(f.md.Rg.Role)
	if err != nil {
		return err
	}
	box, err := core.EncodeToBytes(&f.md.KeySeed)
	if err != nil {
		return err
	}
	tag, err := f.tx.Exec(
		m.Ctx(),
		`INSERT INTO large_file_key(
			short_host_id, short_party_id, file_id, version,
			ptk_gen, key_box, read_role_type, read_role_viz_level, ctime, mtime
		) VALUES($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
		int(m.HostID().Short),
		f.pid.Shorten().ExportToDB(),
		f.fid.ExportToDB(),
		int(f.md.Vers),
		int(f.md.Rg.Gen),
		box,
		int(rk.Typ),
		int(rk.Lev),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("large_file_key")
	}
	return nil
}

func (f *fileUploader) insChunk(m shared.MetaContext) error {

	chnk := f.chnk
	if len(chnk.Data) > kv.MaxEncryptedChunkSize {
		return core.TooBigError{
			Actual: len(chnk.Data),
			Limit:  kv.MaxEncryptedChunkSize,
			Desc:   "file chunk",
		}
	}
	if len(chnk.Data) < kv.MinEncryptedChunkSize {
		return core.UploadError("chunk is too small")
	}
	first := (chnk.Offset == 0)
	final := (chnk.Final != nil)

	err := usageCheckAndInc(
		m,
		f.tx,
		f.pid,
		proto.KVNodeType_File,
		len(chnk.Data),
		first,
	)
	if err != nil {
		return err
	}

	tag, err := f.tx.Exec(
		m.Ctx(),
		`INSERT INTO large_file_chunk(
			short_host_id, short_party_id, file_id, chunk_offset, 
			data, final, ctime
		) VALUES($1, $2, $3, $4, $5, $6, NOW())`,
		int(m.HostID().Short),
		f.pid.Shorten().ExportToDB(),
		f.fid.ExportToDB(),
		int(chnk.Offset),
		chnk.Data.ExportToDB(),
		final,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("large_file_chunk")
	}
	return nil
}

func (f *fileUploader) checkChunks(m shared.MetaContext) error {
	rows, err := f.tx.Query(
		m.Ctx(),
		`SELECT chunk_offset, OCTET_LENGTH(data) FROM large_file_chunk
		WHERE short_host_id=$1 AND short_party_id=$2 AND file_id=$3
		ORDER BY chunk_offset ASC`,
		int(m.HostID().Short), f.pid.Shorten().ExportToDB(), f.fid.ExportToDB(),
	)
	if err != nil {
		return err
	}
	defer rows.Close()
	var pos int64
	var tot int64
	for rows.Next() {
		var offset int64
		var sz int64
		err = rows.Scan(&offset, &sz)
		if err != nil {
			return err
		}
		if offset != pos {
			return core.UploadError("chunks didn't line up")
		}
		tot += sz

		// If given a block of length 16403, 3 is for msgpack overhead, and
		// 16 is for the NaCl tag. Should line up with the offsets that the client is
		// sending.
		sz -= secretbox.Overhead
		pli, err := kv.PaddedLenInv(int64(sz))
		if err != nil {
			return err
		}
		pos += pli
	}
	if tot != int64(f.chnk.Final.Sz) {
		return core.UploadError("wrong file size on reconstruction")
	}
	return nil
}

func (f *fileUploader) finalize(m shared.MetaContext) error {
	if f.chnk.Final == nil {
		return nil
	}
	err := f.checkChunks(m)
	if err != nil {
		return err
	}
	tag, err := f.tx.Exec(
		m.Ctx(),
		`UPDATE large_file SET size=$1, status=$2, mtime=NOW()
		WHERE short_host_id=$3 AND short_party_id=$4 AND file_id=$5 AND status=$6`,
		f.chnk.Final.Sz,
		LargeFileStatusActive.ExportToDB(),
		int(m.HostID().Short),
		f.pid.Shorten().ExportToDB(),
		f.fid.ExportToDB(),
		LargeFileStatusUploading.ExportToDB(),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.UpdateError("large_file")
	}
	err = f.lfe.Finalize(m, f.tx, f.fid)
	if err != nil {
		return err
	}
	return nil
}

type ChunkedLargeFileStream struct {
	bufs [][]byte
	ptr  int
}

func NewChunkedLargeFileStream(b [][]byte) *ChunkedLargeFileStream {
	return &ChunkedLargeFileStream{
		bufs: b,
		ptr:  0,
	}
}

func (c *ChunkedLargeFileStream) Len() int {
	ret := 0
	for _, b := range c.bufs {
		ret += len(b)
	}
	return ret
}

func (c *ChunkedLargeFileStream) Push(b []byte) {
	c.bufs = append(c.bufs, b)
}

func (c *ChunkedLargeFileStream) Next() ([]byte, error) {
	if c.ptr >= len(c.bufs) {
		return nil, nil
	}
	ret := c.bufs[c.ptr]
	c.ptr++
	return ret, nil
}

var _ LargeFileStreamer = (*ChunkedLargeFileStream)(nil)

func loadLargeFileMetadata(
	m shared.MetaContext,
	db *pgxpool.Conn,
	pid proto.PartyID,
	val proto.KVNodeID,
	role proto.Role,
) (
	*proto.LargeFileMetadata,
	error,
) {
	var v, ptkg, rt, vl int
	var keyBox []byte
	var status string
	fid, err := val.ToFileID()
	if err != nil {
		return nil, err
	}

	err = db.QueryRow(
		m.Ctx(),
		`SELECT version, read_role_type, read_role_viz_level, ptk_gen, key_box,
		    status
		FROM large_file
		JOIN large_file_key USING(short_host_id, short_party_id, file_id)
		WHERE short_host_id=$1 AND short_party_id=$2 AND file_id=$3
		ORDER BY version DESC
		LIMIT 1`,
		int(m.ShortHostID()), pid.Shorten().ExportToDB(), fid.ExportToDB(),
	).Scan(&v, &rt, &vl, &ptkg, &keyBox, &status)
	if err != nil && err == pgx.ErrNoRows {
		return nil, core.NotFoundError("large file metadata")
	}
	if err != nil {
		return nil, err
	}
	st, err := ParseLargeFileStatus(status)
	if err != nil {
		return nil, err
	}
	switch st {
	case LargeFileStatusUploading:
		return nil, core.KVUploadInProgressError{}
	case LargeFileStatusDead:
		return nil, core.KVNoentError{}
	case LargeFileStatusActive:
	default:
		return nil, core.BadServerDataError("bad file status")
	}
	var sb proto.SecretBox
	err = core.DecodeFromBytes(&sb, keyBox)
	if err != nil {
		return nil, err
	}

	ret := proto.LargeFileMetadata{
		Rg: proto.RoleAndGen{
			Gen: proto.Generation(ptkg),
		},
		KeySeed: sb,
		Vers:    proto.KVVersion(v),
	}
	err = ret.Rg.Role.ImportFromDB(rt, vl)
	if err != nil {
		return nil, err
	}

	return &ret, nil
}

func getNode(
	m shared.MetaContext,
	lfe LargeFileStorageEngine,
	db *pgxpool.Conn,
	pid proto.PartyID,
	role proto.Role,
	arg rem.KvGetNodeArg,
) (
	*rem.KVGetNodeRes,
	error,
) {
	ret, err := loadNode(m, db, pid, arg.Id, role)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func getChunk(
	m shared.MetaContext,
	lfe LargeFileStorageEngine,
	db *pgxpool.Conn,
	pid proto.PartyID,
	role proto.Role,
	arg rem.KvGetEncryptedChunkArg,
) (
	*rem.GetEncryptedChunkRes,
	error,
) {
	return lfe.Get(m, db, pid, arg.Id, arg.Offset)
}

func loadNode(
	m shared.MetaContext,
	db *pgxpool.Conn,
	pid proto.PartyID,
	nodeId proto.KVNodeID,
	role proto.Role,
) (
	*rem.KVGetNodeRes,
	error,
) {
	typ, err := nodeId.Type()
	if err != nil {
		return nil, err
	}

	var ret *rem.KVGetNodeRes

	switch typ {
	case proto.KVNodeType_SmallFile:
		file, err := loadSmallFileOrSymlink(m, db, pid, nodeId, role)
		if err != nil {
			return nil, err
		}
		tmp := rem.NewKVGetNodeResWithSmallfile(*file)
		ret = &tmp
	case proto.KVNodeType_Symlink:
		symlink, err := loadSmallFileOrSymlink(m, db, pid, nodeId, role)
		if err != nil {
			return nil, err
		}
		tmp := rem.NewKVGetNodeResWithSymlink(*symlink)
		ret = &tmp
	case proto.KVNodeType_File:
		hdr, err := loadLargeFileMetadata(m, db, pid, nodeId, role)
		if err != nil {
			return nil, err
		}
		tmp := rem.NewKVGetNodeResWithFile(*hdr)
		ret = &tmp
	case proto.KVNodeType_Dir:
		did, err := nodeId.ToDirID()
		if err != nil {
			return nil, err
		}
		dir, err := getDir(m, db, pid, role, *did)
		if err != nil {
			return nil, err
		}
		tmp := rem.NewKVGetNodeResWithDir(*dir)
		ret = &tmp
	}
	return ret, nil
}

func mLoadSmallFilesOrSymlinks(
	m shared.MetaContext,
	db *pgxpool.Conn,
	pid proto.PartyID,
	keys []proto.KVNodeID,
	role proto.Role,
	failOnPermError bool,
) (
	[]*proto.SmallFileBox,
	error,
) {

	nodeIDs := core.Map(keys, func(v proto.KVNodeID) []byte { return v.ExportToDB() })

	rows, err := db.Query(
		m.Ctx(),
		`SELECT ptk_gen, box, read_role_type, read_role_viz_level, node_id
		FROM small_file_or_symlink
		WHERE short_host_id=$1 AND short_party_id=$2 AND node_id = ANY($3)`,
		int(m.ShortHostID()), pid.Shorten().ExportToDB(), nodeIDs,
	)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tab := make(map[proto.KVNodeID]*proto.SmallFileBox)

	for rows.Next() {
		var g int
		var box []byte
		var rt, vl int
		var nodeIdRaw []byte

		err := rows.Scan(&g, &box, &rt, &vl, &nodeIdRaw)
		if err != nil {
			return nil, err
		}
		var fileRole proto.Role
		err = fileRole.ImportFromDB(rt, vl)
		if err != nil {
			return nil, err
		}

		err = assertAtOrAbove(role, fileRole, proto.KVOp_Read, proto.KVNodeType_File)
		if err != nil {
			if failOnPermError {
				return nil, err
			}
			continue
		}

		item := proto.SmallFileBox{
			Rg: proto.RoleAndGen{
				Role: fileRole,
				Gen:  proto.Generation(g),
			},
		}
		err = item.DataBox.ImportFromDB(box)
		if err != nil {
			return nil, err
		}
		var key proto.KVNodeID
		err = key.ImportFromDB(nodeIdRaw)
		if err != nil {
			return nil, err
		}
		tab[key] = &item
	}
	ret := make([]*proto.SmallFileBox, 0, len(keys))
	for _, v := range keys {
		ret = append(ret, tab[v])
	}
	return ret, nil
}

func loadSmallFileOrSymlink(
	m shared.MetaContext,
	db *pgxpool.Conn,
	pid proto.PartyID,
	nodeId proto.KVNodeID,
	role proto.Role,
) (
	*proto.SmallFileBox,
	error,
) {
	ret, err := mLoadSmallFilesOrSymlinks(m, db, pid, []proto.KVNodeID{nodeId}, role, true)
	if err != nil {
		return nil, err
	}
	if len(ret) != 1 {
		return nil, core.NotFoundError("small file")
	}
	return ret[0], nil
}
