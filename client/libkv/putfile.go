// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libkv

import (
	"fmt"
	"io"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/kv"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"golang.org/x/crypto/nacl/secretbox"
)

func (k *Minder) prepSmallFile(
	m MetaContext,
	kvp *KVParty,
	data lcl.SmallFileData,
	rp *proto.RolePair,
) (
	*proto.KVNodeID,
	func(m MetaContext) error,
	error,
) {
	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, nil, err
	}
	key, gen, err := kvp.kvStoreKeyCurrent(m, rp.Read)
	if err != nil {
		return nil, nil, err
	}

	nid, err := newNodeID(proto.KVNodeType_SmallFile)
	if err != nil {
		return nil, nil, err
	}
	sfid, err := nid.ToSmallFileID()
	if err != nil {
		return nil, nil, err
	}

	payload := lcl.NewSmallFileBoxPayloadWithSmallfile(data)

	ctext, err := key.BoxPaddedWithNonce(&payload, nid.NaclNonce())
	if err != nil {
		return nil, nil, err
	}

	sfb := proto.SmallFileBox{
		Rg:      proto.RoleAndGen{Role: rp.Read, Gen: gen},
		DataBox: ctext,
	}

	err = cli.KvPutSmallFileOrSymlink(m.Ctx(), rem.KvPutSmallFileOrSymlinkArg{
		Auth: *auth,
		Id:   *nid,
		Sfb:  sfb,
	})
	if err != nil {
		return nil, nil, err
	}
	cachePut := func(m MetaContext) error {
		return kvp.caches.smallFile.Put(m, *sfid, sfb, &data)
	}

	return nid, cachePut, err
}

func (k *Minder) prepSymlink(
	m MetaContext,
	kvp *KVParty,
	path proto.KVPath,
	rp *proto.RolePair,
) (
	*proto.KVNodeID,
	func(m MetaContext) error,
	error,
) {
	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, nil, err
	}
	key, gen, err := kvp.kvStoreKeyCurrent(m, rp.Read)
	if err != nil {
		return nil, nil, err
	}

	nid, err := newNodeID(proto.KVNodeType_Symlink)
	if err != nil {
		return nil, nil, err
	}
	sid, err := nid.ToSymlinkID()
	if err != nil {
		return nil, nil, err
	}

	pyld := lcl.NewSmallFileBoxPayloadWithSymlink(path)

	ctext, err := key.BoxPaddedWithNonce(&pyld, nid.NaclNonce())
	if err != nil {
		return nil, nil, err
	}

	sfb := proto.SmallFileBox{
		Rg:      proto.RoleAndGen{Role: rp.Read, Gen: gen},
		DataBox: ctext,
	}

	err = cli.KvPutSmallFileOrSymlink(m.Ctx(), rem.KvPutSmallFileOrSymlinkArg{
		Auth: *auth,
		Id:   *nid,
		Sfb:  sfb,
	})
	if err != nil {
		return nil, nil, err
	}
	ppath, err := kv.ParsePath(path)
	if err != nil {
		return nil, nil, err
	}
	cacheVal := Symlink{
		Path: *ppath,
		Raw:  path,
	}
	cachePut := func(m MetaContext) error {
		return kvp.caches.symlink.Put(m, *sid, sfb, &cacheVal)
	}

	return nid, cachePut, err
}

func (k *Minder) putSymlink(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	target proto.KVPath,
) (*PutFileRes, error) {
	return k.putFile(m, cfg, path,
		func(kvp *KVParty, rp *proto.RolePair) (*proto.KVNodeID, func(m MetaContext) error, error) {
			return k.prepSymlink(m, kvp, target, rp)
		},
	)
}

type PutFileOpts struct {
	Version *proto.KVVersion // Assert existing version.
}

func (k *Minder) putSmallFile(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	data lcl.SmallFileData,
) (*PutFileRes, error) {
	return k.putFile(m, cfg, path,
		func(kvp *KVParty, rp *proto.RolePair) (*proto.KVNodeID, func(m MetaContext) error, error) {
			return k.prepSmallFile(m, kvp, data, rp)
		},
	)
}

type PutFileRes struct {
	NodeID proto.KVNodeID
	Dirent *Dirent
}

func (k *Minder) putFile(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	prep func(kvp *KVParty, rp *proto.RolePair) (*proto.KVNodeID, func(m MetaContext) error, error),
) (
	*PutFileRes,
	error,
) {

	kvp, rp, err := k.initReqWrite(m, cfg)
	if err != nil {
		return nil, err
	}

	pap, err := kv.ParseAbsPath(path)
	if err != nil {
		return nil, err
	}

	if pap.TrailingSlash {
		return nil, core.BadArgsError("trailing slash")
	}

	parentDir, file, err := pap.Split()
	if err != nil {
		return nil, err
	}

	var ret *PutFileRes
	err = k.retryCacheLoop(m, kvp, func(m MetaContext) error {

		dp, err := k.walkFromRoot(m, kvp, parentDir, walkOpts{mkdirP: cfg.MkdirP, writePerms: rp})
		if err != nil {
			return err
		}
		if dp.dir == nil {
			return core.InternalError("unexpected nil directory")
		}

		newFileID, cacheFn, err := prep(kvp, rp)
		if err != nil {
			return err
		}
		lno := linkNodeOpts{perms: *rp, overwriteOk: cfg.OverwriteOk, direntVers: cfg.AssertVersion}
		de, err := k.linkNode(m, kvp, dp.dir, file, *newFileID, lno)
		if err != nil {
			return err
		}
		if cacheFn != nil {
			err = cacheFn(m)
			if err != nil {
				return err
			}
		}
		ret = &PutFileRes{
			NodeID: *newFileID,
			Dirent: de,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func chunkNonce(
	fid proto.FileID,
	offset proto.Offset,
	isFinal bool,
) (
	*[24]byte,
	error,
) {
	pld := lcl.ChunkNoncePayload{
		Id:     fid,
		Offset: offset,
		Final:  isFinal,
	}
	hsh, err := core.PrefixedHash(&pld)
	if err != nil {
		return nil, err
	}
	var ret [24]byte
	copy(ret[:], (*hsh)[0:24])
	return &ret, nil
}

func boxChunk(
	fks *proto.FileKeySeed,
	chnk proto.ChunkPlaintext,
	fid proto.FileID,
	offset proto.Offset,
	isFinal bool,
	sz proto.Size,
) (
	*proto.UploadChunk,
	proto.Size,
	error,
) {
	nn, err := chunkNonce(fid, offset, isFinal)
	if err != nil {
		return nil, 0, err
	}
	raw, err := core.EncodeToBytes(&chnk)
	if err != nil {
		return nil, 0, err
	}
	padded, err := kv.PadChunk(raw)
	if err != nil {
		return nil, 0, err
	}
	ctext := proto.NaclCiphertext(
		secretbox.Seal(nil, padded, nn, (*[32]byte)(fks)),
	)
	sz += proto.Size(len(ctext))
	ret := &proto.UploadChunk{
		Data:   ctext,
		Offset: offset,
	}
	if isFinal {
		ret.Final = &proto.UploadFinal{
			Sz: sz,
		}
	}
	return ret, sz, nil
}

func (k *Minder) PutFileFirst(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	data []byte,
	isFinal bool,
) (
	*PutFileRes,
	error,
) {
	if len(data)+kv.SmallFileOverhead <= kv.SmallFileSize {
		return k.putSmallFile(m, cfg, path, lcl.SmallFileData(data))
	}

	f := func(kvp *KVParty, rp *proto.RolePair) (*proto.KVNodeID, func(m MetaContext) error, error) {

		auth, cli, err := k.client(m, kvp)
		if err != nil {
			return nil, nil, err
		}
		key, gen, err := kvp.kvStoreKeyCurrent(m, rp.Read)
		if err != nil {
			return nil, nil, err
		}

		nid, err := newNodeID(proto.KVNodeType_File)
		if err != nil {
			return nil, nil, err
		}

		var fks proto.FileKeySeed
		err = core.RandomFill(fks[:])
		if err != nil {
			return nil, nil, err
		}

		fid, err := nid.ToFileID()
		if err != nil {
			return nil, nil, err
		}
		vers := proto.KVVersion(1)

		pld := lcl.FileKeyBoxPayload{
			Id:   *fid,
			Vers: vers,
			Seed: fks,
		}

		ctext, err := key.Box(&pld)
		if err != nil {
			return nil, nil, err
		}

		md := proto.LargeFileMetadata{
			Rg: proto.RoleAndGen{
				Role: rp.Read,
				Gen:  gen,
			},
			KeySeed: *ctext,
			Vers:    vers,
		}

		ulc, sz, err := boxChunk(&fks, data, *fid, 0, isFinal, 0)
		if err != nil {
			return nil, nil, err
		}

		arg := rem.KvFileUploadInitArg{
			Auth:   *auth,
			FileID: *fid,
			Md:     md,
			Chunk:  *ulc,
		}
		err = cli.KvFileUploadInit(m.Ctx(), arg)
		if err != nil {
			return nil, nil, err
		}

		// Cache the result in case we decide to fetch it again soon.
		cacheFn := func(m MetaContext) error {
			err = kvp.caches.lfmd.Put(m, *fid, md, &fks)
			if err != nil {
				return err
			}
			return nil
		}

		// Cache the upload state for continued chunk puts. We might consider
		// doing this persistently to resume uploads after a restart, but for now,
		// do the simple thing.
		if !isFinal {
			kvp.caches.upload[*fid] = &fileUploadState{
				fks: &fks,
				off: proto.Offset(len(data)),
				sz:  sz,
			}
		}
		return nid, cacheFn, nil
	}

	return k.putFile(m, cfg, path, f)
}

func (k *Minder) PutFileChunk(
	m MetaContext,
	cfg lcl.KVConfig,
	id proto.FileID,
	data proto.ChunkPlaintext,
	offset proto.Offset,
	final bool,
) error {
	kvp, _, err := k.initReqWrite(m, cfg)
	if err != nil {
		return nil
	}

	us := kvp.caches.upload[id]
	if us == nil {
		return core.NotFoundError("upload state")
	}

	us.Lock()
	defer us.Unlock()

	if us.off != offset {
		return core.UploadError("offset mismatch")
	}

	ulc, sz, err := boxChunk(us.fks, data, id, offset, final, us.sz)
	if err != nil {
		return err
	}

	us.sz = sz
	us.off += proto.Offset(len(data))

	auth, client, err := k.client(m, kvp)
	if err != nil {
		return err
	}

	arg := rem.KvFileUploadChunkArg{
		Auth:   *auth,
		FileID: id,
		Chunk:  *ulc,
	}

	start := time.Now()
	err = client.KvFileUploadChunk(m.Ctx(), arg)
	if err != nil {
		return err
	}
	end := time.Now()
	dur := end.Sub(start)
	rate := fmt.Sprintf("%.5f", float64(len(data))/1000000/dur.Seconds())
	m.Infow("PutFileChunk", "duration", dur, "size", len(data), "rate-M/sec",
		rate)

	cacheEntry := rem.GetEncryptedChunkRes{
		Offset: ulc.Offset,
		Chunk:  proto.Chunk(ulc.Data),
		Final:  final,
	}

	err = kvp.caches.lfch.Put(m, ChunkIndex{FileID: id, Offset: offset}, cacheEntry, nil)
	if err != nil {
		return err
	}

	return nil
}

// PutFile is called from the CLI to chunk over the local agent bridge, and also internally for
// git purposes. It always writes a first chunk and maybe subsequent chunks for bigger files.
// Small files are guaranteed to fix into one chunk, but the converse is not true. That is,
// some single-chunk files may be bigger than the small file size.
func PutFile(
	rdr io.Reader,
	putFirst func(data []byte, isFinal bool) (proto.KVNodeID, error),
	putChunk func(id proto.FileID, data []byte, offset proto.Offset, final bool) error,
	chnkSz int,
) error {
	if chnkSz > kv.MaxInputFileChunkSize {
		return core.InternalError("chunk size too big")
	}
	if chnkSz == 0 {
		chnkSz = kv.MaxInputFileChunkSize
	}
	if chnkSz <= kv.SmallFileSize {
		return core.InternalError("chunk size too small, must be greater than small file")
	}

	buf := make([]byte, chnkSz)

	// If we read 2048 bytes or less, we'll get back io.ErrUnexpectedEOF, which is
	// fine, that just means we're only going to deliver 1 chunk.
	n, err := io.ReadFull(rdr, buf)
	var final bool

	if err == io.ErrUnexpectedEOF || err == io.EOF {
		final = true
	} else if err != nil {
		return err
	}

	offset := proto.Offset(n)

	res, err := putFirst(buf[0:n], final)
	if err != nil {
		return err
	}

	if final {
		return nil
	}

	// This will fail for small files, but we'll never have
	// a small file that has subsequent chunks.
	fid, err := res.ToFileID()
	if err != nil {
		return err
	}

	for !final {
		n, err := io.ReadFull(rdr, buf)
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			final = true
		} else if err != nil {
			return err
		}
		err = putChunk(*fid, buf[0:n], offset, final)
		if err != nil {
			return err
		}
		offset += proto.Offset(n)
	}
	return nil
}
