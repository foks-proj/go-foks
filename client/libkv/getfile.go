// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libkv

import (
	"io"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/kv"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"golang.org/x/crypto/nacl/secretbox"
)

func (kvp *KVParty) unboxFileKeySeed(
	m MetaContext,
	id proto.FileID,
	md *proto.LargeFileMetadata,
) (
	*proto.FileKeySeed,
	error,
) {
	kb, err := kvp.kvStoreKeyAtRoleGen(m, md.Rg.Role, md.Rg.Gen)
	if err != nil {
		return nil, err
	}
	var pld lcl.FileKeyBoxPayload
	err = kb.Unbox(&pld, md.KeySeed)
	if err != nil {
		return nil, err
	}

	if !pld.Id.Eq(id) {
		return nil, core.ValidationError("file key seed id mismatch")
	}
	if md.Vers != pld.Vers {
		return nil, core.ValidationError("file key seed version mismatch")
	}
	return &pld.Seed, nil
}

func (kvp *KVParty) unboxSmallFile(
	m MetaContext,
	id proto.SmallFileID,
	sb proto.SmallFileBox,
) (
	lcl.SmallFileData,
	error,
) {
	sfb, err := kvp.unboxSmallFileOrSymlink(m, id.NaclNonce(), sb)
	if err != nil {
		return nil, err
	}
	typ, err := sfb.GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.KVNodeType_SmallFile {
		return nil, core.ValidationError("not a file")
	}
	dat := sfb.Smallfile()
	return dat, nil
}

type smallFilePackage struct {
	box  proto.SmallFileBox
	data lcl.SmallFileData
}

func (kvp *KVParty) getSmallFile(
	m MetaContext,
	id proto.SmallFileID,
) (
	*smallFilePackage,
	error,
) {
	enc, plain, err := kvp.caches.smallFile.Get(m, id)
	if err != nil {
		return nil, err
	}
	if plain != nil {
		return &smallFilePackage{data: *plain, box: *enc}, nil
	}
	if enc == nil {
		return nil, nil
	}
	sfd, err := kvp.unboxSmallFile(m, id, *enc)
	if err != nil {
		return nil, err
	}
	kvp.caches.smallFile.PutMem(id, enc, &sfd)
	return &smallFilePackage{data: sfd, box: *enc}, nil
}

func (k *Minder) GetFile(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
) (
	*lcl.GetFileRes,
	error,
) {
	kvp, err := k.initReq(m, cfg)
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
	var ret *lcl.GetFileRes
	err = k.retryCacheLoopWithOptions(
		m,
		kvp,
		kvRetryOptions{skipCacheCheck: cfg.SkipCacheCheck},
		func(m MetaContext) error {

			dp, err := k.walkFromRoot(m, kvp, pap, walkOpts{endAtFile: true})
			if err != nil {
				return err
			}
			if dp.de == nil {
				return core.InternalError("unexpected nil dirent")
			}
			if dp.leaf == nil {
				return core.InternalError("unexpected nil file")
			}
			tmp, err := k.getFileForNodeID(m, kvp, *dp.leaf)
			if err != nil {
				return err
			}
			ret = tmp
			ret.De = dp.de.KVDirent
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (k *Minder) getSmallFile(
	m MetaContext,
	kvp *KVParty,
	sfid proto.SmallFileID,
) (
	*smallFilePackage,
	error,
) {
	sfd, err := kvp.getSmallFile(m, sfid)
	if err != nil {
		return nil, err
	}
	if sfd != nil {
		return sfd, nil
	}
	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, err
	}
	res, err := cli.KvGetNode(m.Ctx(), rem.KvGetNodeArg{
		Auth: *auth,
		Id:   sfid.KVNodeID(),
	})
	if err != nil {
		return nil, err
	}
	typ, err := res.GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.KVNodeType_SmallFile {
		return nil, core.BadServerDataError("not a small file")
	}
	sfb := res.Smallfile()
	dat, err := kvp.unboxSmallFile(m, sfid, sfb)
	if err != nil {
		return nil, err
	}
	err = kvp.caches.smallFile.Put(m, sfid, sfb, &dat)
	if err != nil {
		return nil, err
	}
	return &smallFilePackage{box: sfb, data: dat}, nil
}

func (kvp *KVParty) getLargeFileMetadata(
	m MetaContext,
	fid proto.FileID,
) (
	*proto.LargeFileMetadata,
	*proto.FileKeySeed,
	error,
) {
	lfmd, seed, err := kvp.caches.lfmd.Get(m, fid)
	if err != nil {
		return nil, nil, err
	}
	if lfmd != nil && seed != nil {
		return lfmd, seed, nil
	}
	if lfmd == nil {
		return nil, nil, nil
	}
	seed, err = kvp.unboxFileKeySeed(m, fid, lfmd)
	if err != nil {
		return nil, nil, err
	}
	kvp.caches.lfmd.putMem(fid, *lfmd, seed)
	return lfmd, seed, nil
}

func (k *Minder) getFileMetadata(
	m MetaContext,
	kvp *KVParty,
	fid proto.FileID,
) (
	*proto.LargeFileMetadata,
	*proto.FileKeySeed,
	error,
) {
	lfmdp, seed, err := kvp.getLargeFileMetadata(m, fid)
	if err != nil {
		return nil, nil, err
	}
	if lfmdp != nil {
		return lfmdp, seed, nil
	}
	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, nil, err
	}

	res, err := cli.KvGetNode(m.Ctx(), rem.KvGetNodeArg{
		Auth: *auth,
		Id:   fid.KVNodeID(),
	})
	if err != nil {
		return nil, nil, err
	}
	typ, err := res.GetT()
	if err != nil {
		return nil, nil, err
	}
	if typ != proto.KVNodeType_File {
		return nil, nil, core.BadServerDataError("not a file")
	}
	lfmd := res.File()
	seed, err = kvp.unboxFileKeySeed(m, fid, &lfmd)
	if err != nil {
		return nil, nil, err
	}
	err = kvp.caches.lfmd.Put(m, fid, lfmd, seed)
	if err != nil {
		return nil, nil, err
	}
	return &lfmd, seed, nil
}

func (k *Minder) getLargeFileEncryptedChunk(
	m MetaContext,
	kvp *KVParty,
	fid proto.FileID,
	offset proto.Offset,
) (
	*rem.GetEncryptedChunkRes,
	error,
) {
	chnk, _, err := kvp.caches.lfch.Get(m, ChunkIndex{FileID: fid, Offset: offset})
	if err != nil {
		return nil, err
	}
	if chnk != nil {
		return chnk, nil
	}
	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, err
	}
	arg := rem.KvGetEncryptedChunkArg{
		Auth:   *auth,
		Id:     fid,
		Offset: offset,
	}
	res, err := cli.KvGetEncryptedChunk(m.Ctx(), arg)
	if err != nil {
		return nil, err
	}
	chnk = &res
	offset = res.Offset
	err = kvp.caches.lfch.Put(m, ChunkIndex{FileID: fid, Offset: offset}, res, nil)
	if err != nil {
		return nil, err
	}
	return chnk, nil
}

func (k *Minder) getLargeFileChunkAtOffsetWithSeed(
	m MetaContext,
	kvp *KVParty,
	fid proto.FileID,
	offset proto.Offset,
	seed *proto.FileKeySeed,
) (
	*lcl.GetFileChunkRes,
	error,
) {
	chnk, err := k.getLargeFileEncryptedChunk(m, kvp, fid, offset)
	if err != nil {
		return nil, err
	}
	nn, err := chunkNonce(fid, offset, chnk.Final)
	if err != nil {
		return nil, err
	}

	buf, ok := secretbox.Open(nil, chnk.Chunk, nn, (*[32]byte)(seed))
	if !ok {
		return nil, core.DecryptionError{}
	}
	var ret proto.ChunkPlaintext
	err = core.DecodeFromBytes(&ret, buf)
	if err != nil {
		return nil, err
	}

	if chnk.Offset < offset {
		return nil, core.InternalError("chunk offset less than requested offset")
	}
	diff := chnk.Offset - offset
	if int(diff) > len(ret) {
		return nil, core.InternalError("chunk runs out of bounds")
	}
	ret = ret[diff:]

	return &lcl.GetFileChunkRes{Chunk: ret, Final: chnk.Final}, nil
}

func (k *Minder) getLargeFileFirstChunk(
	m MetaContext,
	kvp *KVParty,
	fid proto.FileID,
) (
	*lcl.GetFileRes,
	error,
) {
	_, seed, err := k.getFileMetadata(m, kvp, fid)
	if err != nil {
		return nil, err
	}
	chunk, err := k.getLargeFileChunkAtOffsetWithSeed(m, kvp, fid, 0, seed)
	if err != nil {
		return nil, err
	}
	return &lcl.GetFileRes{
		Chunk: *chunk,
		Id:    &fid,
	}, nil
}

func (k *Minder) getFileForNodeID(
	m MetaContext,
	kvp *KVParty,
	nid proto.KVNodeID,
) (
	*lcl.GetFileRes,
	error,
) {
	typ, err := nid.Type()
	if err != nil {
		return nil, err
	}
	switch typ {
	case proto.KVNodeType_SmallFile:
		sfid, err := nid.ToSmallFileID()
		if err != nil {
			return nil, err
		}
		sfd, err := k.getSmallFile(m, kvp, *sfid)
		if err != nil {
			return nil, err
		}
		return &lcl.GetFileRes{
			Chunk: lcl.GetFileChunkRes{
				Chunk: proto.ChunkPlaintext(sfd.data),
				Final: true,
			},
		}, nil
	case proto.KVNodeType_File:
		fid, err := nid.ToFileID()
		if err != nil {
			return nil, err
		}
		return k.getLargeFileFirstChunk(m, kvp, *fid)
	default:
		return nil, core.KVTypeError("not a file")

	}
}

func (k *Minder) GetFileChunk(
	m MetaContext,
	cfg lcl.KVConfig,
	id proto.FileID,
	offset proto.Offset,
) (
	*lcl.GetFileChunkRes,
	error,
) {
	kvp, err := k.initReq(m, cfg)
	if err != nil {
		return nil, err
	}
	_, seed, err := k.getFileMetadata(m, kvp, id)
	if err != nil {
		return nil, err
	}
	return k.getLargeFileChunkAtOffsetWithSeed(m, kvp, id, offset, seed)
}

func GetFile(
	wr io.Writer,
	getFirst func() (lcl.GetFileRes, error),
	getNext func(proto.FileID, proto.Offset) (lcl.GetFileChunkRes, error),
) error {

	_, err := GetFileWithHeader(wr, getFirst, getNext)
	return err
}

func GetFileWithHeader(
	wr io.Writer,
	getFirst func() (lcl.GetFileRes, error),
	getNext func(proto.FileID, proto.Offset) (lcl.GetFileChunkRes, error),
) (
	*proto.KVDirent,
	error,
) {

	gfr, err := getFirst()
	if err != nil {
		return nil, err
	}
	offset, err := wr.Write(gfr.Chunk.Chunk)
	if err != nil {
		return nil, err
	}
	final := gfr.Chunk.Final

	for !final {
		gfcr, err := getNext(*gfr.Id, proto.Offset(offset))
		if err != nil {
			return nil, err
		}
		n, err := wr.Write(gfcr.Chunk)
		if err != nil {
			return nil, err
		}
		offset += n
		final = gfcr.Final
	}
	return &gfr.De, nil
}

func (k *Minder) GetFileWithHeader(
	mctx MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	wr io.Writer,
) (
	*proto.KVDirent,
	error,
) {
	return GetFileWithHeader(
		wr,
		func() (lcl.GetFileRes, error) {
			tmp, err := k.GetFile(
				mctx,
				cfg,
				path,
			)
			if err != nil {
				return lcl.GetFileRes{}, err
			}
			return *tmp, nil
		},
		func(id proto.FileID, offset proto.Offset) (lcl.GetFileChunkRes, error) {
			tmp, err := k.GetFileChunk(
				mctx,
				cfg,
				id,
				offset,
			)
			if err != nil {
				return lcl.GetFileChunkRes{}, err
			}
			return *tmp, nil
		},
	)

}
