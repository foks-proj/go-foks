// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libkv

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/kv"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type mover struct {
	path    proto.KVPath
	pap     *kv.ParsedPath
	de      *lookupDirentRes
	symlink *Dirent
	typ     proto.KVNodeType
	srcLeaf proto.KVPathComponent
}

func (k *Minder) prepareMovePath(
	m MetaContext,
	kvp *KVParty,
	src proto.KVPath,
	wo walkOpts,
) (
	*mover,
	error,
) {
	pap, err := kv.ParseAbsPath(src)
	if err != nil {
		return nil, err
	}
	_, leaf, err := pap.Split()
	if err != nil {
		return nil, err
	}

	wres, err := k.walkFromRoot(m, kvp, pap, wo)
	if err != nil {
		return nil, err
	}

	if wres.lde == nil {
		return nil, core.KVNoentError{Path: src}
	}

	de := wres.lde

	ret := mover{
		path:    src,
		pap:     pap,
		srcLeaf: leaf,
		de:      de,
		symlink: wres.symlink,
	}

	if de.found != nil {
		typ, err := de.found.Value.Type()
		if err != nil {
			return nil, err
		}
		ret.typ = typ

		if pap.TrailingSlash && typ != proto.KVNodeType_Dir && typ != proto.KVNodeType_None {
			return nil, core.KVPathError("trailing slash on non-directory")
		}
	}

	return &ret, nil
}

func (k *Minder) Mv(
	m MetaContext,
	cfg lcl.KVConfig,
	srcPath proto.KVPath,
	dstPath proto.KVPath,
) error {
	kvp, rp, err := k.initReqWrite(m, cfg)
	if err != nil {
		return err
	}
	return k.retryCacheLoop(m, kvp, func(m MetaContext) error {
		return k.mvInner(m, cfg, srcPath, dstPath, kvp, rp)
	})
}

func (k *Minder) mvInner(
	m MetaContext,
	cfg lcl.KVConfig,
	srcPath proto.KVPath,
	dstPath proto.KVPath,
	kvp *KVParty,
	rp *proto.RolePair,
) error {

	src, err := k.prepareMovePath(m, kvp, srcPath, walkOpts{mvSrc: true, writePerms: rp})
	if err != nil {
		return err
	}
	if src.de.found == nil || src.typ == proto.KVNodeType_None {
		return core.KVNoentError{Path: srcPath}
	}

	dst, err := k.prepareMovePath(m, kvp, dstPath, walkOpts{mvDst: true, writePerms: rp})
	if err != nil {
		return err
	}

	val := src.de.found.Value
	tmp, err := src.de.found.edit(m, Tombstone(), linkNodeOpts{perms: *rp}, src.de.newKb)
	if err != nil {
		return err
	}
	edits := []*Dirent{tmp}

	dlno := linkNodeOpts{perms: *rp, overwriteOk: cfg.OverwriteOk}

	switch {
	case dst.typ == proto.KVNodeType_None:

		de := core.Or(dst.de.found, dst.de.templ)
		// Should never happen
		if de == nil {
			return core.InternalError("templ and found were both nil")
		}

		tmp, err := de.edit(m, val, dlno, dst.de.newKb)
		if err != nil {
			return err
		}
		edits = append(edits, tmp)

	case dst.de.found != nil && dst.typ == proto.KVNodeType_Dir:

		dir, err := k.loadDir(m, kvp, dst.de.found.Value)
		if err != nil {
			return err
		}
		target, err := k.lookupDirent(m, kvp, dir, src.srcLeaf, lookupDirentOpts{forPut: true})
		if err != nil {
			return err
		}

		de := core.Or(target.found, target.templ)

		tmp, err := de.edit(m, val, dlno, target.newKb)
		if err != nil {
			return err
		}
		edits = append(edits, tmp)

	case (dst.symlink != nil || dst.de.found != nil) && dst.typ != proto.KVNodeType_Dir:

		// Cannot overwrite a file with a directory
		if src.typ == proto.KVNodeType_Dir {
			return core.KVNeedDirError{}
		}

		de := core.Or(dst.symlink, dst.de.found)

		tmp, err := de.edit(m, val, dlno, dst.de.newKb)
		if err != nil {
			return err
		}
		edits = append(edits, tmp)

	default:
		return core.InternalError("unexpected case")
	}

	err = k.putDirent(m, kvp, edits)
	if err != nil {
		return err
	}

	return nil
}
