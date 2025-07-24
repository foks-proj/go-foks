// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libkv

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/kv"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type walkRes struct {
	dir     *DirPair         // if ending at a directory
	leaf    *proto.KVNodeID  // if ending at a file or symlink
	lde     *lookupDirentRes // if ending at a dirent (for mv)
	symlink *Dirent          // This pointed to the final lde, we might need it in some cases
	de      *Dirent          // dirent returned for stat calls (and regular GetFile's)
}

type walkOpts struct {
	mkdirP         bool            // if true, can create all parent dirs; needs writePerms != nil
	writePerms     *proto.RolePair // if true, can create dirs with these write perms
	needCreate     bool            // a mkdir must make a directory at the leaf (but a PutFile need not)
	endAtFile      bool            // on if a walk needs to end at a file
	readlink       bool            // for a readlink call, we don't follow the last component if it's a symlink
	mvSrc          bool            // walk down to a source for a mv operation
	mvDst          bool            // walk down to a target for a mv operation
	stat           bool            // walk down for a stat call; if ending a dir, don't open the dir, just return the dirent
	unlink         bool            // walk down for an unlink; can't end at a dir or somethhing not there
	writePermsRoot *proto.RolePair // if non-nil, we can create root with these write perms

}

func (wo walkOpts) forLast(last bool) walkOpts {
	ret := walkOpts{
		endAtFile: (last && wo.endAtFile),
		readlink:  (last && wo.readlink),
		mvSrc:     (last && wo.mvSrc),
		mvDst:     (last && wo.mvDst),
		stat:      (last && wo.stat),
		unlink:    (last && wo.unlink),
	}
	if wo.writePerms != nil && (wo.mkdirP || last) {
		ret.writePerms = wo.writePerms
	}
	return ret
}

func (k *Minder) walk(
	m MetaContext,
	kvp *KVParty,
	wd walkStackFrame,
	path []proto.KVPathComponent,
	wo walkOpts,
) (
	*walkRes,
	error,
) {
	stk := []walkStackFrame{wd}
	maxDepth := kv.MaxPathLength
	var lastWres *walkOneRes
	var lastSymlink *Dirent

	for i := 0; i < maxDepth && len(path) > 0; i++ {

		last := (len(path) == 1)
		tmpOpts := wo.forLast(last)

		wres, err := k.walkOne(m, kvp, stk, path, tmpOpts)
		if err != nil {
			return nil, err
		}

		// special case! if we're looking up for a move destination, and we're at the end of the path,
		// and the penultimate component was a symlink, we might need to overwite the symlink! So we
		// need to hang onto it below. Note, we only hang onto it the first time! If /a/b/c -> /d/e/f -> /x/y/z,
		// all we really need is c, since either we're going to follow that to a directory, or we're going to
		// overwrite it with a new file.
		if lastWres != nil && lastSymlink == nil && lastWres.symlink != nil {
			lastSymlink = lastWres.symlink
		}

		path = wres.path
		lastWres = wres
		stk = wres.stk
	}

	var dp *DirPair
	if len(stk) > 0 {
		dp = core.Last(stk).dir
	}

	switch {
	case len(path) > 0:
		return nil, core.KVPathTooDeepError{}
	case lastWres != nil && lastWres.leaf != nil && (wo.endAtFile || wo.readlink):
		return &walkRes{leaf: lastWres.leaf, de: lastWres.de}, nil
	case lastWres != nil && (wo.mvSrc || wo.mvDst || wo.unlink):
		return &walkRes{lde: lastWres.lde, symlink: lastSymlink}, nil
	case wo.stat:
		ret := walkRes{dir: dp}
		if lastWres != nil {
			ret.de = lastWres.de
			ret.leaf = lastWres.leaf
		}
		if ret.leaf == nil && len(stk) > 0 {
			ret.de = core.Last(stk).de
		}
		return &ret, nil
	case dp == nil:
		return nil, core.KVPathError("empty dir stack")
	case wo.needCreate && (lastWres == nil || !lastWres.didMkdir):
		return nil, core.KVExistsError{}
	default:
		return &walkRes{dir: dp}, nil
	}
}

// walkFromRoot down the absolute path from the root to the leaf. If writePerms != nil, we can
// create diretories as we go with the given permissions write/read permissions.
func (k *Minder) walkFromRoot(
	m MetaContext,
	kvp *KVParty,
	pap *kv.ParsedPath,
	wo walkOpts,
) (
	*walkRes,
	error,
) {
	root, err := k.getRoot(m, kvp)
	if err != nil {
		return nil, err
	}

	var wd *DirPair

	switch {
	case root == nil && wo.writePermsRoot != nil:
		wd, err = k.mkRoot(m, kvp, *wo.writePermsRoot)
		if err != nil {
			return nil, err
		}
	case root != nil:
		wd, err = k.loadDirWithDirID(m, kvp, root.Root)
		if err != nil {
			return nil, err
		}
	default:
		return nil, core.KVNoentError{Path: "/"}
	}

	if wd == nil {
		return nil, core.InternalError("wd was nil, not expected")
	}
	wd.IsRoot = true

	return k.walk(m, kvp, walkStackFrame{dir: wd}, pap.Components, wo)
}

type walkOneRes struct {
	stk      []walkStackFrame
	path     []proto.KVPathComponent
	leaf     *proto.KVNodeID
	lde      *lookupDirentRes
	symlink  *Dirent
	didMkdir bool
	de       *Dirent
}

type walkStackFrame struct {
	dir *DirPair
	de  *Dirent
	nm  proto.KVPathComponent // the plaintext name of the path component, for error messages
}

func (k *Minder) walkOne(
	m MetaContext,
	kvp *KVParty,
	stk []walkStackFrame,
	path []proto.KVPathComponent,
	opts walkOpts,
) (
	*walkOneRes,
	error,
) {

	if len(path) == 0 {
		return nil, core.InternalError("empty path")
	}
	if len(stk) == 0 {
		return nil, core.InternalError("empty dir stack")
	}

	comp := path[0]
	rest := path[1:]
	wd := core.Last(stk)
	forPut := (opts.writePerms != nil)

	// explain where we are in the current path traversal, only used on errors
	currentPath := func() proto.KVPath {
		var comps []proto.KVPathComponent
		for _, frame := range stk {
			comps = append(comps, frame.nm)
		}
		comps = append(comps, comp)
		return proto.PathComponentJoinAbsolute(comps)
	}

	switch {
	case len(comp) == 0:
		return nil, core.InternalError("empty component")
	case comp == ".":
		if opts.endAtFile || opts.mvSrc || opts.unlink {
			return nil, core.KVNeedFileError{}
		}
		return &walkOneRes{stk: stk, path: rest}, nil
	case comp == "..":
		if len(stk) == 1 && !stk[0].dir.IsRoot {
			return nil, core.KVPathError("tried to go up from non-root")
		}
		if opts.endAtFile || opts.mvSrc || opts.unlink {
			return nil, core.KVNeedFileError{}
		}
		return &walkOneRes{stk: stk[:len(stk)-1], path: rest}, nil
	}

	lde, err := k.lookupDirent(m, kvp, wd.dir, comp, lookupDirentOpts{forPut: forPut})

	// If we get back a not-found error, and we're about to return it, and it
	// doesn't contain our current path, insert it back.
	if noEntErr, ok := err.(core.KVNoentError); ok && noEntErr.Path.IsEmpty() {
		noEntErr.Path = currentPath()
		err = noEntErr
	}

	if err != nil {
		return nil, err
	}

	var newDirent *Dirent
	var kb *kv.KeyBundle

	switch {

	// We didn't find a dirent, but we made a "template" for a new dirent
	// as a result of the failed lookup. No error in this case, it's expected.
	case lde.templ != nil:

		if opts.mvSrc || opts.unlink {
			return nil, core.KVNoentError{Path: proto.PathComponentJoin(path)}
		}

		if opts.mvDst {
			return &walkOneRes{lde: lde}, nil
		}

		newDirent = lde.templ
		kb = lde.newKb

	case lde.found == nil:
		return nil, core.InternalError("unexpected nil dirent")

	default:

		// The complicated case, we found a dirent. Might be any number of things,
		// so let's investigate further.
		found := lde.found
		typ, err := found.Type()
		if err != nil {
			return nil, err
		}

		// In the case of the source of a mv() operation, we always want the found
		// dirent and we don't care what it is (well, we do care if it's a None,
		// since that's an error). Buf it's a directory, for instance, no need to
		// investigate what's inside it.
		//
		// The other subcase to consider is that we're walking for a mvTarget,
		// and the last component is a file or directory. In the dir case, we'll load
		// the directory later to simplify code here. But if the last component is
		// a symlink, we need to resolve it, and overwrite what it points to in the
		// case of a file, or add to that directory in the case of a directory.
		if opts.mvSrc || opts.unlink || (opts.mvDst && typ != proto.KVNodeType_Symlink) {
			return &walkOneRes{lde: lde}, nil
		}

		switch typ {
		case proto.KVNodeType_Dir:
			// If another dir, that's not a problem, just extend our stack, and keep going.
			dir, err := k.loadDir(m, kvp, found.Value)
			if err != nil {
				return nil, err
			}
			if dir == nil {
				return nil, core.KVMkdirError("dir was nil")
			}
			if opts.endAtFile || opts.unlink {
				return nil, core.KVNeedFileError{}
			}
			stk = append(stk, walkStackFrame{dir: dir, de: found, nm: comp})
			return &walkOneRes{stk: stk, path: rest}, nil

		case proto.KVNodeType_None:
			// If it's a tombstoned dirent, then we can overwrite it without an issue.
			newDirent = found
			kb = lde.newKb

		case proto.KVNodeType_Symlink:
			if opts.readlink || opts.unlink {
				tmp := found.Value
				return &walkOneRes{leaf: &tmp, de: found, lde: lde}, nil
			}

			slp, err := k.loadSymlink(m, kvp, found.Value)
			if err != nil {
				return nil, err
			}
			if slp.sym.Path.LeadingSlash {
				root := stk[0]
				if !root.dir.IsRoot {
					return nil, core.KVPathError("cannot symlink back to root")
				}
				stk = stk[0:1]
			}
			biggerPath := append(slp.sym.Path.Components, rest...)

			// This is a funny case where we hold onto a symlink. We need different behavior
			// based on whether the symlink is pointing to a file or directory at the *end* of a
			// a target path. If pointing to a directory, we will create inside the linnked directory.
			// If pointing to a file, then we need to overwrite the symlink.
			symlink := core.Sel(opts.mvDst, lde.found, nil)

			return &walkOneRes{stk: stk, path: biggerPath, symlink: symlink, de: found}, nil

		case proto.KVNodeType_File, proto.KVNodeType_SmallFile:
			if opts.endAtFile || opts.stat {
				tmp := found.Value
				return &walkOneRes{leaf: &tmp, de: found}, nil
			}
			return nil, core.KVNeedDirError{}

		default:
			return nil, core.KVNeedDirError{}
		}
	}

	if newDirent == nil {
		return nil, core.InternalError("unexpected nil dirent")
	}
	if kb == nil {
		return nil, core.InternalError("unexpected nil key bundle")
	}

	if opts.writePerms == nil {
		// We walked off the end of the path and we weren't allowed to create a new directory
		return nil, core.KVNoentError{Path: proto.PathComponentJoin(path)}
	}

	newDir, _, err := k.makeEmptyDir(m, kvp, *opts.writePerms)
	if err != nil {
		return nil, err
	}

	// Next dirent is +1 the previous. Will be 1 for first version
	newDirent.Version++
	newNodeID := newDir.Id()
	newDirent.Value = *newNodeID.KVNodeID()
	newDirent.WriteRole = opts.writePerms.Write

	err = newDirent.mac(kb)
	if err != nil {
		return nil, err
	}

	err = k.putDirent(m, kvp, []*Dirent{newDirent})
	if err != nil {
		return nil, err
	}

	stk = append(stk, walkStackFrame{dir: newDir, de: newDirent, nm: comp})

	return &walkOneRes{stk: stk, path: rest, didMkdir: true}, nil
}
