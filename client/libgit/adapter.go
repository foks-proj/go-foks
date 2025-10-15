// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libgit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	remhelp "github.com/foks-proj/go-git-remhelp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage"
)

var rxx = regexp.MustCompile(`^[a-zA-Z0-9._-]*$`)

func IsValidRepoName(s string) bool {
	return rxx.MatchString(s)
}

func NormalizedRepoName(s string) (proto.GitRepo, error) {
	if !IsValidRepoName(s) {
		return "", core.NameError("invalid git repo name; must contain only letters, numbers, dots, underscores, and dashes")
	}
	return proto.GitRepo(strings.ToLower(s)), nil
}

type GitPath struct {
	repoName proto.GitRepo
}

func NewGitPath(r proto.GitRepo) GitPath {
	return GitPath{repoName: r}
}

var GitPathPrefix = []string{"app", "git"}

func (p GitPath) Prefix() []string {
	ret := append([]string{}, GitPathPrefix...)
	ret = append(ret, string(p.repoName))
	return ret
}

func (p GitPath) PrefixJoined() proto.KVPath {
	items := []string{proto.KVPathSeparator}
	items = append(items, p.Prefix()...)
	return proto.KVPathJoin(items...)
}

func (p GitPath) Path(file ...string) proto.KVPath {
	args := []string{proto.KVPathSeparator}
	args = append(args, p.Prefix()...)
	args = append(args, file...)
	return proto.KVPathJoin(args...)
}

func (p GitPath) RefsPath() proto.KVPath {
	return p.Path("refs")
}

func (p GitPath) Head() proto.KVPath {
	return p.Path("HEAD")
}

type adapter struct {
	fs         *libkv.Minder
	g          *libclient.GlobalContext
	auOverride *libclient.UserContext
	actingAs   *proto.FQTeamParsed
	repoName   proto.GitRepo
	gitpath    GitPath
	opts       StorageOpts
}

func newAdapter(
	g *libclient.GlobalContext,
	fs *libkv.Minder,
	auOverride *libclient.UserContext,
	actingAs *proto.FQTeamParsed,
	repoName proto.GitRepo,
	opts StorageOpts,
) *adapter {
	return &adapter{
		fs:         fs,
		g:          g,
		auOverride: auOverride,
		actingAs:   actingAs,
		repoName:   repoName,
		gitpath: GitPath{
			repoName: repoName,
		},
		opts: opts,
	}
}

func (a *adapter) module(
	module proto.GitRepo,
) *adapter {
	return newAdapter(a.g, a.fs, a.auOverride, a.actingAs, a.gitpath.repoName.Module(string(module)), a.opts)
}

func (a *adapter) objectPath(hash plumbing.Hash) proto.KVPath {
	return a.gitpath.Path("objects", hash.String())
}

func (a *adapter) remoteRepoID(ctx context.Context) (*proto.GitRemoteRepoID, error) {
	mctx, cfg := a.initOpWithContext(ctx)
	st, err := a.fs.Stat(mctx, cfg, a.gitpath.PrefixJoined())
	if err != nil {
		return nil, err
	}
	did, err := st.De.Value.ToDirID()
	if err != nil {
		return nil, err
	}
	hid, err := a.fs.HostID(mctx, cfg)
	if err != nil {
		return nil, err
	}
	return &proto.GitRemoteRepoID{
		Host: *hid,
		Dir:  *did,
	}, nil
}

func (a *adapter) initOp() (
	libkv.MetaContext,
	lcl.KVConfig,
) {
	return a.initOpWithContext(context.Background())
}

func (a *adapter) initOpWithContext(
	ctx context.Context,
) (
	libkv.MetaContext,
	lcl.KVConfig,
) {
	cfg := lcl.KVConfig{
		ActingAs: a.actingAs,
	}
	mctx := libkv.NewMetaContext(libclient.NewMetaContext(context.Background(), a.g))
	if a.auOverride != nil {
		mctx = mctx.SetActiveUser(a.auOverride)
	}
	return mctx, cfg
}

type readerWithBonusByte struct {
	r    io.Reader
	done bool
	val  byte
}

func (r *readerWithBonusByte) Read(p []byte) (int, error) {
	if r.done {
		return r.r.Read(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.val
	r.done = true

	// See issue-219; note that if the blob we are reading is empty,
	// we'll get ret=0, err=EOF. We can't error out here, we still
	// need to return the one byte we have. Thus we update ret
	// in the EOF case as well as the non-error case.
	ret, err := r.r.Read(p[1:])
	if err == nil || errors.Is(err, io.EOF) {
		ret += 1
	}
	return ret, err
}

var _ io.Reader = (*readerWithBonusByte)(nil)

func (a *adapter) putDataToPath(ctx context.Context, p string, rdr io.Reader) error {
	mctx, cfg := a.initOpWithContext(ctx)
	cfg.MkdirP = true
	cfg.OverwriteOk = true
	path := a.gitpath.Path(p)
	return a.putFile(mctx, cfg, path, rdr)
}

func (a *adapter) pushEncodedObject(ctx context.Context, obj plumbing.EncodedObject) (plumbing.Hash, error) {

	path := a.objectPath(obj.Hash())

	rdr, err := obj.Reader()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	defer rdr.Close()

	rbb := readerWithBonusByte{r: rdr, val: byte(obj.Type())}

	mctx, cfg := a.initOp()
	mctx.Infow("pushEncodedObject", "path", path, "sz", obj.Size())
	cfg.MkdirP = true
	cfg.OverwriteOk = true

	err = a.putFile(mctx, cfg, path, &rbb)
	mctx.Infow("pushEncodedObject", "path", path, "err", err)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	return obj.Hash(), nil
}

type writerOneByteHeader struct {
	w    io.Writer
	done bool
	val  byte
}

func (w *writerOneByteHeader) Write(p []byte) (int, error) {
	if w.done {
		return w.w.Write(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	w.val = p[0]
	w.done = true
	ret, err := w.w.Write(p[1:])
	if err != nil {
		return ret, err
	}
	return 1 + ret, nil
}

func (a *adapter) getDataFromPath(
	ctx context.Context,
	p string,
	wr io.Writer,
) error {
	mctx, cfg := a.initOpWithContext(ctx)
	path := a.gitpath.Path(p)
	_, err := a.getFile(mctx, cfg, path, wr)
	if err != nil {
		return err
	}
	return nil
}

var _ io.Writer = (*writerOneByteHeader)(nil)

func (a *adapter) getFile(
	mctx libkv.MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	wr io.Writer,
) (
	*proto.KVDirent,
	error,
) {
	return a.fs.GetFileWithHeader(mctx, cfg, path, wr)
}

func (a *adapter) fetchEncodedObject(
	ctx context.Context,
	typ plumbing.ObjectType,
	hsh plumbing.Hash,
) (plumbing.EncodedObject, error) {

	path := a.objectPath(hsh)

	mctx, cfg := a.initOp()
	mctx.Infow("fetchEncodedObject", "path", path)

	var ret plumbing.MemoryObject
	wr, err := ret.Writer()
	if err != nil {
		return nil, err
	}

	// Strip the first byte off since it's the type byte that we squirreled in there
	wr1 := writerOneByteHeader{w: wr}

	// If it's a successful read, no need to check that the cache is stale (since objects are immutable)
	cfg.SkipCacheCheck = true

	_, err = a.getFile(mctx, cfg, path, &wr1)
	if core.IsKVNoentError(err) {
		return nil, plumbing.ErrObjectNotFound
	}
	if err != nil {
		return nil, err
	}

	if typ == plumbing.AnyObject {
		typ = plumbing.ObjectType(wr1.val)
	}
	ret.SetType(typ)

	return &ret, nil
}

func (a *adapter) statEncodedObject(
	ctx context.Context,
	hsh plumbing.Hash,
) (*lcl.KVStat, error) {
	path := a.objectPath(hsh)
	mctx, cfg := a.initOp()
	mctx.Infow("statEncodedObject", "path", path)
	res, err := a.fs.Stat(mctx, cfg, path)
	mctx.Infow("statEncodedObject", "path", path, "err", err)
	if core.IsKVNoentError(err) {
		return nil, plumbing.ErrObjectNotFound
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

type objectIter struct {
	a        *adapter
	buf      []plumbing.Hash
	ptr      int
	typ      plumbing.ObjectType
	path     proto.KVPath
	nxt      *lcl.KVListNext
	pageSize uint64
	started  bool
}

func (o *objectIter) load(ents []lcl.KVListEntry) error {
	if o.ptr >= len(o.buf) {
		o.ptr = 0
		o.buf = nil
	}
	tmp := make([]plumbing.Hash, 0, len(ents))
	for _, e := range ents {
		nm := string(e.Name)
		if plumbing.IsHash(nm) {
			o.buf = append(o.buf, plumbing.NewHash(nm))
		}
	}
	o.buf = append(o.buf, tmp...)
	return nil
}

func (o *objectIter) refresh(ctx context.Context) error {
	// more in buffer, all good
	if o.ptr < len(o.buf) {
		return nil
	}
	if o.nxt == nil && o.started {
		return io.EOF
	}
	o.started = true
	mctx, cfg := o.a.initOpWithContext(ctx)
	nxt := proto.NewKVListPaginationWithNone()
	var dirID *proto.DirID
	if o.nxt != nil {
		nxt = o.nxt.Nxt
		dirID = &o.nxt.Id
	}
	opts := rem.KVListOpts{
		Start: nxt,
		Num:   o.pageSize,
	}
	tmp, err := o.a.fs.List(mctx, cfg, o.path, dirID, opts)
	if err != nil {
		return err
	}
	err = o.load(tmp.Ents)
	if err != nil {
		return err
	}
	o.nxt = tmp.Nxt
	return nil
}

func (o *objectIter) Next() (plumbing.EncodedObject, error) {
	ctx := context.Background()
	for {
		obj, err := o.nextAny(ctx)
		if err != nil {
			return nil, err
		}
		if obj.Type() == o.typ || o.typ == plumbing.AnyObject {
			return obj, nil
		}
	}
}

func (o *objectIter) nextAny(ctx context.Context) (plumbing.EncodedObject, error) {
	err := o.refresh(ctx)
	if err != nil {
		return nil, err
	}
	if o.ptr >= len(o.buf) {
		return nil, core.InternalError("empty after sucessful refresh")
	}
	hsh := o.buf[o.ptr]
	o.ptr++

	obj, err := o.a.fetchEncodedObject(ctx, plumbing.AnyObject, hsh)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func (o *objectIter) ForEach(f func(plumbing.EncodedObject) error) error {
	return storer.ForEachIterator(o, f)
}

func (o *objectIter) Close() {
}

var _ storer.EncodedObjectIter = (*objectIter)(nil)

func (a *adapter) openObjectIter(
	ctx context.Context,
	typ plumbing.ObjectType,
) (*objectIter, error) {
	path := a.gitpath.Path("objects")

	pageSize := a.opts.ListPageSize
	if pageSize == 0 {
		pageSize = a.g.Cfg().KVListPageSize()
	}

	ret := &objectIter{
		a:        a,
		typ:      typ,
		path:     path,
		pageSize: pageSize,
	}
	return ret, nil
}

func (a *adapter) putFile(
	mctx libkv.MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	rdr io.Reader,
) error {
	return libkv.PutFile(
		rdr,
		func(data []byte, isFinal bool) (proto.KVNodeID, error) {
			res, err := a.fs.PutFileFirst(
				mctx,
				cfg,
				path,
				data,
				isFinal,
			)
			if err != nil {
				return proto.KVNodeID{}, err
			}
			return res.NodeID, nil
		},
		func(id proto.FileID, data []byte, offset proto.Offset, isFinal bool) error {
			return a.fs.PutFileChunk(
				mctx,
				cfg,
				id,
				data,
				offset,
				isFinal,
			)
		},
		0,
	)
}

func (a *adapter) putReference(ctx context.Context, ref *plumbing.Reference) error {
	prfx := a.gitpath.PrefixJoined()
	mctx, cfg := a.initOpWithContext(ctx)
	newRefStr := ref.Name().String()
	newRefKVPath := proto.KVPath(newRefStr)
	cfg.MkdirP = true
	cfg.OverwriteOk = true
	return a.fs.PutGitRef(mctx, cfg, prfx, newRefKVPath, ref.String())
}

func (a *adapter) getReference(ctx context.Context, nm plumbing.ReferenceName) (*plumbing.Reference, error) {
	mctx, cfg := a.initOpWithContext(ctx)
	ref, _, err := a.getReferenceWithMctx(mctx, cfg, nm)
	return ref, err
}

func (a *adapter) getReferenceWithMctx(
	mctx libkv.MetaContext,
	cfg lcl.KVConfig,
	nm plumbing.ReferenceName,
) (*plumbing.Reference, proto.KVVersion, error) {
	val, vers, err := a.fs.GetGitRef(mctx, cfg, a.gitpath.PrefixJoined(), proto.KVPath(nm.String()))
	if core.IsKVNoentError(err) {
		return nil, vers, plumbing.ErrReferenceNotFound
	}
	var zed proto.KVVersion
	if err != nil {
		return nil, zed, err
	}
	ret := plumbing.NewReferenceFromStrings(string(nm), val)
	return ret, vers, nil
}

func (a *adapter) putReferenceConditional(ctx context.Context, new, old *plumbing.Reference) error {
	if old != nil && old.Name().String() != new.Name().String() {
		return core.InternalError("old and new reference names do not match")
	}
	prfx := a.gitpath.PrefixJoined()
	mctx, cfg := a.initOpWithContext(ctx)
	newRefStr := new.Name().String()
	newRefKVPath := proto.KVPath(newRefStr)

	if old != nil {
		tmp, vers, err := a.fs.GetGitRef(mctx, cfg, prfx, newRefKVPath)
		if err != nil {
			return err
		}
		existingRef := plumbing.NewReferenceFromStrings(newRefStr, tmp)
		if existingRef.Hash() != old.Hash() {
			return storage.ErrReferenceHasChanged
		}
		cfg.AssertVersion = &vers
	}
	cfg.MkdirP = true
	cfg.OverwriteOk = true
	err := a.fs.PutGitRef(mctx, cfg, prfx, newRefKVPath, new.String())
	if err != nil && errors.Is(err, core.KVRaceError("dirent")) {
		return storage.ErrReferenceHasChanged
	}
	if err != nil {
		return err
	}
	return nil
}

type referenceIter struct {
	a    *adapter
	refs []plumbing.Reference
	mctx libkv.MetaContext
	cfg  lcl.KVConfig
}

var _ storer.ReferenceIter = (*referenceIter)(nil)

func (r *referenceIter) Next() (*plumbing.Reference, error) {
	if len(r.refs) == 0 {
		return nil, io.EOF
	}
	ret := r.refs[0]
	r.refs = r.refs[1:]
	return &ret, nil
}

func (r *referenceIter) ForEach(f func(*plumbing.Reference) error) error {
	for _, ref := range r.refs {
		tmp := ref
		if err := f(&tmp); err != nil {
			return err
		}
	}
	return nil
}

func (r *referenceIter) Close() {
}

func (a *adapter) openReferenceIter(ctx context.Context) (*referenceIter, error) {
	mctx, cfg := a.initOpWithContext(ctx)
	prfx := a.gitpath.PrefixJoined()

	refs, err := a.fs.ExploreGitRefs(mctx, cfg, prfx, nil)
	if err != nil {
		return nil, err
	}
	grefs := core.Map(refs, func(x proto.GitRef) plumbing.Reference {
		return *plumbing.NewReferenceFromStrings(x.Name.String(), x.Value)
	})

	return &referenceIter{
		a:    a,
		refs: grefs,
		mctx: mctx,
		cfg:  cfg,
	}, nil
}

func (a *adapter) unlinkReference(ctx context.Context, nm plumbing.ReferenceName) error {
	mctx, cfg := a.initOpWithContext(ctx)
	prfx := a.gitpath.PrefixJoined()
	return a.fs.UnlinkGitRef(mctx, cfg, prfx, proto.KVPath(nm.String()))
}

func (a *adapter) fetchNewIndices(
	ctx context.Context,
	since time.Time,
) (
	[]remhelp.RawIndex,
	error,
) {
	path := a.gitpath.Path("objects", "idx")
	mctx, cfg := a.initOpWithContext(ctx)
	nxt := proto.NewKVListPaginationWithTime(proto.ExportTimeMicro(since))
	keepGoing := true
	var dirID *proto.DirID
	lps := a.opts.ListPageSize
	if lps == 0 {
		lps = a.g.Cfg().KVListPageSize()
	}
	opts := rem.KVListOpts{
		Start:          nxt,
		Num:            lps,
		LoadSmallFiles: true,
	}
	var files []proto.KVPathComponent
	first := true
	seen := make(map[proto.KVPathComponent]bool)
	for keepGoing {
		tmp, err := a.fs.List(mctx, cfg, path, dirID, opts)
		if core.IsKVNoentError(err) && first {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		for _, e := range tmp.Ents {
			if e.Value.IsFileOrSmallFile() {
				if !seen[e.Name] {
					files = append(files, e.Name)
					seen[e.Name] = true
				}
			}
		}
		if tmp.Nxt != nil {
			dirID = &tmp.Nxt.Id
			opts.Start = tmp.Nxt.Nxt
		} else {
			keepGoing = false
		}
		first = false
	}

	ret := make([]remhelp.RawIndex, 0, len(files))
	for _, f := range files {
		idxName := remhelp.ParsePackIndex(string(f))
		if idxName.IsZero() {
			continue
		}
		filePath := path.Append(f)
		var buf bytes.Buffer
		de, err := a.getFile(mctx, cfg, filePath, &buf)
		if err != nil {
			return nil, err
		}
		ret = append(ret, remhelp.RawIndex{
			Name:  idxName,
			Data:  buf.Bytes(),
			CTime: de.Ctime.Import(),
		})
	}

	return ret, nil
}

func (a *adapter) fetchPackData(
	ctx context.Context,
	name remhelp.IndexName,
	wc io.Writer,
) error {
	fileName := name.PackDataFilename()
	path := a.gitpath.Path("objects", "pack", fileName)
	mctx, cfg := a.initOpWithContext(ctx)
	_, err := a.getFile(mctx, cfg, path, wc)
	return err
}

func (a *adapter) pushPackData(
	ctx context.Context,
	name remhelp.IndexName,
	rc io.Reader,
) error {
	fileName := name.PackDataFilename()
	path := a.gitpath.Path("objects", "pack", fileName)

	mctx, cfg := a.initOp()
	cfg.MkdirP = true
	mctx.Infow("pushPackData", "path", path)

	err := a.putFile(mctx, cfg, path, rc)
	if err != nil {
		return err
	}
	return nil
}

func (a *adapter) pushPackIndex(
	ctx context.Context,
	name remhelp.IndexName,
	rc io.Reader,
) error {
	fileName := name.PackIndexFilename()
	path := a.gitpath.Path("objects", "idx", fileName)

	mctx, cfg := a.initOp()
	cfg.MkdirP = true
	mctx.Infow("pushPackData", "path", path)

	err := a.putFile(mctx, cfg, path, rc)
	if err != nil {
		return err
	}
	return nil
}

func (a *adapter) hasIndex(
	ctx context.Context,
	name remhelp.IndexName,
) (bool, error) {
	fileName := name.PackIndexFilename()
	path := a.gitpath.Path("objects", "idx", fileName)
	mctx, cfg := a.initOp()
	_, err := a.fs.Stat(mctx, cfg, path)
	if core.IsKVNoentError(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
