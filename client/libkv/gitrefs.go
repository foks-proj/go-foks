// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libkv

import (
	"bytes"
	"sync"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/kv"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

const gitRefsDir = proto.KVPathComponent("refs")

var gitRefSubdirs = []proto.KVPathComponent{"heads", "tags", "remotes"}

type entryIndex struct {
	id   proto.DirentID
	vers proto.KVVersion
}

type gitRef struct {
	ei   entryIndex
	tm   time.Time
	name proto.KVPathComponent
	val  *string // if nil, then means it's been deleted
}

type gitRefSet struct {
	dirVersion    proto.KVVersion
	m             map[proto.DirentID]*gitRef
	latest        time.Time
	latestEntries map[entryIndex]struct{}
}

func newGitRefSet() *gitRefSet {
	return &gitRefSet{
		m:             make(map[proto.DirentID]*gitRef),
		latestEntries: make(map[entryIndex]struct{}),
	}
}

type ExploreGitRefsOpts struct {
	PageSize int
}

type gitRefDirExplorer struct {
	// passed in by the caller
	opts   ExploreGitRefsOpts
	prfx   proto.KVPathComponent
	path   proto.KVPath
	minder *Minder
	cfg    lcl.KVConfig

	kvp *KVParty
	pap *kv.ParsedPath
	res []proto.GitRef

	// relating to our working directory
	did    *proto.DirID
	dir    *DirPair
	kbsMap map[proto.KVVersion]*kv.KeyBundle

	// scratch for working
	mem  *gitRefSet
	disk *proto.GitRefBoxedSet

	// for fetching from the server
	cli  *rem.KVStoreClient
	auth *rem.KVAuth

	// figure out the next server fetch, if necessary
	start       proto.KVListPagination
	moreToFetch bool

	// we get these back from the server
	cacheRefs []proto.GitRefBoxed
	newRefs   []proto.GitRefBoxed
	resBoxed  []proto.GitRefBoxed
}

func (g *gitRefDirExplorer) loadDir(m MetaContext) error {
	return g.minder.retryCacheLoop(m, g.kvp, func(m MetaContext) error {
		did, err := g.minder.openDir(m, g.kvp, g.pap)
		if err != nil {
			return err
		}
		dir, err := g.minder.loadDirWithDirID(m, g.kvp, *did)
		if err != nil {
			return err
		}
		g.did = did
		g.dir = dir
		g.kbsMap = loadDirKeys(g.dir)
		return nil
	})
}

func (g *gitRefDirExplorer) client(m MetaContext) (*rem.KVAuth, *rem.KVStoreClient, error) {
	if g.cli != nil {
		return g.auth, g.cli, nil
	}
	auth, cli, err := g.minder.client(m, g.kvp)
	if err != nil {
		return nil, nil, err
	}
	g.cli = cli
	g.auth = auth
	return auth, cli, nil
}

func (g *gitRefDirExplorer) loadCache(m MetaContext) error {
	disk, mem, err := g.kvp.caches.gitRefSet.Get(m, *g.did)
	if err != nil {
		return err
	}

	if disk == nil {
		return nil
	}
	v := g.dir.GetVersion()
	if disk.DirVersion != v {
		return nil
	}

	g.disk = disk
	g.cacheRefs = disk.Refs
	g.mem = mem

	return nil
}

func (g *gitRefDirExplorer) getNextPage(m MetaContext) error {
	auth, cli, err := g.client(m)
	if err != nil {
		return err
	}

	res, err := cli.KvList(m.Ctx(), rem.KvListArg{
		Auth: *auth,
		Dir:  *g.did,
		Opts: rem.KVListOpts{
			Start:          g.start,
			Num:            uint64(g.opts.PageSize),
			LoadSmallFiles: true,
		},
	})
	if err != nil {
		return err
	}

	g.moreToFetch = !res.Final && len(res.Ents) > 0
	if g.moreToFetch {
		g.start = proto.NewKVListPaginationWithTime(
			core.Last(res.Ents).Ctime,
		)
	}

	refs := make([]proto.GitRefBoxed, 0, len(res.Ents))
	nxt := 0
	for i, e := range res.Ents {
		ref := proto.GitRefBoxed{De: e}
		if nxt < len(res.ExtEnts) && res.ExtEnts[nxt].Pos == uint64(i) {
			ref.Sfb = res.ExtEnts[nxt].Sfb
			nxt++
		}
		refs = append(refs, ref)
	}

	g.newRefs = append(g.newRefs, refs...)

	return nil
}

func (g *gitRefDirExplorer) isFresh(m MetaContext) (bool, error) {
	err := g.getNextPage(m)
	if err != nil {
		return false, err
	}
	if g.moreToFetch {
		return false, nil
	}
	if g.mem == nil {
		return false, nil
	}

	for _, e := range g.newRefs {
		tm := e.De.Ctime.Import()
		if tm.After(g.mem.latest) {
			return false, nil
		}
		ei := entryIndex{id: e.De.Id, vers: e.De.Version}
		if _, ok := g.mem.latestEntries[ei]; !ok {
			return false, nil
		}
	}

	return true, nil
}

func (g *gitRefDirExplorer) fetchAll(m MetaContext) error {
	for g.moreToFetch {
		err := g.getNextPage(m)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *gitRefDirExplorer) unboxDirent(
	m MetaContext,
	e *proto.GitRefBoxed,
) (
	*gitRef,
	error,
) {
	nm, kvle, err := openDirentToKVListEntry(g.kbsMap, *g.did, &e.De)
	if err != nil {
		return nil, err
	}
	ret := gitRef{
		name: nm,
		tm:   e.De.Ctime.Import(),
		ei: entryIndex{
			id:   e.De.Id,
			vers: e.De.Version,
		},
	}
	if kvle == nil {
		return &ret, nil
	}
	typ, err := kvle.Value.Type()
	if err != nil {
		return &ret, nil
	}
	switch typ {
	case proto.KVNodeType_None:
		return &ret, nil
	case proto.KVNodeType_File:
		return nil, nil
	case proto.KVNodeType_Symlink:
		return nil, nil
	case proto.KVNodeType_Dir:
		return nil, nil
	default:
	}
	sfid, err := kvle.Value.ToSmallFileID()
	if err != nil {
		return nil, err
	}
	dat, err := g.kvp.unboxSmallFile(m, *sfid, e.Sfb)
	if err != nil {
		return nil, err
	}
	sdat := string(dat)
	ret.val = &sdat
	return &ret, nil
}

func (g *gitRefDirExplorer) unboxVec(m MetaContext, inp []proto.GitRefBoxed) ([]*gitRef, error) {
	ret := make([]*gitRef, 0, len(inp))
	for _, e := range inp {
		ge, err := g.unboxDirent(m, &e)
		if err != nil {
			return nil, err
		}
		if ge != nil {
			ret = append(ret, ge)
		}
	}
	return ret, nil

}

func (g *gitRefDirExplorer) makeMem(m MetaContext) error {
	if g.mem != nil {
		return nil
	}
	refsUnboxed, err := g.unboxVec(m, g.cacheRefs)
	if err != nil {
		return err
	}
	ret := newGitRefSet()
	ret.dirVersion = g.dir.GetVersion()
	ret.loadIn(refsUnboxed)
	g.mem = ret
	return nil
}

func (g *gitRefSet) loadIn(inp []*gitRef) {
	for _, e := range inp {
		g.m[e.ei.id] = e
	}
	for i := len(inp) - 1; i >= 0; i-- {
		e := inp[i]
		if g.latest.IsZero() || g.latest.Equal(e.tm) {
			g.latest = e.tm
			g.latestEntries[e.ei] = struct{}{}
		}
	}
}

func (g *gitRefDirExplorer) writeBack(m MetaContext) error {
	out := proto.GitRefBoxedSet{
		DirVersion: g.dir.GetVersion(),
		Refs:       g.resBoxed,
	}
	return g.kvp.caches.gitRefSet.Put(m, *g.did, out, g.mem)
}

func (g *gitRefDirExplorer) init(m MetaContext) error {
	kvp, err := g.minder.initReq(m, g.cfg)
	if err != nil {
		return err
	}
	g.kvp = kvp
	pap, err := kv.ParsePath(g.path.Append(gitRefsDir, g.prfx))
	if err != nil {
		return err
	}
	g.pap = pap
	if g.opts.PageSize == 0 {
		g.opts.PageSize = 4096 // load in batches of 4k
	}
	return nil
}

func (g *gitRefDirExplorer) initPageStart(m MetaContext) error {
	var tm proto.TimeMicro
	if g.disk != nil && len(g.disk.Refs) > 0 {
		lst := core.Last(g.disk.Refs)
		tm = lst.De.Ctime
	}
	g.start = proto.NewKVListPaginationWithTime(tm)
	return nil
}

func (g *gitRefDirExplorer) stage1(m MetaContext) error {
	err := g.init(m)
	if err != nil {
		return err
	}
	err = g.loadDir(m)
	if err != nil {
		return err
	}
	err = g.loadCache(m)
	if err != nil {
		return err
	}
	err = g.initPageStart(m)
	if err != nil {
		return err
	}
	return nil
}

func (g *gitRefDirExplorer) run(m MetaContext) error {

	err := g.stage1(m)
	if err != nil {
		return err
	}

	fresh, err := g.isFresh(m)
	if err != nil {
		return err
	}

	if !fresh {
		err := g.stage2(m)
		if err != nil {
			return err
		}
	} else {
		g.resBoxed = g.cacheRefs
	}

	err = g.makeRes(m)
	if err != nil {
		return err
	}

	return nil
}

func (g *gitRefDirExplorer) makeRes(m MetaContext) error {
	out := make([]proto.GitRef, 0, len(g.resBoxed))
	for _, e := range g.resBoxed {
		if curr := g.mem.m[e.De.Id]; curr != nil && curr.ei.vers == e.De.Version && curr.val != nil {
			// Everything in refs/ or tags/ is query-escaped, so that a multi-directory-tree
			// is flattened into a single directory tree. We need to unescape it here.
			tmp, err := curr.name.Unescape()
			if err != nil {
				return err
			}
			name := proto.PathJoin(
				[]proto.KVPath{
					gitRefsDir.ToPath(),
					g.prfx.ToPath(),
					tmp,
				},
			)
			out = append(out, proto.GitRef{
				Name:  name,
				Value: *curr.val,
			})
		}
	}
	g.res = out
	return nil
}

func (g *gitRefDirExplorer) serialize(m MetaContext) error {
	out := make([]proto.GitRefBoxed, 0, len(g.mem.m))
	seen := make(map[entryIndex]bool)

	doVec := func(v []proto.GitRefBoxed) {
		for i := len(v) - 1; i >= 0; i-- {
			e := v[i]
			curr := g.mem.m[e.De.Id]
			if curr != nil && curr.ei.vers == e.De.Version && curr.val != nil && !seen[curr.ei] {
				out = append(out, e)
				seen[curr.ei] = true
			}
		}
	}
	doVec(g.newRefs)
	doVec(g.cacheRefs)

	g.resBoxed = core.Reverse(out)
	return nil
}

func (g *gitRefDirExplorer) stage2(m MetaContext) error {

	err := g.fetchAll(m)
	if err != nil {
		return err
	}

	err = g.makeMem(m)
	if err != nil {
		return err
	}

	newRefs, err := g.unboxVec(m, g.newRefs)
	if err != nil {
		return err
	}

	// load in the new refs
	g.mem.loadIn(newRefs)

	err = g.serialize(m)
	if err != nil {
		return err
	}

	err = g.writeBack(m)
	if err != nil {
		return err
	}
	return nil
}

type gitRefExplorer struct {
	path   proto.KVPath
	minder *Minder
	dirs   map[proto.KVPathComponent]*gitRefDirExplorer
	head   *proto.GitRef
	cfg    lcl.KVConfig
}

func newGitRefExplorer(
	path proto.KVPath,
	cfg lcl.KVConfig,
	minder *Minder,
	opt ExploreGitRefsOpts,
) *gitRefExplorer {
	dirs := make(map[proto.KVPathComponent]*gitRefDirExplorer)
	for _, d := range gitRefSubdirs {
		dirs[d] = &gitRefDirExplorer{
			prfx:   d,
			path:   path,
			cfg:    cfg,
			minder: minder,
			opts:   opt,
		}
	}
	return &gitRefExplorer{
		path:   path,
		dirs:   dirs,
		minder: minder,
		cfg:    cfg,
	}
}

func (g *gitRefExplorer) loadHead(m MetaContext) error {
	comp := proto.KVPathComponent("HEAD")
	path := g.path.Append(comp)
	var buf bytes.Buffer
	_, err := g.minder.GetFileWithHeader(m, g.cfg, path, &buf)
	if err != nil {
		return err
	}
	g.head = &proto.GitRef{
		Name:  comp.ToPath(),
		Value: buf.String(),
	}
	return nil
}

func (g *gitRefExplorer) run(m MetaContext) ([]proto.GitRef, error) {

	var wg sync.WaitGroup
	tot := len(g.dirs) + 1
	wg.Add(tot)

	// It might be the tags/ or refs/ directory doesn't exist. Then it's
	// not an error, just return an empty list (for that part of it).
	cleanErr := func(e error) error {
		if core.IsKVNoentError(e) {
			return nil
		}
		return e
	}

	errch := make(chan error, tot)
	for _, d := range g.dirs {
		go func(d *gitRefDirExplorer) {
			err := d.run(m)
			errch <- err
			wg.Done()
		}(d)
	}

	go func() {
		err := g.loadHead(m)
		errch <- err
		wg.Done()
	}()

	var err error
	for i := 0; i < tot; i++ {
		e := <-errch
		e = cleanErr(e)
		if e != nil {
			err = e
		}
	}
	if err != nil {
		return nil, err
	}
	res := []proto.GitRef{}
	for _, d := range g.dirs {
		res = append(res, d.res...)
	}
	if g.head != nil {
		res = append(res, *g.head)
	}
	return res, nil
}

func (k *Minder) ExploreGitRefs(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	optsp *ExploreGitRefsOpts,
) (
	[]proto.GitRef,
	error,
) {
	if optsp == nil {
		optsp = &ExploreGitRefsOpts{}
	}

	gre := newGitRefExplorer(path, cfg, k, *optsp)
	return gre.run(m)
}

type gitRefPath struct {
	prefix proto.KVPath
	path   proto.KVPath
	final  proto.KVPath
}

func (g *gitRefPath) convert() (proto.KVPath, error) {
	err := g.parse()
	if err != nil {
		return "", err
	}
	return g.final, nil
}

func (g *gitRefPath) parse() error {
	pap, err := kv.ParsePath(g.path)
	if err != nil {
		return err
	}

	isSubdir := func(d proto.KVPathComponent) bool {
		for _, s := range gitRefSubdirs {
			if d == s {
				return true
			}
		}
		return false
	}

	if len(pap.Components) >= 2 && pap.Components[0] == gitRefsDir && isSubdir(pap.Components[1]) {
		// Strip off everything after 'heads/' or 'tags/' and flatten into a depth-1 tree.
		nm := proto.PathComponentJoin(pap.Components[2:]).Escape()
		g.final = g.prefix.Append(pap.Components[0], pap.Components[1], nm)
	} else {
		g.final = g.prefix.Join(g.path)
	}

	return nil
}

func (k *Minder) PutGitRef(
	m MetaContext,
	cfg lcl.KVConfig,
	prefix proto.KVPath,
	path proto.KVPath,
	val string,
) error {
	gp := gitRefPath{prefix: prefix, path: path}
	final, err := gp.convert()
	if err != nil {
		return err
	}
	_, err = k.PutFileFirst(m, cfg, final, []byte(val), true)
	if err != nil {
		return err
	}
	return nil
}

func (k *Minder) StatGitRef(
	m MetaContext,
	cfg lcl.KVConfig,
	prefix proto.KVPath,
	path proto.KVPath,
) (
	*lcl.KVStat,
	error,
) {
	gp := gitRefPath{prefix: prefix, path: path}
	final, err := gp.convert()
	if err != nil {
		return nil, err
	}
	return k.Stat(m, cfg, final)
}

func (k *Minder) GetGitRef(
	m MetaContext,
	cfg lcl.KVConfig,
	prefix proto.KVPath,
	path proto.KVPath,
) (
	string,
	proto.KVVersion,
	error,
) {
	gp := gitRefPath{prefix: prefix, path: path}
	final, err := gp.convert()
	if err != nil {
		return "", 0, err
	}
	tmp, err := k.GetFile(m, cfg, final)
	if err != nil {
		return "", 0, err
	}
	if !tmp.Chunk.Final {
		return "", 0, core.InternalError("expected single-chunk file")
	}
	return string(tmp.Chunk.Chunk), tmp.De.Version, nil
}

func (k *Minder) UnlinkGitRef(
	m MetaContext,
	cfg lcl.KVConfig,
	prefix proto.KVPath,
	path proto.KVPath,
) error {
	gp := gitRefPath{prefix: prefix, path: path}
	final, err := gp.convert()
	if err != nil {
		return err
	}
	return k.Unlink(m, cfg, final)
}
