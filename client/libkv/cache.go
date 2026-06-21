// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libkv

import (
	"fmt"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/kv"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type RootCache struct {
	*libclient.Cache[*proto.FQParty, core.EmptyKey, proto.KVRoot, *proto.KVRoot, struct{}]
}

func (r *RootCache) ClearBefore(m MetaContext, vers proto.KVVersion) error {
	if !r.Settings.UseDisk {
		return nil
	}
	return r.Cache.ClearBefore(m.Base(), core.EmptyKey{}, vers)
}

type DirSeedPair struct {
	Active     *proto.DirKeySeed
	Encrypting *proto.DirKeySeed
}

type DirCache struct {
	*libclient.Cache[*proto.FQParty, proto.DirID, proto.KVDirPair, *proto.KVDirPair, DirSeedPair]
}

func NewRootCache(p proto.FQParty, settings libclient.CacheSettings) *RootCache {
	return &RootCache{libclient.NewCache[*proto.FQParty, core.EmptyKey, proto.KVRoot, *proto.KVRoot, struct{}](lcl.DataType_KVNSRoot, &p, settings)}
}

func (r *RootCache) Get(m MetaContext) (*proto.KVRoot, error) {
	v, _, err := r.Cache.Get(m.Base(), core.EmptyKey{})
	return v, err
}

func (r *RootCache) Put(m MetaContext, v proto.KVRoot) error {
	return r.Cache.Put(m.Base(), core.EmptyKey{}, v, nil)
}

func NewDirCache(p proto.FQParty, settings libclient.CacheSettings) *DirCache {
	return &DirCache{
		Cache: libclient.NewCache[
			*proto.FQParty,
			proto.DirID,
			proto.KVDirPair,
			*proto.KVDirPair,
			DirSeedPair,
		](lcl.DataType_KVDir, &p, settings),
	}
}

type DirWithSeed struct {
	proto.KVDir
	Seed *proto.DirKeySeed
}

type DirPair struct {
	Active     DirWithSeed
	Encrypting *DirWithSeed
	Owner      proto.FQParty
	IsRoot     bool
}

func (d *DirPair) GetVersion() proto.KVVersion {
	if d.Encrypting != nil {
		return d.Encrypting.Version
	}
	return d.Active.Version
}

func (d *DirPair) Id() proto.DirID {
	return d.Active.Id
}

func (d *DirPair) Split() (*proto.KVDirPair, *DirSeedPair) {
	ret := proto.KVDirPair{
		Active: d.Active.KVDir,
	}
	seed := DirSeedPair{
		Active: d.Active.Seed,
	}
	if d.Encrypting != nil {
		ret.Encrypting = &d.Encrypting.KVDir
		seed.Encrypting = d.Encrypting.Seed
	}
	return &ret, &seed
}

func NewDirPairFromSingle(o proto.FQParty, d proto.KVDir, s proto.DirKeySeed) *DirPair {
	return &DirPair{
		Active: DirWithSeed{
			KVDir: d,
			Seed:  &s,
		},
		Owner: o,
	}
}

func NewDirPair(o proto.FQParty, d proto.KVDirPair, s *DirSeedPair) *DirPair {
	ret := &DirPair{
		Active: DirWithSeed{
			KVDir: d.Active,
		},
		Owner: o,
	}
	if s != nil {
		ret.Active.Seed = s.Active
	}
	if d.Encrypting != nil {
		ret.Encrypting = &DirWithSeed{
			KVDir: *d.Encrypting,
		}
		if s != nil {
			ret.Encrypting.Seed = s.Encrypting
		}
	}
	return ret
}

func (d *DirCache) Get(m MetaContext, k proto.DirID) (*DirPair, error) {
	v, memVal, err := d.Cache.Get(m.Base(), k)
	if err != nil {
		return nil, err
	}
	m.VisitDir(k, v)
	if v == nil {
		return nil, nil
	}
	return NewDirPair(*d.Scope, *v, memVal), nil
}

func (d *DirCache) Put(m MetaContext, v *DirPair) error {
	dp, seed := v.Split()
	return d.Cache.Put(m.Base(), v.Id(), *dp, seed)
}

func (d *DirCache) PutMem(v *DirPair) {
	dp, seed := v.Split()
	d.Cache.PutMem(v.Id(), *dp, seed)
}

type Dirent struct {
	proto.KVDirent
	Nm *proto.KVPathComponent // known upon decryption
}

type DirentCache struct {
	*libclient.Cache[*proto.FQParty, proto.HMAC, proto.KVDirent, *proto.KVDirent, proto.KVPathComponent]
}

func NewDirentCache(p proto.FQParty, settings libclient.CacheSettings) *DirentCache {
	return &DirentCache{
		Cache: libclient.NewCache[
			*proto.FQParty,
			proto.HMAC,
			proto.KVDirent,
			*proto.KVDirent,
			proto.KVPathComponent,
		](lcl.DataType_KVDirent, &p, settings),
	}
}

func (d *DirentCache) Get(m MetaContext, k proto.HMAC) (*Dirent, error) {
	v, memVal, err := d.Cache.Get(m.Base(), k)
	if err != nil {
		return nil, err
	}
	m.VisitDirent(v)
	if v == nil {
		return nil, nil
	}
	return &Dirent{
		KVDirent: *v,
		Nm:       memVal,
	}, nil
}

func (d *DirentCache) Put(m MetaContext, v *Dirent) error {
	return d.Cache.Put(m.Base(), v.NameMac, v.KVDirent, v.Nm)
}

func (d *DirentCache) PutMem(v *Dirent) {
	d.Cache.PutMem(v.NameMac, v.KVDirent, v.Nm)
}

func (d *DirPair) WriteTo() *DirWithSeed {
	if d.Encrypting != nil {
		return d.Encrypting
	}
	return &d.Active
}

type Symlink struct {
	Raw  proto.KVPath
	Path kv.ParsedPath
}

type SymlinkCache struct {
	*libclient.Cache[*proto.FQParty, proto.SymlinkID, proto.SmallFileBox, *proto.SmallFileBox, Symlink]
}

func NewSymlinkCache(p proto.FQParty, settings libclient.CacheSettings) *SymlinkCache {
	return &SymlinkCache{
		Cache: libclient.NewCache[
			*proto.FQParty,
			proto.SymlinkID,
			proto.SmallFileBox,
			*proto.SmallFileBox,
			Symlink,
		](lcl.DataType_KVSymlink, &p, settings),
	}
}

func (s *SymlinkCache) PutMem(i proto.SymlinkID, b *proto.SmallFileBox, v *Symlink) {
	s.Cache.PutMem(i, *b, v)
}

type SmallFileCache struct {
	*libclient.Cache[*proto.FQParty, proto.SmallFileID, proto.SmallFileBox, *proto.SmallFileBox, lcl.SmallFileData]
}

func NewSmallFileCache(p proto.FQParty, settings libclient.CacheSettings) *SmallFileCache {
	return &SmallFileCache{
		Cache: libclient.NewCache[
			*proto.FQParty,
			proto.SmallFileID,
			proto.SmallFileBox,
			*proto.SmallFileBox,
			lcl.SmallFileData,
		](lcl.DataType_KVSymlink, &p, settings),
	}
}

func (s *SmallFileCache) PutMem(i proto.SmallFileID, b *proto.SmallFileBox, v *lcl.SmallFileData) {
	s.Cache.PutMem(i, *b, v)
}

type LargeFileMetadataCache struct {
	*libclient.Cache[*proto.FQParty, proto.FileID, proto.LargeFileMetadata, *proto.LargeFileMetadata, proto.FileKeySeed]
}

func NewLargeFileMetadataCache(p proto.FQParty, settings libclient.CacheSettings) *LargeFileMetadataCache {
	return &LargeFileMetadataCache{
		Cache: libclient.NewCache[
			*proto.FQParty,
			proto.FileID,
			proto.LargeFileMetadata,
			*proto.LargeFileMetadata,
			proto.FileKeySeed,
		](lcl.DataType_KVFileHeader, &p, settings),
	}
}

type ChunkIndex struct {
	FileID proto.FileID
	Offset proto.Offset
}

func (c ChunkIndex) DbKey() (proto.DbKey, error) {
	fid, err := c.FileID.KVNodeID().StringErr()
	if err != nil {
		return nil, err
	}
	s := fmt.Sprintf("%s-%d", fid, c.Offset)
	return proto.DbKey(s), nil
}

type LargeFileChunkCache struct {
	*libclient.Cache[*proto.FQParty, ChunkIndex, rem.GetEncryptedChunkRes, *rem.GetEncryptedChunkRes, struct{}]
}

func NewLargeFileChunkCache(p proto.FQParty, settings libclient.CacheSettings) *LargeFileChunkCache {
	settings.UseMem = false
	return &LargeFileChunkCache{
		Cache: libclient.NewCache[
			*proto.FQParty,
			ChunkIndex,
			rem.GetEncryptedChunkRes,
			*rem.GetEncryptedChunkRes,
			struct{},
		](lcl.DataType_KVFileChunk, &p, settings),
	}
}

type GitRefSetCache struct {
	*libclient.Cache[*proto.FQParty, proto.DirID, proto.GitRefBoxedSet, *proto.GitRefBoxedSet, gitRefSet]
}

func NewGitRefSetCache(p proto.FQParty, settings libclient.CacheSettings) *GitRefSetCache {
	return &GitRefSetCache{
		Cache: libclient.NewCache[
			*proto.FQParty,
			proto.DirID,
			proto.GitRefBoxedSet,
			*proto.GitRefBoxedSet,
			gitRefSet,
		](lcl.DataType_KVGitRefSet, &p, settings),
	}
}

type DirentCacheAccess struct {
	Version proto.KVVersion
	Hmac    proto.HMAC
}

type DirCacheAccess struct {
	Version proto.KVVersion
	Dirents map[proto.DirentID]DirentCacheAccess
}

type DirDirentPair struct {
	Dir    proto.DirID
	Dirent proto.DirentID
}

type CacheAccess struct {
	Dir  map[proto.DirID]DirCacheAccess
	Root proto.KVVersion
	kvp  *KVParty
}

func (C *CacheAccess) clear() {
	C.Dir = nil
	C.Root = 0
	C.kvp = nil
}

func NewCacheAccess() *CacheAccess {
	return &CacheAccess{}
}

type MetaContext struct {
	libclient.MetaContext
	cacheAccess *CacheAccess
	au          *libclient.UserContext
}

func (m MetaContext) Base() libclient.MetaContext {
	return m.MetaContext
}

func NewMetaContext(m libclient.MetaContext) MetaContext {
	return MetaContext{
		MetaContext: m,
		cacheAccess: NewCacheAccess(),
	}
}

func (m MetaContext) SetActiveUser(u *libclient.UserContext) MetaContext {
	m.au = u
	return m
}

func (m MetaContext) ActiveUser() (*libclient.UserContext, error) {
	if m.au != nil {
		return m.au, nil
	}
	ret := m.G().ActiveUser()
	if ret != nil {
		return ret, nil
	}
	return nil, core.NoActiveUserError{}
}

func (c *CacheAccess) setKVParty(p *KVParty) error {
	if c.kvp != nil && !c.kvp.Eq(p) {
		return core.InternalError("FQParty changed in request")
	}
	if c.kvp != nil {
		return nil
	}
	c.kvp = p
	return nil
}

func (m MetaContext) VisitDir(d proto.DirID, p *proto.KVDirPair) {
	if m.cacheAccess == nil {
		return
	}
	m.cacheAccess.VisitDir(d, p)
}

func (c *CacheAccess) VisitDir(d proto.DirID, p *proto.KVDirPair) {
	if p == nil {
		return
	}
	v := proto.KVVersion(p.GetVersion())
	if c.Dir == nil {
		c.Dir = make(map[proto.DirID]DirCacheAccess)
	}
	dcc, ok := c.Dir[d]
	if ok {
		dcc.Version = max(v, dcc.Version)
	} else {
		dcc = DirCacheAccess{
			Version: v,
		}
		c.Dir[d] = dcc
	}
}

func max(a, b proto.KVVersion) proto.KVVersion {
	if a > b {
		return a
	}
	return b
}

func (m *MetaContext) InitCacheContext(p *KVParty) error {
	if p == nil {
		return core.InternalError("no party")
	}
	m.cacheAccess = NewCacheAccess()
	return m.cacheAccess.setKVParty(p)
}

func (m MetaContext) VisitRoot(v *proto.KVRoot) {
	if m.cacheAccess == nil {
		return
	}
	m.cacheAccess.VisitRoot(v)
}

func (c *CacheAccess) VisitRoot(r *proto.KVRoot) {
	if r == nil {
		return
	}
	c.Root = max(r.Vers, c.Root)
}

func (m MetaContext) VisitDirent(d *proto.KVDirent) {
	if m.cacheAccess == nil {
		return
	}
	m.cacheAccess.VisitDirent(d)
}

func (c *CacheAccess) VisitDirent(d *proto.KVDirent) {
	if d == nil {
		return
	}
	if c.Dir == nil {
		c.Dir = make(map[proto.DirID]DirCacheAccess)
	}
	dir, ok := c.Dir[d.ParentDir]
	if !ok {
		dir = DirCacheAccess{
			Version: d.Version,
		}
		c.Dir[d.ParentDir] = dir
	} else {
		dir.Version = max(d.DirVersion, dir.Version)
	}
	if dir.Dirents == nil {
		dir.Dirents = make(map[proto.DirentID]DirentCacheAccess)
	}
	dir.Dirents[d.Id] = DirentCacheAccess{
		Version: d.Version,
		Hmac:    d.NameMac,
	}
	c.Dir[d.ParentDir] = dir
}
