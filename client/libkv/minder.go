// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libkv

import (
	"sync"
	"time"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/chains"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/kv"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type KVParty struct {
	sync.RWMutex
	au          proto.FQUser
	id          proto.FQParty
	skm         libclient.SharedKeyManager
	voTok       *rem.TeamVOBearerToken
	caches      *caches
	root        *proto.KVRoot
	cs          CacheSettings
	refreshTime time.Time
}

func (k *KVParty) IsUser() bool {
	return k.id.Party.IsUser()
}

func (k *KVParty) isLocal() bool {
	return k.au.HostID.Eq(k.id.Host)
}

func (k *KVParty) DefaultRootPerms() *proto.RolePair {
	if k.IsUser() {
		return &proto.RolePair{
			Write: proto.OwnerRole,
			Read:  proto.OwnerRole,
		}
	}
	return &proto.RolePair{
		Write: proto.AdminRole,
		Read:  proto.MinKVRole,
	}
}

func (k *KVParty) isTeamFresh(m MetaContext) (bool, error) {
	if k.voTok == nil || k.skm == nil {
		return false, nil
	}
	if k.refreshTime.IsZero() {
		return false, nil
	}
	now := m.G().Now()
	diff := now.Sub(k.refreshTime)
	dur, err := m.G().Cfg().TeamCacheTimeout()
	if err != nil {
		return false, err
	}
	return (diff < dur), nil
}

func (k *KVParty) teamRefresh(
	m MetaContext,
	tw *libclient.TeamWrapper,
) {
	k.refreshTime = m.G().Now()
	k.skm = tw.KeyRing()
	k.voTok = tw.VOBearerToken()
}

type fileUploadState struct {
	sync.Mutex
	fks *proto.FileKeySeed
	off proto.Offset
	sz  proto.Size
}

type caches struct {
	root      *RootCache
	dirent    *DirentCache
	dir       *DirCache
	symlink   *SymlinkCache
	smallFile *SmallFileCache
	lfmd      *LargeFileMetadataCache
	lfch      *LargeFileChunkCache
	gitRefSet *GitRefSetCache
	upload    map[proto.FileID]*fileUploadState
}

func newCaches(p proto.FQParty, settings CacheSettings) *caches {
	return &caches{
		root:      NewRootCache(p, settings),
		dirent:    NewDirentCache(p, settings),
		dir:       NewDirCache(p, settings),
		symlink:   NewSymlinkCache(p, settings),
		smallFile: NewSmallFileCache(p, settings),
		lfmd:      NewLargeFileMetadataCache(p, settings),
		lfch:      NewLargeFileChunkCache(p, settings),
		upload:    make(map[proto.FileID]*fileUploadState),
		gitRefSet: NewGitRefSetCache(p, settings),
	}
}

type Minder struct {
	sync.RWMutex
	au            *libclient.UserContext
	parties       map[proto.FQEntityFixed]*KVParty
	fqptCache     map[proto.StdHash]*proto.FQParty // Cache of FQTeamParsed -> FQParty
	fqptLocks     core.Locktab[proto.StdHash]
	probes        libclient.ProbeCollection
	cacheSettings CacheSettings

	localCliMu sync.Mutex
	localCli   *rem.KVStoreClient
}

func NewMinder(au *libclient.UserContext) *Minder {
	return &Minder{
		au:            au,
		parties:       make(map[proto.FQEntityFixed]*KVParty),
		fqptCache:     make(map[proto.StdHash]*proto.FQParty),
		cacheSettings: CacheSettings{UseMem: true, UseDisk: true},
	}
}

func NewMinderWithCacheSettings(au *libclient.UserContext, s CacheSettings) *Minder {
	return &Minder{
		au:            au,
		parties:       make(map[proto.FQEntityFixed]*KVParty),
		fqptCache:     make(map[proto.StdHash]*proto.FQParty),
		cacheSettings: s,
	}
}

func (k *Minder) clientLocal(
	m libclient.MetaContext,
	au *libclient.UserContext,
) (
	*chains.Probe,
	*rem.KVStoreClient,
	error,
) {
	cert, err := au.ClientCert(m)
	if err != nil {
		return nil, nil, err
	}
	pr := au.HomeServer()
	if pr == nil {
		return nil, nil, core.HomeError("no home server")
	}

	k.localCliMu.Lock()
	defer k.localCliMu.Unlock()

	if k.localCli != nil {
		return pr, k.localCli, nil
	}

	gcli, err := pr.RPCClient(m, proto.ServerType_KVStore, cert)
	if err != nil {
		return nil, nil, err
	}
	ret := core.NewKVStoreClient(gcli, m)
	k.localCli = &ret
	return pr, &ret, nil
}

func (k *Minder) probe(m libclient.MetaContext, host proto.HostID) (*chains.Probe, error) {
	return k.probes.Get(m, host)
}

func (k *Minder) clientRemote(
	m libclient.MetaContext,
	kvp *KVParty,
) (
	*chains.Probe,
	*rem.KVStoreClient,
	error,
) {
	host := kvp.id.Host
	p, err := k.probe(m, host)
	if err != nil {
		return nil, nil, err
	}

	gcli, err := p.RPCClient(m, proto.ServerType_KVStore, nil)
	if err != nil {
		return nil, nil, err
	}
	ret := core.NewKVStoreClient(gcli, m)
	return p, &ret, nil
}

func (k *KVParty) Eq(k2 *KVParty) bool {
	return k.au.Eq(k2.au) && k.id.Eq(k2.id)
}

func (k *KVParty) fillAuthToken(
	auth *rem.KVAuth,
) error {
	if k.IsUser() && !k.isLocal() {
		return core.PermissionError("user not on home server")
	}
	// No auth needed for acting as a user (on home server).
	if k.IsUser() {
		return nil
	}
	tok := k.voTok
	if tok == nil {
		return core.PermissionError("no VO token")
	}
	*auth = rem.NewKVAuthWithTeam(*tok)
	return nil
}

func (k *KVParty) getRoot(
	m MetaContext,
) (
	*proto.KVRoot,
	error,
) {
	k.Lock()
	defer k.Unlock()
	if k.root != nil {
		m.VisitRoot(k.root)
		return k.root, nil
	}
	root, err := k.caches.root.Get(m)
	if err != nil {
		return nil, err
	}
	m.VisitRoot(k.root)
	k.root = root
	return root, nil
}

func (k *KVParty) putRoot(
	m MetaContext,
	root proto.KVRoot,
) error {
	k.Lock()
	defer k.Unlock()
	if k.cs.UseMem {
		k.root = &root
	}
	return k.caches.root.Put(m, root)
}

func (k *Minder) client(
	m MetaContext,
	kvp *KVParty,
) (
	*rem.KVAuth,
	*rem.KVStoreClient,
	error,
) {
	var auth rem.KVAuth
	var cli *rem.KVStoreClient
	var err error
	mb := m.Base()
	if kvp.isLocal() {
		_, cli, err = k.clientLocal(mb, k.au)
	} else {
		_, cli, err = k.clientRemote(mb, kvp)
	}
	if err != nil {
		return nil, nil, err
	}
	err = kvp.fillAuthToken(&auth)
	if err != nil {
		return nil, nil, err
	}
	return &auth, cli, nil
}

func (k *Minder) clientWithCacheCheck(
	m MetaContext,
	kvp *KVParty,
) (
	*rem.KVReqHeader,
	*rem.KVStoreClient,
	error,
) {
	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, nil, err
	}
	hdr := rem.KVReqHeader{
		Auth: *auth,
	}
	hdr.Precondition, err = m.makeVersionVector()
	if err != nil {
		return nil, nil, err
	}
	return &hdr, cli, nil
}

func (k *Minder) getKVParty(
	m MetaContext,
	cfg lcl.KVConfig,
) (
	*KVParty,
	error,
) {
	var ret *KVParty
	var err error

	if cfg.ActingAs == nil {
		ret, err = k.getKVPartyUser(m)
	} else {
		ret, err = k.getKVPartyTeam(m, *cfg.ActingAs)
	}
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (k *Minder) getKVPartyTeam(
	m MetaContext,
	actingAs proto.FQTeamParsed,
) (
	*KVParty,
	error,
) {
	hsh, err := core.PrefixedHash(&actingAs)
	if err != nil {
		return nil, err
	}

	// Single-flight all activity for this FQTeamParsed, which otherwise is hard to lock
	// using our various caches.
	lh := k.fqptLocks.Acquire(*hsh)
	defer lh.Release()

	k.Lock()
	membId := k.fqptCache[*hsh]
	k.Unlock()

	var kvp *KVParty

	if membId != nil {
		kvp, err = k.getLockedKVParty(*membId)
		if err != nil {
			return nil, err
		}
		defer kvp.Unlock()
		isFresh, err := kvp.isTeamFresh(m)
		if err != nil {
			return nil, err
		}
		if isFresh {
			return kvp, nil
		}
	}

	tw, err := k.au.TeamMinder().LoadTeam(m.Base(), actingAs, libclient.LoadTeamOpts{Refresh: true})
	if err != nil {
		return nil, err
	}
	fqp := tw.Prot().Fqt.FQParty()

	k.Lock()
	k.fqptCache[*hsh] = &fqp
	k.Unlock()

	if kvp == nil {
		kvp, err = k.getLockedKVParty(fqp)
		if err != nil {
			return nil, err
		}
		defer kvp.Unlock()
		isFresh, err := kvp.isTeamFresh(m)
		if err != nil {
			return nil, err
		}
		if isFresh {
			return kvp, nil
		}
	}

	kvp.teamRefresh(m, tw)

	return kvp, nil
}

func (k *Minder) getLockedKVParty(
	p proto.FQParty,
) (
	*KVParty, // new KVP, return locked so we can initialize it
	error,
) {
	fqef, err := p.FQEntity().Fixed()
	if err != nil {
		return nil, err
	}
	k.Lock()
	defer k.Unlock()
	ret := k.parties[*fqef]
	if ret != nil {
		ret.Lock()
		return ret, nil
	}
	ret = &KVParty{
		id:     p,
		au:     k.au.FQU(),
		caches: newCaches(p, k.cacheSettings),
		cs:     k.cacheSettings,
	}
	ret.Lock()
	k.parties[*fqef] = ret
	return ret, nil
}

func (k *Minder) getKVPartyUser(
	m MetaContext,
) (
	*KVParty,
	error,
) {
	kvp, err := k.getLockedKVParty(k.au.FQParty())
	if err != nil {
		return nil, err
	}
	defer kvp.Unlock()
	if kvp.skm != nil {
		return kvp, nil
	}

	skm, err := k.au.GetSharedKeyManager(m.Base())
	if err != nil {
		return nil, err
	}
	kvp.skm = skm
	return kvp, nil
}

func (k *Minder) initReq(
	m MetaContext,
	cfg lcl.KVConfig,
) (
	*KVParty,
	error,
) {
	au, err := m.ActiveUser()
	if err != nil {
		return nil, err
	}
	if !au.Eq(k.au) {
		return nil, core.WrongUserError{}
	}
	kvp, err := k.getKVParty(m, cfg)
	if err != nil {
		return nil, err
	}
	return kvp, nil
}

func (k *Minder) HostID(m MetaContext, cfg lcl.KVConfig) (*proto.HostID, error) {
	kvp, err := k.initReq(m, cfg)
	if err != nil {
		return nil, err
	}
	ret := kvp.id.Host
	return &ret, nil
}

func (k *Minder) initReqWrite(
	m MetaContext,
	cfg lcl.KVConfig,
) (
	*KVParty,
	*proto.RolePair,
	error,
) {
	kvp, err := k.initReq(m, cfg)
	if err != nil {
		return nil, nil, err
	}
	rp := cfg.Roles.FillDefaults(kvp.IsUser())
	return kvp, &rp, nil
}

func deriveKVStoreKey(
	s core.SharedPrivateSuiter,
) (
	*kv.KeyBundle,
	error,
) {
	k := s.AppKey()
	deriv := proto.NewAppKeyDerivationWithEnum(proto.AppKeyEnum_KVStore)
	ss32, err := core.GenericDeriveKey32(k, &deriv)
	if err != nil {
		return nil, err
	}
	ret := kv.NewKeyBundle(ss32)
	return ret, nil
}

func (kvp *KVParty) kvStoreKeyCurrent(
	m MetaContext,
	r proto.Role,
) (
	*kv.KeyBundle,
	proto.Generation,
	error,
) {
	var zed proto.Generation
	ks, err := kvp.skm.PrivateKeysForRole(m.Base(), r)
	if err != nil {
		return nil, zed, err
	}
	if ks == nil {
		return nil, zed, core.KeyNotFoundError{Which: "shared key seq for role"}
	}
	sps := ks.Current()
	if sps == nil {
		return nil, zed, core.KeyNotFoundError{Which: "current shared key"}
	}
	key, err := deriveKVStoreKey(sps)
	if err != nil {
		return nil, zed, err
	}
	return key, sps.Metadata().Gen, nil
}

func (kvp *KVParty) unboxExternalNonce(
	m MetaContext,
	out core.CryptoPayloader,
	b *proto.SeedBoxExternalNonce,
	n *proto.NaclNonce,
) error {
	kb, err := kvp.kvStoreKeyAtRoleGen(m, b.Rg.Role, b.Rg.Gen)
	if err != nil {
		return err
	}
	key, err := kb.BoxKey()
	if err != nil {
		return err
	}
	err = core.OpenSecretBoxWithNonceInto(out, b.Ctext, n, key)
	if err != nil {
		return err
	}
	return nil
}

func parseSymlink(
	p proto.KVPath,
) (
	*Symlink,
	error,
) {
	pp, err := kv.ParsePath(p)
	if err != nil {
		return nil, err
	}
	return &Symlink{Path: *pp, Raw: p}, nil
}

func (kvp *KVParty) unboxSymlink(
	m MetaContext,
	id proto.SymlinkID,
	sb proto.SmallFileBox,
) (
	*Symlink,
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
	if typ != proto.KVNodeType_Symlink {
		return nil, core.ValidationError("not a symlink")
	}
	ret, err := parseSymlink(sfb.Symlink())
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (kvp *KVParty) unboxSmallFileOrSymlink(
	m MetaContext,
	nn *proto.NaclNonce,
	sb proto.SmallFileBox,
) (
	*lcl.SmallFileBoxPayload,
	error,
) {

	var tmp lcl.SmallFileBoxPayload
	kb, err := kvp.kvStoreKeyAtRoleGen(m, sb.Rg.Role, sb.Rg.Gen)
	if err != nil {
		return nil, err
	}
	bk, err := kb.BoxKey()
	if err != nil {
		return nil, err
	}
	err = core.OpenSecretBoxWithNonceInto(&tmp, sb.DataBox, nn, bk)
	if err != nil {
		return nil, err
	}
	return &tmp, nil
}

func (kvp *KVParty) getSymlink(
	m MetaContext,
	id proto.SymlinkID,
) (
	*symlinkPackage,
	error,
) {
	enc, plain, err := kvp.caches.symlink.Get(m, id)
	if err != nil {
		return nil, err
	}
	if plain != nil {
		return &symlinkPackage{sym: plain, sfb: enc}, nil
	}
	if enc == nil {
		return nil, nil
	}
	ret, err := kvp.unboxSymlink(m, id, *enc)
	if err != nil {
		return nil, err
	}
	kvp.caches.symlink.PutMem(id, enc, ret)
	return &symlinkPackage{sym: ret, sfb: enc}, nil
}

func (kvp *KVParty) getDir(
	m MetaContext,
	dirID proto.DirID,
) (
	*DirPair,
	error,
) {
	ret, err := kvp.caches.dir.Get(m, dirID)
	if err != nil {
		return nil, err
	}
	if ret == nil {
		return nil, nil
	}
	err = kvp.unboxDirSeeds(m, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (kvp *KVParty) unboxDirSeeds(
	m MetaContext,
	d *DirPair,
) error {

	did := d.Id()
	nonce := did.ToNonce()

	doOne := func(dws *DirWithSeed) error {
		if dws == nil || dws.Seed != nil {
			return nil
		}
		var seed proto.DirKeySeed
		err := kvp.unboxExternalNonce(m, &seed, &dws.Box, nonce)
		if err != nil {
			return err
		}
		dws.Seed = &seed
		return nil
	}
	err := doOne(&d.Active)
	if err != nil {
		return err
	}
	err = doOne(d.Encrypting)
	if err != nil {
		return err
	}

	// Update the cache with the unencrypted seed
	kvp.caches.dir.PutMem(d)
	return nil
}

type keyBundle struct {
	*kv.KeyBundle
	rg proto.RoleAndGen
}

func (kvp *KVParty) boxDirSeed(
	m MetaContext,
	r proto.Role,
	s *proto.DirKeySeed,
	i *proto.DirID,
) (
	*proto.SeedBoxExternalNonce,
	*keyBundle,
	error,
) {
	key, gen, err := kvp.kvStoreKeyCurrent(m, r)
	if err != nil {
		return nil, nil, err
	}
	bk, err := key.BoxKey()
	if err != nil {
		return nil, nil, err
	}
	// No need for padding
	box, err := core.SealIntoSecretBoxWithNonce(s, i.ToNonce(), bk)
	if err != nil {
		return nil, nil, err
	}
	ret := proto.SeedBoxExternalNonce{
		Rg: proto.RoleAndGen{
			Role: r,
			Gen:  gen,
		},
		Ctext: box,
	}
	kb := &keyBundle{
		KeyBundle: key,
		rg:        ret.Rg,
	}
	return &ret, kb, nil
}

func (kvp *KVParty) kvStoreKeyAtRoleGen(
	m MetaContext,
	role proto.Role,
	gen proto.Generation,
) (
	*kv.KeyBundle,
	error,
) {
	ks, err := kvp.skm.PrivateKeysForRole(m.Base(), role)
	if err != nil {
		return nil, err
	}
	if ks == nil {
		return nil, core.KeyNotFoundError{Which: "shared key seq for role"}
	}
	sps := ks.At(gen)
	if sps == nil {
		return nil, core.KeyNotFoundError{Which: "shared key at gen"}
	}
	key, err := deriveKVStoreKey(sps)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (k *Minder) getRoot(
	m MetaContext,
	kvp *KVParty,
) (
	*proto.KVRoot,
	error,
) {
	nsroot, err := kvp.getRoot(m)
	if err != nil || nsroot != nil {
		return nsroot, err
	}

	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, err
	}
	root, err := cli.KvGetRoot(m.Ctx(), *auth)

	// No root found is OK, just return nil
	if core.IsKVNoentError(err) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	kb, err := kvp.kvStoreKeyAtRoleGen(m, root.Rg.Role, root.Rg.Gen)
	if err != nil {
		return nil, err
	}

	binding, err := kb.Hmac(root.ToBindingPayload(kvp.id))
	if err != nil {
		return nil, err
	}

	if !binding.Eq(root.BindingMac) {
		return nil, core.VerifyError("binding mac")
	}

	err = kvp.putRoot(m, root)
	if err != nil {
		return nil, err
	}

	return &root, nil
}

func (k *Minder) makeEmptyDir(
	m MetaContext,
	kvp *KVParty,
	rp proto.RolePair,
) (
	*DirPair,
	*keyBundle,
	error,
) {

	var seed proto.DirKeySeed
	err := core.RandomFill(seed[:])
	if err != nil {
		return nil, nil, err
	}

	var dirid proto.DirID
	err = core.RandomFill(dirid[:])
	if err != nil {
		return nil, nil, err
	}

	box, kb, err := kvp.boxDirSeed(m, rp.Read, &seed, &dirid)
	if err != nil {
		return nil, nil, err
	}

	kvd := proto.KVDir{
		Id:        dirid,
		Version:   proto.KVVersion(1),
		Box:       *box,
		WriteRole: rp.Write,
		Status:    proto.KVDirStatus_Active,
	}

	hdr, cli, err := k.clientWithCacheCheck(m, kvp)
	if err != nil {
		return nil, nil, err
	}
	err = cli.KvMkdir(m.Ctx(), rem.KvMkdirArg{
		Hdr: *hdr,
		Dir: kvd,
	})
	if sce := m.catchStaleCacheError(err); sce != nil {
		return nil, nil, sce
	}
	if err != nil {
		return nil, nil, err
	}
	ret := NewDirPairFromSingle(kvp.id, kvd, seed)
	err = kvp.caches.dir.Put(m, ret)
	if err != nil {
		return nil, nil, err
	}
	return ret, kb, err
}

func (k *Minder) mkRoot(
	m MetaContext,
	kvp *KVParty,
	rp proto.RolePair,
) (
	*DirPair,
	error,
) {
	ret, kb, err := k.makeEmptyDir(m, kvp, rp)
	if err != nil {
		return nil, err
	}

	m.Infow("created new root dir", "id", ret.Id())

	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, err
	}
	vers := proto.KVVersion(1)

	bpl := proto.KVRootBindingPayload{
		Party: kvp.id,
		Rg:    kb.rg,
		Root:  ret.Id(),
		Vers:  vers,
	}
	bm, err := kb.Hmac(&bpl)
	if err != nil {
		return nil, err
	}
	root := proto.KVRoot{
		Root:       ret.Id(),
		Vers:       vers,
		Rg:         kb.rg,
		BindingMac: *bm,
	}

	err = cli.KvPutRoot(m.Ctx(), rem.KvPutRootArg{
		Auth: *auth,
		Root: root,
	})
	if err != nil {
		return nil, err
	}
	err = kvp.putRoot(m, root)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (k *Minder) loadDir(
	m MetaContext,
	kvp *KVParty,
	nodeID proto.KVNodeID,
) (
	*DirPair,
	error,
) {
	dirID, err := nodeID.ToDirID()
	if err != nil {
		return nil, err
	}
	return k.loadDirWithDirID(m, kvp, *dirID)
}

func (k *Minder) loadDirWithDirID(
	m MetaContext,
	kvp *KVParty,
	dirID proto.DirID,
) (
	*DirPair,
	error,
) {

	ret, err := kvp.getDir(m, dirID)
	if err != nil || ret != nil {
		return ret, err
	}

	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, err
	}

	res, err := cli.KvGetDir(m.Ctx(), rem.KvGetDirArg{
		Auth: *auth,
		Id:   dirID,
	})
	if err != nil {
		return nil, err
	}

	ret = NewDirPair(kvp.id, res, nil /* no seeds known */)
	err = kvp.unboxDirSeeds(m, ret)
	if err != nil {
		return nil, err
	}
	err = kvp.caches.dir.Put(m, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

type lookupDirentOpts struct {
	forPut bool
}

type lookupDirentRes struct {
	found *Dirent       // if a dirent was found, return it here
	templ *Dirent       // if one wasn't found, return a template for a new one here
	newKb *kv.KeyBundle // always the KeyBundle of the newer parent directory
}

func (k *Minder) lookupDirent(
	m MetaContext,
	kvp *KVParty,
	wd *DirPair,
	comp proto.KVPathComponent,
	opts lookupDirentOpts,
) (
	*lookupDirentRes,
	error,
) {
	var comps []rem.KVNameMACAtDirVersion
	var boxes []*proto.SecretBox
	var kbs []*kv.KeyBundle
	var didLookup bool

	kbsMap := make(map[proto.KVVersion]*kv.KeyBundle)

	fillRet := func(ret *lookupDirentRes) *lookupDirentRes {
		ret.newKb = kbs[0]
		if ret.templ != nil {
			ret.templ.DirVersion = wd.WriteTo().KVDir.Version
		}
		return ret
	}

	doOneCacheLookup := func(d *DirWithSeed) (*Dirent, error) {
		if d.Seed == nil {
			return nil, core.InternalError("no seed")
		}
		didLookup = true

		pyld := lcl.KVDirentNamePayload{
			ParentDir:  d.KVDir.Id,
			DirVersion: d.KVDir.Version,
			Name:       comp,
		}
		kb := kv.NewKeyBundle(d.Seed.ToSecretSeed32())
		kbs = append(kbs, kb)
		kbsMap[d.KVDir.Version] = kb
		mac, err := kb.Hmac(&pyld)
		if err != nil {
			return nil, err
		}
		comps = append(comps, rem.KVNameMACAtDirVersion{
			Mac:     *mac,
			DirVers: d.KVDir.Version,
		})
		if opts.forPut {
			box, err := kb.BoxPadded(&pyld)
			if err != nil {
				return nil, err
			}
			boxes = append(boxes, box)
		}
		de, err := kvp.caches.dirent.Get(m, *mac)
		if err != nil {
			return nil, err
		}
		return de, nil
	}

	var found *Dirent

	if wd.Encrypting != nil {
		ret, err := doOneCacheLookup(wd.Encrypting)
		if err != nil {
			return nil, err
		}
		found = ret
	}

	if found == nil {
		ret, err := doOneCacheLookup(&wd.Active)
		if err != nil {
			return nil, err
		}
		found = ret
	}

	if found != nil {
		ret := fillRet(&lookupDirentRes{found: found})
		return ret, nil
	}

	if !didLookup {
		return nil, core.InternalError("no lookup")
	}

	// At this point, we haven't found a dirent in the cache, so let's go to the server.
	hdr, cli, err := k.clientWithCacheCheck(m, kvp)
	if err != nil {
		return nil, err
	}
	arg := rem.KvGetArg{
		Hdr: *hdr,
		Path: rem.KVNodePathMultiple{
			Names:     comps,
			ParentDir: wd.Id(),
		},
		Follow: rem.FollowBehavior_Any,
	}
	res, err := cli.KvGet(m.Ctx(), arg)

	if sce := m.catchStaleCacheError(err); sce != nil {
		return nil, sce
	}

	if core.IsKVNoentError(err) && opts.forPut {

		tmp := comp

		// We can return the "template" of the dirent to fill in later, since we already
		// computed many of the fields.
		templ := Dirent{
			KVDirent: proto.KVDirent{
				ParentDir:  wd.Id(),
				DirVersion: wd.WriteTo().Version,
				NameMac:    comps[0].Mac,
				NameBox:    *boxes[0],
				Version:    proto.KVVersion(0),
			},
			Nm: &tmp,
		}
		// Make a random dirent ID
		err = core.RandomFill(templ.Id[:])
		if err != nil {
			return nil, err
		}

		ret := fillRet(&lookupDirentRes{templ: &templ})

		// Note that we're returning no error, since for a put, it's fine to not
		// find the dirent.
		return ret, nil
	}

	if err != nil {
		return nil, err
	}

	kb := kbsMap[res.De.DirVersion]
	if kb == nil {
		return nil, core.KeyNotFoundError{Which: "dir KeyBundle"}
	}

	bpl := res.De.ToBindingPayload()
	bm, err := kb.Hmac(bpl)
	if err != nil {
		return nil, err
	}
	if !bm.Eq(res.De.BindingMac) {
		return nil, core.VerifyError("dirent binding mac")
	}

	tmpComp := comp

	de := Dirent{
		KVDirent: res.De,
		Nm:       &tmpComp,
	}
	err = kvp.caches.dirent.Put(m, &de)
	if err != nil {
		return nil, err
	}
	typ := proto.KVNodeType_None
	if res.Data != nil {
		typ, err = res.Data.GetT()
		if err != nil {
			return nil, err
		}
	}
	switch typ {
	case proto.KVNodeType_None:
		return nil, core.KVNoentError{}
	case proto.KVNodeType_Dir:
		raw := res.Data.Dir()
		dir := NewDirPair(kvp.id, raw, nil)
		err = kvp.caches.dir.Put(m, dir)
		if err != nil {
			return nil, err
		}
	case proto.KVNodeType_Symlink:
		slid, err := res.De.Value.ToSymlinkID()
		if err != nil {
			return nil, err
		}
		err = kvp.caches.symlink.Put(m, *slid, res.Data.Symlink(), nil)
		if err != nil {
			return nil, err
		}
	case proto.KVNodeType_SmallFile:
		sfid, err := res.De.Value.ToSmallFileID()
		if err != nil {
			return nil, err
		}
		err = kvp.caches.smallFile.Put(m, *sfid, res.Data.Smallfile(), nil)
		if err != nil {
			return nil, err
		}
	case proto.KVNodeType_File:
		fid, err := res.De.Value.ToFileID()
		if err != nil {
			return nil, err
		}
		err = kvp.caches.lfmd.Put(m, *fid, res.Data.File(), nil)
		if err != nil {
			return nil, err
		}
	}
	ret := fillRet(&lookupDirentRes{found: &de})
	return ret, nil
}

type linkNodeOpts struct {
	perms       proto.RolePair
	overwriteOk bool
	direntVers  *proto.KVVersion
}

func (k *Minder) linkNode(
	m MetaContext,
	kvp *KVParty,
	wd *DirPair,
	comp proto.KVPathComponent,
	nodeID proto.KVNodeID,
	opts linkNodeOpts,
) (
	*Dirent,
	error,
) {

	newDirent, err := k.prepareDirent(m, kvp, wd, comp, nodeID, opts)
	if err != nil {
		return nil, err
	}
	err = k.putDirent(m, kvp, []*Dirent{newDirent})
	if err != nil {
		return nil, err
	}
	return newDirent, nil
}

func (k *Minder) prepareDirent(
	m MetaContext,
	kvp *KVParty,
	wd *DirPair,
	comp proto.KVPathComponent,
	nodeID proto.KVNodeID,
	opts linkNodeOpts,
) (
	*Dirent,
	error,
) {

	assertDirentVersion := func(d *Dirent) error {
		switch {
		case opts.direntVers == nil:
			return nil
		case d == nil && *opts.direntVers != 0:
			return core.KVRaceError("dirent")
		case d != nil && d.Version != *opts.direntVers:
			return core.KVRaceError("dirent")
		default:
			return nil
		}
	}

	doLookup := func() (*lookupDirentRes, error) {
		de, err := k.lookupDirent(m, kvp, wd, comp, lookupDirentOpts{forPut: true})
		if err != nil {
			return nil, err
		}
		if de.templ != nil {
			err := assertDirentVersion(nil)
			if err != nil {
				return nil, err
			}
			return de, nil
		}
		if de.found == nil {
			return nil, core.InternalError("unexpected nil dirent")
		}
		found := de.found
		typ, err := found.Type()
		if err != nil {
			return nil, err
		}
		switch typ {
		case proto.KVNodeType_File, proto.KVNodeType_SmallFile:
			if !opts.overwriteOk {
				return nil, core.KVExistsError{}
			}
		case proto.KVNodeType_None:
			// noop
		default:
			return nil, core.KVExistsError{}
		}
		err = assertDirentVersion(found)
		if err != nil {
			return nil, err
		}
		de.templ = de.found
		de.found = nil
		return de, nil
	}

	res, err := doLookup()
	if err != nil {
		return nil, err
	}
	if res == nil || res.templ == nil {
		return nil, core.InternalError("unexpected nil dirent template")
	}

	newDirent, err := res.templ.edit(m, nodeID, opts, res.newKb)
	if err != nil {
		return nil, err
	}
	return newDirent, nil

}

func Tombstone() proto.KVNodeID {
	var ret proto.KVNodeID
	return ret
}

func (d *Dirent) edit(
	m MetaContext,
	nodeID proto.KVNodeID,
	opts linkNodeOpts,
	kb *kv.KeyBundle,
) (
	*Dirent,
	error,
) {

	ret := *d
	ret.Version++
	ret.WriteRole = opts.perms.Write
	ret.Value = nodeID

	err := ret.mac(kb)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (d *Dirent) mac(kb *kv.KeyBundle) error {

	// The binding mac prevents the server from reassigning the value for this directory entry.
	// It won't protect against rollback, which we need the transparency tree for.
	bmp := d.ToBindingPayload()
	binding, err := kb.Hmac(bmp)
	if err != nil {
		return err
	}
	d.BindingMac = *binding
	return nil
}

type symlinkPackage struct {
	sfb *proto.SmallFileBox
	sym *Symlink
}

func (k *Minder) loadSymlink(
	m MetaContext,
	kvp *KVParty,
	nodeID proto.KVNodeID,
) (
	*symlinkPackage,
	error,
) {
	slid, err := nodeID.ToSymlinkID()
	if err != nil {
		return nil, err
	}
	sl, err := kvp.getSymlink(m, *slid)
	if err != nil {
		return nil, err
	}
	if sl != nil {
		return sl, nil
	}
	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, err
	}

	res, err := cli.KvGetNode(m.Ctx(), rem.KvGetNodeArg{
		Auth: *auth,
		Id:   nodeID,
	})
	if err != nil {
		return nil, err
	}
	typ, err := res.GetT()
	if err != nil {
		return nil, err
	}
	if typ != proto.KVNodeType_Symlink {
		return nil, core.BadServerDataError("not a symlink")
	}
	sfb := res.Symlink()
	ret, err := kvp.unboxSymlink(m, *slid, sfb)
	if err != nil {
		return nil, err
	}
	err = kvp.caches.symlink.Put(m, *slid, sfb, ret)
	if err != nil {
		return nil, err
	}
	return &symlinkPackage{sym: ret, sfb: &sfb}, nil
}

func (k *Minder) putDirent(
	m MetaContext,
	kvp *KVParty,
	newDirents []*Dirent,
) error {

	hdr, cli, err := k.clientWithCacheCheck(m, kvp)
	if err != nil {
		return err
	}

	var lst []proto.KVDirent
	for _, d := range newDirents {
		lst = append(lst, d.KVDirent)
	}

	err = cli.KvPut(m.Ctx(), rem.KvPutArg{
		Hdr:     *hdr,
		Dirents: lst,
	})
	if sce := m.catchStaleCacheError(err); sce != nil {
		return sce
	}
	if err != nil {
		return err
	}

	for _, d := range newDirents {
		err = kvp.caches.dirent.Put(m, d)
		if err != nil {
			return err
		}
	}
	return nil
}

// mkdirRoot special-cases making the root directory as an active effect (as
// opposed to a passive side effect).
func (k *Minder) mkdirRoot(
	m MetaContext,
	kvp *KVParty,
	rp *proto.RolePair,
) (
	*proto.DirID,
	error,
) {
	root, err := k.getRoot(m, kvp)
	if err != nil {
		return nil, err
	}
	if root != nil {
		return nil, core.KVExistsError{}
	}
	if rp == nil {
		rp = kvp.DefaultRootPerms()
	}
	wd, err := k.mkRoot(m, kvp, *rp)
	if err != nil {
		return nil, err
	}
	ret := wd.Id()
	m.Infow("created root directory", "id", ret, "fqp", kvp.id)
	return &ret, nil
}

func (k *Minder) Mkdir(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
) (*proto.DirID, error) {
	kvp, rp, err := k.initReqWrite(m, cfg)
	if err != nil {
		return nil, err
	}

	pap, err := kv.ParseAbsPath(path)
	if err != nil {
		return nil, err
	}

	if len(pap.Components) == 0 {
		return k.mkdirRoot(m, kvp, rp)
	}

	var ret *proto.DirID

	err = k.retryCacheLoop(m, kvp, func(m MetaContext) error {

		dp, err := k.walkFromRoot(m, kvp, pap,
			walkOpts{
				mkdirP:         cfg.MkdirP,
				writePerms:     rp,
				needCreate:     true,
				writePermsRoot: kvp.DefaultRootPerms(),
			},
		)
		if err != nil {
			return err
		}
		if dp.dir == nil {
			return core.InternalError("unexpected nil directory")
		}
		tmp := dp.dir.Id()
		ret = &tmp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func newNodeID(typ proto.KVNodeType) (*proto.KVNodeID, error) {
	var id proto.KVNodeID
	id[0] = byte(typ)
	err := core.RandomFill(id[1:])
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func (k *Minder) Symlink(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	target proto.KVPath,
) (
	*PutFileRes,
	error,
) {
	return k.putSymlink(m, cfg, path, target)
}

func (k *Minder) Readlink(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
) (
	*proto.KVPath,
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
	var ret *proto.KVPath
	err = k.retryCacheLoop(m, kvp, func(m MetaContext) error {
		dp, err := k.walkFromRoot(m, kvp, pap, walkOpts{readlink: true})
		if err != nil {
			return err
		}
		if dp.leaf == nil {
			return core.InternalError("unexpected nil leaf")
		}
		sl, err := k.loadSymlink(m, kvp, *dp.leaf)
		if err != nil {
			return err
		}
		ret = &sl.sym.Raw
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (k *Minder) statFile(
	m MetaContext,
	kvp *KVParty,
	typ proto.KVNodeType,
	de *Dirent,
	ret *lcl.KVStat,
) error {
	if de == nil {
		return core.InternalError("unexpected nil leaf")
	}
	ret.Write = de.WriteRole
	switch typ {
	case proto.KVNodeType_SmallFile:
		sfid, err := de.Value.ToSmallFileID()
		if err != nil {
			return err
		}
		sf, err := k.getSmallFile(m, kvp, *sfid)
		if err != nil {
			return err
		}
		ret.Read = sf.box.Rg
		ret.V = lcl.NewKVStatVarWithSmallfile(lcl.KVStatFile{
			Size: proto.Size(len(sf.data)),
		})
	case proto.KVNodeType_File:
		fid, err := de.Value.ToFileID()
		if err != nil {
			return err
		}
		lfmd, _, err := k.getFileMetadata(m, kvp, *fid)
		if err != nil {
			return err
		}
		ret.Read = lfmd.Rg
		ret.V = lcl.NewKVStatVarWithFile(lcl.KVStatFile{
			Size: 0,
		})
	}

	return nil
}

func (k *Minder) Unlink(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
) error {
	kvp, rp, err := k.initReqWrite(m, cfg)
	if err != nil {
		return err
	}
	pap, err := kv.ParseAbsPath(path)
	if err != nil {
		return err
	}
	return k.retryCacheLoop(m, kvp, func(m MetaContext) error {
		return k.unlinkInner(m, cfg, kvp, rp, pap)
	})
}

func (k *Minder) unlinkInner(
	m MetaContext,
	cfg lcl.KVConfig,
	kvp *KVParty,
	rp *proto.RolePair,
	pap *kv.ParsedPath,
) error {
	wr, err := k.walkFromRoot(m, kvp, pap, walkOpts{unlink: true})
	if err != nil {
		return err
	}
	lde := wr.lde
	if lde == nil || lde.found == nil {
		return core.InternalError("expected lde.found")
	}
	if lde.found.Value.IsTombstone() {
		return core.KVNoentError{Path: pap.Base().ToPath()}
	}
	if lde.found.Value.IsDir() && !cfg.Recursive {
		return core.KVRmdirNeedRecursiveError{}
	}
	tmp, err := lde.found.edit(m, Tombstone(), linkNodeOpts{perms: *rp}, lde.newKb)
	if err != nil {
		return err
	}
	err = k.putDirent(m, kvp, []*Dirent{tmp})
	if err != nil {
		return err
	}
	return nil
}

func (k *Minder) Stat(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
) (
	*lcl.KVStat,
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
	var ret *lcl.KVStat
	err = k.retryCacheLoop(m, kvp, func(m MetaContext) error {
		tmp, err := k.statInner(m, cfg, kvp, pap)
		if err != nil {
			return err
		}
		ret = tmp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (k *Minder) statInner(
	m MetaContext,
	cfg lcl.KVConfig,
	kvp *KVParty,
	pap *kv.ParsedPath,
) (
	*lcl.KVStat,
	error,
) {

	wr, err := k.walkFromRoot(m, kvp, pap, walkOpts{stat: true, readlink: cfg.NoFollow})
	if err != nil {
		return nil, err
	}

	var ret lcl.KVStat
	var typ proto.KVNodeType
	if wr.de != nil {
		typ, err = wr.de.Type()
		if err != nil {
			return nil, err
		}
		tmp := wr.de.KVDirent
		ret.De = &tmp
	}

	switch {
	case wr.dir != nil:
		active := wr.dir.Active
		ret.Read = active.Box.Rg
		ret.Write = active.WriteRole
		ret.V = lcl.NewKVStatVarWithDir(lcl.KVStatDir{
			Vers: active.Version,
		})
	case typ == proto.KVNodeType_File || typ == proto.KVNodeType_SmallFile:
		err = k.statFile(m, kvp, typ, wr.de, &ret)
		if err != nil {
			return nil, err
		}
	case typ == proto.KVNodeType_Symlink:
		sp, err := k.loadSymlink(m, kvp, wr.de.Value)
		if err != nil {
			return nil, err
		}
		ret.Read = sp.sfb.Rg
		ret.Write = wr.de.WriteRole
		ret.V = lcl.NewKVStatVarWithSymlink(lcl.KVStatSymlink{
			Target: sp.sym.Raw,
		})

	default:
		return nil, core.KVTypeError("unexpected node type")
	}

	return &ret, nil
}

func (k *Minder) GetUsage(
	m MetaContext,
	cfg lcl.KVConfig,
) (
	*proto.KVUsage,
	error,
) {
	kvp, err := k.initReq(m, cfg)
	if err != nil {
		return nil, err
	}
	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, err
	}
	res, err := cli.KvUsage(m.Ctx(), *auth)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (k *Minder) List(
	m MetaContext,
	cfg lcl.KVConfig,
	path proto.KVPath,
	id *proto.DirID,
	opts rem.KVListOpts,
) (
	*lcl.CliKVListRes,
	error,
) {
	kvp, err := k.initReq(m, cfg)
	if err != nil {
		return nil, err
	}
	if id != nil {
		return k.listWithDirID(m, kvp, *id, opts)
	}

	pap, err := kv.ParseAbsPath(path)
	if err != nil {
		return nil, err
	}
	var ret *lcl.CliKVListRes
	err = k.retryCacheLoop(m, kvp, func(m MetaContext) error {
		tmp, err := k.listInner(m, kvp, pap, opts)
		if err != nil {
			return err
		}
		ret = tmp
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func loadDirKeys(
	dp *DirPair,
) map[proto.KVVersion]*kv.KeyBundle {
	ret := make(map[proto.KVVersion]*kv.KeyBundle)
	add := func(d *DirWithSeed) {
		if d == nil {
			return
		}
		kb := kv.NewKeyBundle(d.Seed.ToSecretSeed32())
		ret[d.KVDir.Version] = kb
	}
	add(&dp.Active)
	add(dp.Encrypting)
	return ret
}

func openDirentToKVListEntry(
	kbsMap map[proto.KVVersion]*kv.KeyBundle,
	dirID proto.DirID,
	de *proto.KVDirent,
) (
	proto.KVPathComponent,
	*lcl.KVListEntry,
	error,
) {
	var name proto.KVPathComponent
	var pyld lcl.KVDirentNamePayload
	de.ParentDir = dirID
	kb := kbsMap[de.DirVersion]
	if kb == nil {
		return name, nil, core.KeyNotFoundError{Which: "dir key"}
	}
	err := kb.Unbox(&pyld, de.NameBox)
	if err != nil {
		return name, nil, err
	}
	mac, err := kb.Hmac(&pyld)
	if err != nil {
		return name, nil, err
	}
	if !mac.Eq(de.NameMac) {
		return name, nil, core.VerifyError("dirent name mac")
	}
	bpk := de.ToBindingPayload()
	bm, err := kb.Hmac(bpk)
	if err != nil {
		return name, nil, err
	}
	if !bm.Eq(de.BindingMac) {
		return name, nil, core.VerifyError("dirent binding mac")
	}
	// Tombstoned dirents are not included in the list,

	if de.Value.IsTombstone() {
		return pyld.Name, nil, nil
	}
	kvle := lcl.KVListEntry{
		De:    de.Id,
		Name:  pyld.Name,
		Write: de.WriteRole,
		Value: de.Value,
		Ctime: de.Ctime,
	}
	return pyld.Name, &kvle, nil
}

func (k *Minder) listWithDirID(
	m MetaContext,
	kvp *KVParty,
	dirID proto.DirID,
	opts rem.KVListOpts,
) (
	*lcl.CliKVListRes,
	error,
) {
	// Will hit the cache in almost all cases.
	dir, err := k.loadDirWithDirID(m, kvp, dirID)
	if err != nil {
		return nil, err
	}

	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, err
	}
	res, err := cli.KvList(
		m.Ctx(),
		rem.KvListArg{
			Auth: *auth,
			Dir:  dirID,
			Opts: opts,
		},
	)
	if err != nil {
		return nil, err
	}

	kbsMap := loadDirKeys(dir)

	var ret lcl.CliKVListRes
	ret.Ents = make([]lcl.KVListEntry, 0, len(res.Ents))
	for _, de := range res.Ents {
		_, kvle, err := openDirentToKVListEntry(kbsMap, dirID, &de)
		if err != nil {
			return nil, err
		}
		if kvle != nil {
			ret.Ents = append(ret.Ents, *kvle)
		}
	}

	if !res.Final {
		if len(res.Ents) == 0 {
			return nil, core.BadServerDataError("unexpected empty list for non-final")
		}
		lst := core.Last(res.Ents)
		typ, err := opts.Start.GetT()
		if err != nil {
			return nil, err
		}
		var nxt proto.KVListPagination
		if typ == proto.KVListPaginationType_Time {
			nxt = proto.NewKVListPaginationWithTime(lst.Ctime)
		} else {
			nxt = proto.NewKVListPaginationWithMac(lst.NameMac)
		}
		ret.Nxt = &lcl.KVListNext{
			Id:  dirID,
			Nxt: nxt,
		}
	}

	// If the server sent down small file boxes for some files, we can just
	// inject them into the cache here. We'll only hit this loop if
	// opts.LoadSmallFiles is true, but no need to check, since we'll get an
	// empty list otherwise.
	for _, ext := range res.ExtEnts {
		pos := ext.Pos
		if int(pos) >= len(res.Ents) {
			return nil, core.BadServerDataError("ext po out of range")
		}
		ent := &res.Ents[pos]
		sfid, err := ent.Value.ToSmallFileID()
		if err != nil {
			return nil, err
		}
		err = kvp.caches.smallFile.Put(m, *sfid, ext.Sfb, nil)
		if err != nil {
			return nil, err
		}
	}
	return &ret, nil
}

func (k *Minder) openDir(
	m MetaContext,
	kvp *KVParty,
	pap *kv.ParsedPath,
) (
	*proto.DirID,
	error,
) {
	wr, err := k.walkFromRoot(m, kvp, pap, walkOpts{stat: true})
	if err != nil {
		return nil, err
	}

	// Special case: if we're listing the root directory, we don't actually
	// do any walking, so we won't have a directory entry below. As such, just
	// use the active directory ID where we started.
	if len(pap.Components) == 0 && pap.LeadingSlash && wr.dir != nil {
		return &wr.dir.Active.Id, nil
	}
	if wr.de == nil {
		return nil, core.KVPathError("path not found")
	}
	typ, err := wr.de.Type()
	if err != nil {
		return nil, err
	}
	if typ != proto.KVNodeType_Dir {
		return nil, core.KVTypeError("not a directory")
	}
	id := wr.de.Value
	did, err := id.ToDirID()
	if err != nil {
		return nil, err
	}
	return did, nil
}

func (k *Minder) listInner(
	m MetaContext,
	kvp *KVParty,
	pap *kv.ParsedPath,
	opts rem.KVListOpts,
) (
	*lcl.CliKVListRes,
	error,
) {
	did, err := k.openDir(m, kvp, pap)
	if err != nil {
		return nil, err
	}
	ret, err := k.listWithDirID(m, kvp, *did, opts)
	if err != nil {
		return nil, err
	}
	ret.Parent = pap.AsDir().Export()
	return ret, nil
}

type Lock struct {
	rem.KVLock
	Minder *Minder
	Cfg    lcl.KVConfig
}

func (k *Minder) AcquireLock(
	m MetaContext,
	cfg lcl.KVConfig,
	id proto.KVDirentIDPair,
	timeout time.Duration,
) (
	*Lock,
	error,
) {
	kvp, _, err := k.initReqWrite(m, cfg)
	if err != nil {
		return nil, err
	}
	auth, cli, err := k.client(m, kvp)
	if err != nil {
		return nil, err
	}
	var lockID rem.LockID
	err = core.RandomFill(lockID[:])
	if err != nil {
		return nil, err
	}

	plock := rem.KVLock{
		Idp:    id,
		LockID: lockID,
	}

	// By default, this is 60s, but for testing, we might want to make it a lot shorter.
	if timeout == 0 {
		kvcfg, err := m.G().Cfg().KvConfig()
		if err != nil {
			return nil, err
		}
		timeout = kvcfg.LockTimeout
	}

	err = cli.KvLockAcquire(m.Ctx(), rem.KvLockAcquireArg{
		Auth:    *auth,
		Lock:    plock,
		Timeout: proto.ExportDurationMilli(timeout),
	})
	if err != nil {
		return nil, err
	}
	ret := Lock{
		KVLock: plock,
		Minder: k,
		Cfg:    cfg,
	}
	return &ret, nil
}

func (l *Lock) Release(m MetaContext) error {

	kvp, _, err := l.Minder.initReqWrite(m, l.Cfg)
	if err != nil {
		return err
	}

	auth, cli, err := l.Minder.client(m, kvp)
	if err != nil {
		return err
	}
	err = cli.KvLockRelease(m.Ctx(), rem.KvLockReleaseArg{
		Auth: *auth,
		Lock: l.KVLock,
	})
	if err != nil {
		return err
	}
	return nil
}
