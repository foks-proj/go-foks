// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

type evilEnv struct {
	tew       *TestEnvWrapper
	a         *TestUser
	b         *TestUser
	r         *TestUser
	q         *TestUser
	role      proto.Role
	rk        *core.RoleKey
	qNameOrig proto.Name
}

func (e *evilEnv) poke(t *testing.T) {
	e.tew.DirectMerklePokeForLeafCheck(t)
}

func PokeMerklePipelineInTest(t *testing.T, m shared.MetaContext) {
	common.PokeMerklePipelineInTest(t, m)
}

func newEvilEnv(t *testing.T) *evilEnv {
	tew := ForkNewTestEnvWrapper(t)
	pushShutdownHook(func() error {
		tew.Shutdown()
		return nil
	})
	a := tew.NewTestUserFakeRoot(t)
	b := tew.NewTestUserFakeRoot(t)
	r := tew.NewTestUserFakeRoot(t)
	q := tew.NewTestUserFakeRoot(t)

	grantToB := func(u *TestUser) {
		cli := tew.userCli(t, u)
		_, err := cli.GrantLocalViewPermissionForUser(context.Background(),
			rem.GrantLocalViewPermissionPayload{
				Viewee: u.uid.ToPartyID(),
				Viewer: b.uid.ToPartyID(),
			},
		)
		require.NoError(t, err)
	}

	// A we'll use for most operations
	grantToB(a)

	// R is a user who has a revoke for us to play with
	grantToB(r)

	// Q is a user who has a renme for us to play with
	grantToB(q)

	m := tew.MetaContext()
	PokeMerklePipelineInTest(t, m)

	role := proto.NewRoleDefault(proto.RoleType_OWNER)
	a.ProvisionNewDevice(t, a.eldest, "yoyodyne 4k", proto.DeviceType_Computer, role)
	pickle := r.ProvisionNewDevice(t, r.eldest, "picklephone 5+", proto.DeviceType_Computer, role)
	tew.DirectMerklePokeForLeafCheck(t)

	// Now Q does a rename
	qNameOrig := q.UsernameNormalized(t)
	changeUsername(m.Ctx(), t, q)

	// Here's r's revoked eldest, signed with her most recent device
	r.RevokeDevice(t, pickle, r.eldest)
	tew.DirectMerklePokeForLeafCheck(t)

	rk, err := core.ImportRole(role)
	require.NoError(t, err)

	return &evilEnv{
		tew:       tew,
		a:         a,
		b:         b,
		r:         r,
		q:         q,
		rk:        rk,
		role:      proto.NewRoleDefault(proto.RoleType_OWNER),
		qNameOrig: qNameOrig,
	}
}

var gEvilEnv *evilEnv

func getEvilEnv(t *testing.T) *evilEnv {
	if gEvilEnv == nil {
		gEvilEnv = newEvilEnv(t)
	}
	return gEvilEnv
}

type evilServerTestHarness struct {
	cli     *libclient.UserLoader
	srv     *shared.UserLoader // will be evil!
	g       *shared.GlobalContext
	resHook func(c *rem.UserChain)
	ult     *libclient.ChainLoaderTesting
}

func (t *evilServerTestHarness) ResolveUsername(
	ctx context.Context,
	arg rem.ResolveUsernameArg,
) (
	proto.UID,
	error,
) {
	var zed proto.UID
	return zed, core.NotImplementedError{}
}

func (t *evilServerTestHarness) LoadUserChain(
	ctx context.Context,
	arg rem.LoadUserChainArg,
) (rem.UserChain, error) {
	m := shared.NewMetaContext(ctx, t.g)
	err := t.srv.Run(m, arg)
	if err != nil {
		return rem.UserChain{}, err
	}
	res := t.srv.Res
	if t.resHook != nil {
		t.resHook(&res)
	}
	return res, nil
}

func newEvilServerTestHarness(
	e *TestEnvWrapper,
	uid proto.UID,
	loggedInUID *proto.UID,
) *evilServerTestHarness {
	var role *proto.Role

	// for now, assume that all user devices are at owner level
	if loggedInUID != nil {
		tmp := proto.OwnerRole
		role = &tmp
	}

	srv := shared.NewUserLoader(loggedInUID, role)
	var loadMode libclient.LoadMode
	if loggedInUID != nil && uid.Eq(*loggedInUID) {
		loadMode = libclient.LoadModeSelf
	}
	cli := libclient.NewUserLoader(
		libclient.LoadUserArg{
			Uid:      uid,
			LoadMode: loadMode,
		},
	)
	ult := &libclient.ChainLoaderTesting{
		SkipMerkleLeafValueCheck: true,
	}
	cli.SetTesting(ult)
	ret := &evilServerTestHarness{
		cli: cli,
		srv: srv,
		g:   e.MetaContext().G(),
		ult: ult,
	}
	cli.SetRPCLoader(ret)
	return ret
}

// requireCLE checks that the given error is a ChainLoaderError, and then casts
// the wrapped error to the passed type T.
func requireCLE[T error](t *testing.T, err error) T {
	require.Error(t, err)
	require.IsType(t, core.ChainLoaderError{}, err)
	ule := err.(core.ChainLoaderError)
	require.NotNil(t, ule.Err)
	var tmp T
	require.IsType(t, tmp, ule.Err)
	return ule.Err.(T)
}

func (e *evilEnv) newTestHarnessSelf() *evilServerTestHarness {
	return newEvilServerTestHarness(e.tew, e.a.uid, &e.a.uid)
}

func (e *evilEnv) newTestHarnessBLoadsA() *evilServerTestHarness {
	return newEvilServerTestHarness(e.tew, e.a.uid, &e.b.uid)
}
func (e *evilEnv) newTestHarnessBLoadsR() *evilServerTestHarness {
	return newEvilServerTestHarness(e.tew, e.r.uid, &e.b.uid)
}

func (e *evilEnv) MetaContextA(t *testing.T) libclient.MetaContext {
	return e.tew.NewClientMetaContext(t, e.a)
}

func (e *evilEnv) MetaContextB(t *testing.T) libclient.MetaContext {
	return e.tew.NewClientMetaContext(t, e.b)
}

func (e *evilEnv) MetaContextR(t *testing.T) libclient.MetaContext {
	return e.tew.NewClientMetaContext(t, e.r)
}

// Corrupt the Tree Location of Seqno=1 so that the comitment
// in Seqno=0 doesn't properly verify.
func TestUserLoaderClientEvilServerBadTreeLocation1(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.srv.Evil = &shared.EvilUserLoaderHooks{
		PostLoadTreeLocations: func(u *shared.UserLoader) {
			loc := u.Locs[1]
			loc[0] ^= 0x01
			u.Res.Locations[0] = loc
		},
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	ble := requireCLE[core.CLBadTreeLocationError](t, err)
	require.Equal(t, proto.Seqno(2), ble.Seqno)
}

// Corrupt the tree location of Seqno=1 so that the computed
// merkle path is not correct.
func TestUserLoaderClientEvilServerBadTreeLocation2(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.srv.Evil = &shared.EvilUserLoaderHooks{
		PostLoadTreeLocations: func(u *shared.UserLoader) {
			loc := u.Locs[1]
			loc[0] ^= 0x01
			u.Locs[1] = loc
		},
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	bmpe := requireCLE[core.CLBadMerklePathError](t, err)
	require.Equal(t, proto.Seqno(1), bmpe.Seqno)
	require.Equal(t, "uid", bmpe.Which)
	require.IsType(t, core.MerkleVerifyError(""), bmpe.Err)
}

// Wrong number of merkle path keys, since we delete one
func TestUserLoaderClientEvilServerNotEnoughMerklePathKeys(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.srv.Evil = &shared.EvilUserLoaderHooks{
		PreMerkle: func(u *shared.UserLoader, keys *([]proto.MerkleTreeRFOutput)) {
			l := len(*keys)
			*keys = (*keys)[:l-1]
		},
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	bce := requireCLE[core.CLBadCountError](t, err)
	require.Equal(t, 3, bce.Expected)
	require.Equal(t, 2, bce.Actual)
	require.Equal(t, "merkle-paths", bce.Which)
}

func TestUserLoaderClientEvilServerNotEnoughTreeLocations(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.srv.Evil = &shared.EvilUserLoaderHooks{
		PostLoadTreeLocations: func(u *shared.UserLoader) {
			l := u.Res.Locations
			u.Res.Locations = l[:len(l)-1]
		},
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	bce := requireCLE[core.CLBadCountError](t, err)
	require.Equal(t, 2, bce.Expected)
	require.Equal(t, 1, bce.Actual)
	require.Equal(t, "locations", bce.Which)
}

func mutateLink(
	t *testing.T,
	u *rem.UserChain,
	i int,
	signingKeys []core.Signer,
	mutator func(*proto.LinkInner),
) {
	li, err := u.Links[i].F_1__.Inner.AllocAndDecode(core.DecoderFactory{})
	require.NoError(t, err)
	mutator(li)
	bl, err := li.EncodeTyped(core.EncoderFactory{})
	require.NoError(t, err)
	lo := proto.LinkOuterV1{
		Inner: *bl,
	}
	err = core.SignStacked(&lo, signingKeys)
	require.NoError(t, err)
	link := proto.NewLinkOuterWithV1(lo)
	u.Links[i] = link
}

// bad sequence numbers, since the server just repeats seqno=1
// and spams over seqno=0. this check will fail before the prev
// check fails.
func TestUserLoaderClientEvilServerBadSeqno(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.Links[0] = u.Links[1]
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	bse := requireCLE[core.CLBadSeqnoError](t, err)
	require.Equal(t, proto.Seqno(1), bse.Expected)
	require.Equal(t, proto.Seqno(2), bse.Actual)
	require.Equal(t, "uid", bse.Which)
}

// Make a prev on seqno=0 even though it should be nil.
func TestUserLoaderCliientEvilServerBadPrevNonNilSeq0(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessBLoadsA()
	th.resHook = func(u *rem.UserChain) {
		mutateLink(t, u, 0,
			[]core.Signer{
				ee.a.puks[*ee.rk],
				ee.a.eldest,
			},
			func(li *proto.LinkInner) {
				var stdHash proto.StdHash
				stdHash[30] = 7
				lh := proto.LinkHash(stdHash)
				li.F_0__.Chainer.Base.Prev = &lh
			},
		)
	}
	_, err := th.cli.Run(ee.MetaContextB(t))
	ole := requireCLE[core.CLOpenLinkError](t, err)
	require.Equal(t, 0, ole.N)
	require.Equal(t, core.LinkError("nil prev hash iff seqno==0"), ole.Err)
}

// Make prev=nil on seqno=1, but it should be non-nil.
func TestUserLoaderCliientEvilServerBadPrevNilSeq1(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessBLoadsA()
	th.resHook = func(u *rem.UserChain) {
		mutateLink(t, u, 1,
			[]core.Signer{
				ee.a.devices[1],
				ee.a.devices[0],
			},
			func(li *proto.LinkInner) {
				li.F_0__.Chainer.Base.Prev = nil
			},
		)
	}
	_, err := th.cli.Run(ee.MetaContextB(t))
	ole := requireCLE[core.CLOpenLinkError](t, err)
	require.Equal(t, 1, ole.N)
	require.Equal(t, core.LinkError("nil prev hash iff seqno==0"), ole.Err)
}

// corrupt the prev at seqno=1
func TestUserLoaderCliientEvilServerBadPrevCorruptSeq1(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessBLoadsA()
	th.resHook = func(u *rem.UserChain) {
		mutateLink(t, u, 1,
			[]core.Signer{
				ee.a.devices[1],
				ee.a.devices[0],
			},
			func(li *proto.LinkInner) {
				prev := li.F_0__.Chainer.Base.Prev
				(*prev)[31] ^= 0x04
				li.F_0__.Chainer.Base.Prev = prev
			},
		)
	}
	_, err := th.cli.Run(ee.MetaContextB(t))
	bpe := requireCLE[core.CLBadPrevError](t, err)
	require.Equal(t, proto.Seqno(2), bpe.Seqno)
	require.NotNil(t, bpe.Expected)
	require.NotNil(t, bpe.Actual)
}

func TestUserLoaderEvilServerCorruptSigs(t *testing.T) {
	ee := getEvilEnv(t)
	ma := ee.MetaContextA(t)

	// there should be 2 sigs on the first link (one for PUK and one
	// for the self-signing key). Second link also has two, one for the
	// new device, and one for the old device. Check
	// that any of the 4 sigs being bad will stop the verification
	for l := 0; l < 2; l++ {

		for i := 0; i < 2; i++ {
			// First corrupt the signature
			th := ee.newTestHarnessSelf()
			th.resHook = func(u *rem.UserChain) {
				u.Links[l].F_1__.Signatures[i].F_0__[0] ^= 0x01
			}
			_, err := th.cli.Run(ma)
			ole := requireCLE[core.CLOpenLinkError](t, err)
			require.Equal(t, l, ole.N)
		}

		// next corrupt the signature body / blob
		th := ee.newTestHarnessSelf()
		th.resHook = func(u *rem.UserChain) {
			u.Links[l].F_1__.Inner[0] ^= 0x01
		}
		_, err := th.cli.Run(ma)
		ole := requireCLE[core.CLOpenLinkError](t, err)
		require.Equal(t, l, ole.N)

		// next swap the two signatures
		reverse := func(sigs []proto.Signature) {
			i, j := sigs[0], sigs[1]
			sigs[0], sigs[1] = j, i
		}
		th = ee.newTestHarnessSelf()
		th.resHook = func(u *rem.UserChain) {
			reverse(u.Links[l].F_1__.Signatures)
		}
		_, err = th.cli.Run(ma)
		ole = requireCLE[core.CLOpenLinkError](t, err)
		require.Equal(t, l, ole.N)
	}
}

// Next mess up the merkle root by corrupting the hash a few
// different ways (which will conflict with what we've already
// received above).
func TestUserLoaderClientEvilServerCorruptMerkleRoot1(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.Merkle.Root.F_1__.BackPointers[0] ^= 0x01
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	mve := requireCLE[core.MerkleVerifyError](t, err)
	require.Contains(t, string(mve), "hash mismatch at epno")
}

// Same as above, but corrupt the root node rather than the
// backpointers hash. Don't go too deep here since we should
// be testing these various failure cases against the merkle loader.
func TestUserLoaderClientEvilServerCorruptMerkleRoot2(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.Merkle.Root.F_1__.RootNode[0] ^= 0x01
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	mve := requireCLE[core.MerkleVerifyError](t, err)
	require.Contains(t, string(mve), "hash mismatch at epno")
}

// Check that attempted rollback attacks fail
func TestUserLoaderClientEvilServerMerkleRollback(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	var epno proto.MerkleEpno
	th.resHook = func(u *rem.UserChain) {
		epno = u.Merkle.Root.F_1__.Epno
		u.Merkle.Root.F_1__.Epno = epno - 1
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	mre := requireCLE[core.MerkleRollbackError](t, err)
	require.Equal(t, epno, mre.Have)
	require.Equal(t, epno-1, mre.Saw)
}

// check that we'll reject links from the wrong user.
func TestUserLoaderClientEvilServerWrongUser(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessBLoadsA()
	th.resHook = func(u *rem.UserChain) {
		mutateLink(t, u, 1,
			[]core.Signer{
				ee.a.devices[1],
				ee.a.devices[0],
			},
			func(li *proto.LinkInner) {
				li.F_0__.Entity.Entity = ee.b.uid.EntityID()
			},
		)
	}
	_, err := th.cli.Run(ee.MetaContextB(t))
	ole := requireCLE[core.CLOpenLinkError](t, err)
	require.Equal(t, 1, ole.N)
	require.Equal(t, core.LinkError("wrong user given"), ole.Err)
}

func badSigner(t *testing.T, ee *evilEnv, u *rem.UserChain) {
	li, err := u.Links[1].F_1__.Inner.AllocAndDecode(core.DecoderFactory{})
	require.NoError(t, err)
	li.F_0__.Signer = proto.GroupChangeSigner{
		Key: entityID(t, ee.b.eldest),
	}
	bl, err := li.EncodeTyped(core.EncoderFactory{})
	require.NoError(t, err)
	lo := proto.LinkOuterV1{
		Inner: *bl,
	}
	err = core.SignStacked(&lo, []core.Signer{
		ee.a.devices[1],
		ee.b.eldest,
	})
	require.NoError(t, err)
	link := proto.NewLinkOuterWithV1(lo)
	u.Links[1] = link
}

// check that we'll reject links signed with a key that doesn't
// belong to the user's key set
func TestUserLoaderClientEvilServerBadSigningKey1(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessBLoadsA()
	th.resHook = func(u *rem.UserChain) { badSigner(t, ee, u) }
	_, err := th.cli.Run(ee.MetaContextB(t))
	pe := requireCLE[core.CLInvalidSignerError](t, err)
	require.Equal(t, proto.Seqno(2), pe.Seqno)
}

// Same thing as above, but if you'll note, we hacked the user_loader client
// to postpone the error it gets due to a failed merkle leaf check.
// In this test, we back out that hack, and ensure that we fail
// with the bad merkle leaf error on the bad link.
func TestUserLoaderClientEvilServerBadSigningKey2(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessBLoadsA()
	th.ult.SkipMerkleLeafValueCheck = false
	th.resHook = func(u *rem.UserChain) { badSigner(t, ee, u) }
	_, err := th.cli.Run(ee.MetaContextB(t))
	bmle := requireCLE[core.CLBadMerkleLeafValueError](t, err)
	require.Equal(t, proto.Seqno(2), bmle.Seqno)
}

// Check that eldest links are properly formed.
func TestUserLoaderClientEvilServerBadEldest(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessBLoadsA()
	th.ult.SkipPrevCheck = true
	th.resHook = func(u *rem.UserChain) {
		mutateLink(t, u, 0,
			[]core.Signer{
				ee.a.puks[*ee.rk],
				ee.a.eldest,
			},
			func(li *proto.LinkInner) {
				var c proto.Commitment
				li.F_0__.Metadata = []proto.ChangeMetadata{
					proto.NewChangeMetadataWithDevicename(c),
				}
			},
		)
	}
	_, err := th.cli.Run(ee.MetaContextB(t))
	eerr := requireCLE[core.ULEldestError](t, err)
	require.Equal(t, core.LinkError("expected at least 3 metadata changes"), eerr.Err)
}

// Revoke the eldest and then provision device bobo with exsiting
// device yoyo. But then try to switch the bobo privision so that it
// says eldest did it.
func TestUserLoaderEvilServerSigWithRevokedDevice(t *testing.T) {
	ee := getEvilEnv(t)
	m := ee.tew.MetaContext()
	// Meet our new test user D.
	d := ee.tew.NewTestUserFakeRoot(t)
	PokeMerklePipelineInTest(t, m)

	dcli := ee.tew.userCli(t, d)
	_, err := dcli.GrantLocalViewPermissionForUser(context.Background(),
		rem.GrantLocalViewPermissionPayload{
			Viewee: d.uid.ToPartyID(),
			Viewer: ee.b.uid.ToPartyID(),
		},
	)

	require.NoError(t, err)

	yoyo := d.ProvisionNewDevice(t, d.eldest, "yoyo", proto.DeviceType_Computer, ee.role)
	ee.poke(t)
	d.RevokeDevice(t, yoyo, d.eldest)
	ee.poke(t)
	bobo := d.ProvisionNewDevice(t, yoyo, "bobo", proto.DeviceType_Computer, ee.role)
	ee.poke(t)

	th := newEvilServerTestHarness(ee.tew, d.uid, &ee.b.uid)
	th.resHook = func(u *rem.UserChain) {
		mutateLink(t, u, 3,
			[]core.Signer{
				bobo,
				d.eldest,
			},
			func(li *proto.LinkInner) {
				li.F_0__.Signer = proto.GroupChangeSigner{
					Key: entityID(t, d.eldest),
				}
			},
		)
	}
	_, err = th.cli.Run(ee.MetaContextB(t))
	pe := requireCLE[core.CLInvalidSignerError](t, err)
	require.Equal(t, proto.Seqno(4), pe.Seqno)
	require.Equal(t, entityID(t, d.eldest), pe.Fqe.Entity)
}

// Handle server sending back too few device names for a self-load
func TestUserLoaderClientEvilServerNotEnoughDeviceNames(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		l := len(u.DeviceNames)
		u.DeviceNames = u.DeviceNames[:l-1]
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	bce := requireCLE[core.CLBadCountError](t, err)
	require.Equal(t, "device-names", bce.Which)
	require.Equal(t, 2, bce.Expected)
	require.Equal(t, 1, bce.Actual)
}

func grantViewPermission(t *testing.T, cli rem.UserClient, viewee proto.UID, viewer proto.UID) {
	ctx := context.Background()
	_, err := cli.GrantLocalViewPermissionForUser(ctx,
		rem.GrantLocalViewPermissionPayload{
			Viewee: viewee.ToPartyID(),
			Viewer: viewer.ToPartyID(),
		},
	)
	require.NoError(t, err)
}

// Handle server sending back a bad device name commitment
func TestUserLoaderClientEvilServerBadDeviceNameCommitment(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.DeviceNames[0].Dln.Label.Name += "x"
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	oce := requireCLE[core.ULOpenCommitmentError](t, err)
	require.Equal(t, "device-name", oce.Which)
	require.Equal(t, 0, oce.Idx)
	require.Equal(t, core.VerifyError("commitment failed"), oce.Err)
}

// Check that a server cannot withhold the tail of a chain.
func TestUserClientLoaderEvilServerWithholdRevoke(t *testing.T) {
	ee := getEvilEnv(t)
	m := ee.tew.MetaContext()
	// Meet our new test user q.
	q := ee.tew.NewTestUserFakeRoot(t)
	PokeMerklePipelineInTest(t, m)

	qcli := ee.tew.userCli(t, q)
	grantViewPermission(t, *qcli, q.uid, ee.b.uid)

	yoyo := q.ProvisionNewDevice(t, q.eldest, "yoyo", proto.DeviceType_Computer, ee.role)
	ee.poke(t)
	q.RevokeDevice(t, yoyo, q.eldest)
	ee.poke(t)

	// First attempt, try to splice around the path we're trying to hide.
	th := newEvilServerTestHarness(ee.tew, q.uid, &ee.b.uid)
	th.resHook = func(u *rem.UserChain) {
		// chop off the revoke and the proof-of-absense
		u.Merkle.Paths = append(u.Merkle.Paths[0:4], u.Merkle.Paths[5])
		u.Links = u.Links[0:2]
		u.Locations = u.Locations[0:2]
	}
	_, err := th.cli.Run(ee.MetaContextB(t))
	mue := requireCLE[core.CLBadMerklePathError](t, err)
	require.Equal(t, proto.Seqno(3), mue.Seqno)
	require.Equal(t, "uid", mue.Which)
	require.IsType(t, core.MerkleVerifyError(""), mue.Err)

	// Next attempt, try to claim the revoke is abasense marker
	th = newEvilServerTestHarness(ee.tew, q.uid, &ee.b.uid)
	th.resHook = func(u *rem.UserChain) {
		// chop off the revoke and the proof-of-absense
		u.Merkle.Paths = u.Merkle.Paths[0:5]
		u.Links = u.Links[0:2]
		u.Locations = u.Locations[0:2]
	}
	_, err = th.cli.Run(ee.MetaContextB(t))
	mue = requireCLE[core.CLBadMerklePathError](t, err)
	require.Equal(t, proto.Seqno(3), mue.Seqno)
	require.Equal(t, "uid", mue.Which)
	require.Equal(t, core.MerkleVerifyError("server claimed key was in tree"), mue.Err)
}

func TestUserClientLoaderEvilServerCorruptPUKs(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessBLoadsA()
	th.ult.SkipPrevCheck = true
	th.resHook = func(u *rem.UserChain) {
		mutateLink(t, u, 0,
			[]core.Signer{
				ee.a.puks[*ee.rk],
				ee.a.eldest,
			},
			func(li *proto.LinkInner) {
				li.F_0__.SharedKeys[0].VerifyKey[3] ^= 0x01
			},
		)
	}
	_, err := th.cli.Run(ee.MetaContextB(t))
	ole := requireCLE[core.CLOpenLinkError](t, err)
	require.Equal(t, 0, ole.N)
	require.IsType(t, core.VerifyError(""), ole.Err)
}

// Revoke error: try to revoke a device that isn't currently active.
func TestUserClientLoaderEvilServerBadRevoke(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessBLoadsR()
	th.ult.SkipPrevCheck = true
	th.resHook = func(u *rem.UserChain) {
		mutateLink(t, u, 2,
			[]core.Signer{
				ee.r.puks[*ee.rk],
				ee.r.devices[0],
			},
			func(li *proto.LinkInner) {
				li.F_0__.Changes[0].Member.Id.Entity[2] ^= 0x01
			},
		)
	}
	_, err := th.cli.Run(ee.MetaContextB(t))
	re := requireCLE[core.ULRevokeError](t, err)
	require.Equal(t, proto.Seqno(3), re.Seqno)
	require.IsType(t, core.LinkError("device to revoke is not currently active"), re.Err)
}

func TestUserClientLoaderEvilServerMissingUsername(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.Usernames = nil
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	bce := requireCLE[core.CLBadCountError](t, err)
	require.Equal(t, "names", bce.Which)
	require.Equal(t, 1, bce.Expected)
	require.Equal(t, 0, bce.Actual)
}

func TestUserClientLoaderEvilServerBadUsernameCommitment(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.Usernames[0].Key[2] ^= 0x80
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	oce := requireCLE[core.ULOpenCommitmentError](t, err)
	require.Equal(t, "username", oce.Which)
	require.Equal(t, 0, oce.Idx)
	require.Equal(t, core.VerifyError("commitment failed"), oce.Err)
}

func TestUserClientLoaderEvilServerBadUsernameCannotNormalize(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.UsernameUtf8 += "汉字"
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	ne := requireCLE[core.NameError](t, err)
	require.Equal(t, core.NameError("found invalid character in name"), ne)
}

func TestUserClientLoaderEvilServerBadUsernameDoesNotMatch(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.UsernameUtf8 += "a"
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	require.Error(t, err)
	require.Equal(t, "chain loader error: username commitment does not match supplied username", err.Error())
}

func TestUserClientLoaderEvilServerNoUsernameLinks(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.Merkle.Paths = u.Merkle.Paths[2:]
		u.NumUsernameLinks = 0
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	require.Error(t, err)
	require.Equal(t, "chain loader error: need at least one username link to prove absense of updates", err.Error())
}

func TestUserClientLoaderEvilServerOneUsernameLink(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.resHook = func(u *rem.UserChain) {
		u.Merkle.Paths = u.Merkle.Paths[1:]
		u.NumUsernameLinks = 1
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	require.Error(t, err)
	require.Equal(t, libclient.ChainLoaderGenericError("need at least two username links to establish a username"), err)
}

// We are expecting 2 username merkle paths. Try to corrupt both of the them
// and make sure the merkle path to the root still fails.
func TestUserClientLoaderEvilServerBadUsernameMerklePath(t *testing.T) {
	for i := 0; i < 2; i++ {
		ee := getEvilEnv(t)
		th := ee.newTestHarnessSelf()
		th.resHook = func(u *rem.UserChain) {
			u.Merkle.Paths[i].Path[4] ^= 0x1
		}
		_, err := th.cli.Run(ee.MetaContextA(t))
		mpe := requireCLE[core.CLBadMerklePathError](t, err)
		require.Equal(t, proto.Seqno(i), mpe.Seqno)
		require.Equal(t, core.MerkleVerifyError("failed to match root node hash"), mpe.Err)
	}
}

// Swap out the Username->UID for a different UID and make sure that it's caught. Note we need
// to block some earlier checks that would have failed due to monkeying with the merkle tree.
func TestUserClientLoaderEvilServerBadUsernameLeaf(t *testing.T) {
	ee := getEvilEnv(t)
	th := ee.newTestHarnessSelf()
	th.ult.SkipMerklePathCheck = true
	th.resHook = func(u *rem.UserChain) {
		v := rem.NewEntityIDMerkleValueWithV1(ee.b.uid.EntityID())
		h, err := core.PrefixedHash(&v)
		require.NoError(t, err)
		u.Merkle.Paths[0].Terminal.F_1__.Leaf = *h
	}
	_, err := th.cli.Run(ee.MetaContextA(t))
	mlve := requireCLE[core.CLBadMerkleLeafValueError](t, err)
	require.Equal(t, "username", mlve.Which)
	require.Equal(t, proto.Seqno(0), mlve.Seqno)
}

// Test user renames, and server trying to hide renames by sending the path for the previous
// username.
func TestUserClientLoaderEvilServerChangeUsernameSendOldMerklePath(t *testing.T) {
	ee := getEvilEnv(t)
	th := newEvilServerTestHarness(ee.tew, ee.q.uid, &ee.b.uid)
	th.srv.Evil = &shared.EvilUserLoaderHooks{
		PreUsernameMerkleKeys: func(u *shared.UserLoader) func() {
			orig := u.Un
			u.Un = ee.qNameOrig
			return func() {
				u.Un = orig
			}
		},
	}
	_, err := th.cli.Run(ee.MetaContextB(t))
	mve := requireCLE[core.CLBadMerklePathError](t, err)
	require.Equal(t, proto.Seqno(0), mve.Seqno)
	require.Equal(t, "username", mve.Which)
	require.Equal(t, core.MerkleVerifyError("failed to match root node hash"), mve.Err)
}

func TestUserClientLoaderEvilServerChangeUsernameIncrementalLoad(t *testing.T) {
	ee := getEvilEnv(t)
	x := ee.tew.NewTestUserFakeRoot(t)
	origName := x.name
	m := ee.tew.MetaContext()
	PokeMerklePipelineInTest(t, m)

	cli := ee.tew.userCli(t, x)
	grantViewPermission(t, *cli, x.uid, ee.b.uid)

	newHarness := func() *evilServerTestHarness {
		return newEvilServerTestHarness(ee.tew, x.uid, &ee.b.uid)
	}

	mb := ee.MetaContextB(t)

	th := newHarness()
	_, err := th.cli.Run(mb)
	require.NoError(t, err)

	changeUsername(m.Ctx(), t, x)
	PokeMerklePipelineInTest(t, m)

	th = newHarness()
	th.resHook = func(u *rem.UserChain) {
		u.Merkle.Paths = u.Merkle.Paths[1:]
		u.NumUsernameLinks = 1
	}
	_, err = th.cli.Run(mb)
	require.NotNil(t, th.cli.Existing())
	wanted := libclient.ChainLoaderGenericError("need at least two username links to establish a username")
	require.Equal(t, wanted, err)

	th = newHarness()
	th.resHook = func(u *rem.UserChain) {
		u.UsernameUtf8 = origName
	}
	_, err = th.cli.Run(mb)
	require.Equal(t, libclient.ChainLoaderGenericError("username commitment does not match supplied username"), err)

	// Now check that it works if no errors are injected.
	th = newHarness()
	_, err = th.cli.Run(mb)
	require.NoError(t, err)
}
