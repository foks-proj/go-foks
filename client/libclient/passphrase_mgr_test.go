// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

type userPassphraseServerRecord struct {
	salt          *proto.PassphraseSalt
	devKey        *proto.Ed25519PublicKey
	ppKey         proto.EntityID
	ppgen         proto.PassphraseGeneration
	skmwkListBox  *proto.SecretBox
	passphraseBox *proto.PpePassphraseBox
	pukBox        *proto.PpePUKBox
}

func (u *userPassphraseServerRecord) isZero() bool {
	return u.salt == nil && u.ppKey == nil &&
		!u.ppgen.IsValid() && u.skmwkListBox == nil &&
		u.passphraseBox == nil && u.pukBox == nil
}

type passphraseServerMock struct {
	users map[proto.UID](*userPassphraseServerRecord)
	key   proto.HMACKey
}

type userServerMock struct {
	uid proto.UID
	rec *userPassphraseServerRecord
}

func (p *passphraseServerMock) StretchOpts() StretchOpts {
	return StretchOpts{IsTest: true}
}

func (p *passphraseServerMock) MakeUserSettingsLink(
	ctx context.Context,
	info proto.PassphraseInfo,
) (
	*rem.PostGenericLinkArg,
	error,
) {
	var ret rem.PostGenericLinkArg
	return &ret, nil
}

func (p *passphraseServerMock) GetUserSettings(
	ctx context.Context,
) (
	*proto.PassphraseInfo,
	error,
) {
	return nil, nil
}

func newPassphraseServerMock() *passphraseServerMock {
	ret := &passphraseServerMock{
		users: make(map[proto.UID](*userPassphraseServerRecord)),
	}
	err := core.RandomFill(ret.key[:])
	if err != nil {
		panic(err)
	}
	return ret
}

func (p *passphraseServerMock) makeNewUser(t *testing.T) (proto.FQUser, proto.SecretSeed32, proto.Ed25519SecretKey, proto.DeviceID) {
	u := core.RandomFQU()
	seed := core.RandomSecretSeed32()
	key, err := core.DeviceSigningSecretKey(seed)
	require.NoError(t, err)
	p.users[u.Uid] = &userPassphraseServerRecord{
		devKey: key.PublicKey(),
	}
	did := key.PublicKey().DeviceID()
	return u, seed, *key, did
}

var _ PassphraseManagerEngine = (*passphraseServerMock)(nil)

func (p *passphraseServerMock) AuthUser(u proto.UID, k *proto.Ed25519PublicKey) (*userPassphraseServerRecord, error) {
	user := p.users[u]
	if user == nil {
		return nil, core.UserNotFoundError{}
	}

	tryKey := func(k2 *proto.Ed25519PublicKey) bool {
		if k == nil {
			return false
		}
		ok, err := core.Eq(k2, k)
		if err != nil {
			return false
		}
		return ok
	}
	if !tryKey(user.devKey) {
		return nil, core.AuthError{}
	}
	return user, nil
}

func (p *passphraseServerMock) Login(ctx context.Context, arg rem.LoginArg) (rem.LoginRes, error) {
	var ret rem.LoginRes
	user := p.users[arg.Uid]
	if user == nil {
		return ret, core.UserNotFoundError{}
	}
	ppKey := user.ppKey.PublicKeyEd25519()
	if ppKey == nil {
		return ret, core.KeyNotFoundError{}
	}
	err := core.VerifyWithEd25519Public(ppKey, arg.Signature, &arg.Challenge.Payload)
	if err != nil {
		return ret, core.AuthError{}
	}
	// We're being lazy and not verifying that the login challenge is legit, but that's fine for now...
	ret.PpGen = user.ppgen
	ret.SkwkBox = *user.skmwkListBox
	ret.PassphraseBox = *user.passphraseBox
	return ret, nil
}

func (u *userServerMock) NextPassphraseGeneration(ctx context.Context) (proto.PassphraseGeneration, error) {
	var zed proto.PassphraseGeneration
	if u.rec == nil {
		return zed, core.AuthError{}
	}
	return u.rec.ppgen + 1, nil
}

func (p *userServerMock) GetSalt(context.Context) (proto.PassphraseSalt, error) {
	var ret proto.PassphraseSalt
	if p.rec == nil {
		return ret, core.AuthError{}
	}
	return *p.rec.salt, nil
}

func (p *userServerMock) StretchVersion(context.Context) (proto.StretchVersion, error) {
	return proto.StretchVersion_TEST, nil
}

func (p *passphraseServerMock) GetLoginChallenge(ctx context.Context, uid proto.UID) (rem.Challenge, error) {
	var ret rem.Challenge
	return ret, nil
}

func (p *userServerMock) GetPpeParcel(
	ctx context.Context,
) (
	proto.PpeParcel,
	error,
) {
	return proto.PpeParcel{
		SkwkBox:       *p.rec.skmwkListBox,
		PpGen:         p.rec.ppgen,
		PukBox:        p.rec.pukBox,
		PassphraseBox: *p.rec.passphraseBox,
		Salt:          *p.rec.salt,
	}, nil
}

func (p *passphraseServerMock) RegServer() RegServerInterface { return p }
func (p *passphraseServerMock) UserServer(uid proto.UID) UserServerInterface {
	return &userServerMock{
		uid: uid,
		rec: p.users[uid],
	}
}

func (u *userServerMock) SetPassphrase(
	ctx context.Context,
	arg rem.SetPassphraseArg,
) error {
	if u.rec == nil {
		return core.AuthError{}
	}
	if !u.rec.isZero() {
		return core.PassphraseError("server-side passphrase was set")
	}
	u.rec.ppKey = arg.Key
	u.rec.skmwkListBox = &arg.SkwkBox
	u.rec.pukBox = arg.PukBox
	u.rec.passphraseBox = &arg.PassphraseBox
	u.rec.ppgen = proto.FirstPassphraseGeneration
	u.rec.salt = &arg.Salt

	return nil

}
func (u *userServerMock) ChangePassphrase(
	ctx context.Context,
	arg rem.ChangePassphraseArg,
) error {
	if u.rec == nil {
		return core.AuthError{}
	}
	if arg.PpGen == proto.PassphraseGeneration(0) {
		return core.PassphraseError("can't call ChangePassphrase for first generation")
	}
	if arg.PpGen != u.rec.ppgen+1 {
		return core.PassphraseError("passphrase generation is out of sequence")
	}
	if u.rec.salt == nil {
		return core.PassphraseError("nil salt for user")
	}
	u.rec.ppKey = arg.Key
	u.rec.skmwkListBox = &arg.SkwkBox
	u.rec.pukBox = arg.PukBox
	u.rec.passphraseBox = &arg.PassphraseBox
	u.rec.ppgen = arg.PpGen
	return nil
}

func TestBasicHappyPath(t *testing.T) {

	mock := newPassphraseServerMock()
	user, _, _, _ := mock.makeNewUser(t)
	ctx := context.Background()

	pm := &PassphraseManager{
		user: user,
	}
	pp := core.RandomPassphrase()

	err := pm.SetPassphrase(ctx, mock, pp, nil)
	require.NoError(t, err)

	pm.Logout()
	err = pm.Login(ctx, mock, pp, nil, nil)
	require.NoError(t, err)

	pp2 := core.RandomPassphrase()
	err = pm.ChangePassphrase(ctx, mock, pp2, nil)
	require.NoError(t, err)

	pm.Logout()
	err = pm.Login(ctx, mock, pp, nil, nil)
	require.Error(t, err)
	require.IsType(t, core.AuthError{}, err)

	err = pm.Login(ctx, mock, pp2, nil, nil)
	require.NoError(t, err)
}

func TestTwoHappyClients(t *testing.T) {

	mock := newPassphraseServerMock()
	user, _, _, _ := mock.makeNewUser(t)
	ctx := context.Background()

	pm1 := &PassphraseManager{
		user: user,
	}
	pp1 := core.RandomPassphrase()

	err := pm1.SetPassphrase(ctx, mock, pp1, nil)
	require.NoError(t, err)

	pm2 := &PassphraseManager{
		user: user,
	}

	err = pm2.Login(ctx, mock, pp1, nil, nil)
	require.NoError(t, err)

	pp2 := core.RandomPassphrase()
	err = pm1.ChangePassphrase(ctx, mock, pp2, nil)
	require.NoError(t, err)

	pp3 := core.RandomPassphrase()
	err = pm2.Login(ctx, mock, pp2, nil, nil)
	require.NoError(t, err)

	err = pm2.ChangePassphrase(ctx, mock, pp3, nil)
	require.NoError(t, err)
}

func TestChangeWithPUK(t *testing.T) {

	mock := newPassphraseServerMock()
	user, _, _, _ := mock.makeNewUser(t)
	var puks []core.SharedPrivateSuiter
	seed := core.RandomSecretSeed32()
	var lst core.SharedPrivateSuiter
	for i := 0; i < 4; i++ {
		puk, err := core.NewSharedPrivateSuite25519(
			proto.EntityType_User,
			proto.OwnerRole,
			seed,
			proto.Generation(i+1),
			user.HostID,
		)
		require.NoError(t, err)
		puks = append(puks, puk)
		lst = puk
	}

	ctx := context.Background()
	pm1 := &PassphraseManager{
		user: user,
	}
	pp1 := core.RandomPassphrase()
	err := pm1.SetPassphrase(ctx, mock, pp1, lst)
	require.NoError(t, err)

	pm2 := &PassphraseManager{
		user: user,
	}
	pp2 := core.RandomPassphrase()
	err = pm2.ChangePassphraseWithPUK(ctx, mock, pp2, puks)
	require.NoError(t, err)

	err = pm1.Login(ctx, mock, pp2, nil, nil)
	require.NoError(t, err)
}

func TestBoxUnbox(t *testing.T) {
	pp := core.RandomPassphrase()
	salt := core.RandomPassphraseSalt()
	s, err := NewStretchedPassphrase(StretchOpts{IsTest: true}, pp, salt, 0, proto.StretchVersion_TEST)
	require.NoError(t, err)

	var payload lcl.PpePUKBoxPayload
	pk, err := s.PublicKeySuite()
	require.NoError(t, err)
	sk, err := s.SecretKeySuite()
	require.NoError(t, err)
	eph, err := pk.Ephemeral()
	require.NoError(t, err)
	box, err := eph.BoxFor(&payload, pk, core.BoxOpts{IncludePublicKey: true})
	require.NoError(t, err)
	require.NoError(t, err)

	var output lcl.PpePUKBoxPayload
	err = sk.UnboxForIncludedEphemeral(&output, *box)
	require.NoError(t, err)
	require.Equal(t, payload, output)

}
