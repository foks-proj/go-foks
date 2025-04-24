// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

type ppePackage struct {
	pp   proto.Passphrase
	sp   *libclient.StretchedPassphrase
	gen  proto.PassphraseGeneration
	salt proto.PassphraseSalt
	r    []lcl.SKMWK
	s    []lcl.PpeSessionKey
}

func (p *ppePackage) pushNewR(t *testing.T) {
	var r lcl.SKMWK
	err := core.RandomFill(r[:])
	require.NoError(t, err)
	p.r = append(p.r, r)
}

func (p *ppePackage) pushNewS(t *testing.T) {
	var s lcl.PpeSessionKey
	err := core.RandomFill(s[:])
	require.NoError(t, err)
	p.s = append(p.s, s)
}

func last[T any](v []T) T {
	return v[len(v)-1]
}

func newPpePackage(t *testing.T) *ppePackage {
	pp := core.RandomPassphrase()
	salt := core.RandomPassphraseSalt()
	sp, err := libclient.NewStretchedPassphrase(
		libclient.StretchOpts{IsTest: true}, pp, salt, proto.FirstPassphraseGeneration, proto.StretchVersion_TEST)
	require.NoError(t, err)
	ret := &ppePackage{
		pp:   pp,
		salt: salt,
		sp:   sp,
	}
	ret.pushNewR(t)
	ret.pushNewS(t)
	return ret
}

func (p *ppePackage) skwkBox(t *testing.T, u *TestUser) proto.SecretBox {
	ePayload := lcl.SKMWKList{
		Fqu:  u.FQUser(),
		Keys: p.r,
	}
	s := last(p.s)
	box, err := core.SealIntoSecretBox(&ePayload, (*proto.SecretBoxKey)(&s))
	require.NoError(t, err)
	return *box
}

func (p *ppePackage) passphraseBox(t *testing.T, u *TestUser) proto.PpePassphraseBox {
	s := last(p.s)
	fPayload := lcl.PpePassphraseBoxPayload{
		Gen:     p.gen,
		Sesskey: s,
	}
	pk, err := p.sp.PublicKeySuite()
	require.NoError(t, err)
	fBox, err := core.BoxForEmphemeral(&fPayload, pk, core.BoxOpts{IncludePublicKey: true})
	require.NoError(t, err)
	return proto.PpePassphraseBox{
		Box: *fBox,
	}

}

func (p *ppePackage) pukBox(t *testing.T, u *TestUser) *proto.PpePUKBox {
	pk, err := p.sp.PublicKeySuite()
	require.NoError(t, err)
	hepk, err := pk.ExportHEPK()
	require.NoError(t, err)
	require.True(t, p.gen.IsValid())
	gPayload := lcl.PpePUKBoxPayload{
		Gen:        p.gen,
		Sesskey:    last(p.s),
		Passphrase: *hepk,
	}
	puk := u.puks[core.RoleKey{Typ: proto.RoleType_OWNER}]
	require.NotNil(t, puk)
	gKey := puk.SecretBoxKey()

	gBox, err := core.SealIntoSecretBox(&gPayload, &gKey)
	require.NoError(t, err)
	return &proto.PpePUKBox{
		Box:     *gBox,
		PukRole: proto.OwnerRole,
		PukGen:  puk.Md.Gen,
	}
}

func (p *ppePackage) setPassphrase(t *testing.T, u *TestUser) rem.SetPassphraseArg {
	pk, err := p.sp.PublicKeySuite()
	require.NoError(t, err)
	eid := pk.GetEntityID()
	p.gen = proto.FirstPassphraseGeneration

	ret := rem.SetPassphraseArg{
		StretchVersion: proto.StretchVersion_TEST,
		Key:            eid,
		Salt:           p.salt,
		SkwkBox:        p.skwkBox(t, u),
		PukBox:         p.pukBox(t, u),
		PassphraseBox:  p.passphraseBox(t, u),
	}
	return ret
}

func (p *ppePackage) changePassphrase(t *testing.T, u *TestUser) rem.ChangePassphraseArg {
	p.gen++
	pp := core.RandomPassphrase()
	sp, err := libclient.NewStretchedPassphrase(
		libclient.StretchOpts{IsTest: true}, pp, p.salt, p.gen, proto.StretchVersion_TEST)
	require.NoError(t, err)
	p.pushNewR(t)
	p.pushNewS(t)
	p.pp = pp
	p.sp = sp
	pk, err := p.sp.PublicKeySuite()
	require.NoError(t, err)
	eid := pk.GetEntityID()

	ret := rem.ChangePassphraseArg{
		Key:            eid,
		SkwkBox:        p.skwkBox(t, u),
		StretchVersion: proto.StretchVersion_TEST,
		PpGen:          p.gen,
		PassphraseBox:  p.passphraseBox(t, u),
		PukBox:         p.pukBox(t, u),
	}
	return ret
}

func TestLogin(t *testing.T) {
	u := GenerateNewTestUser(t)
	require.NotNil(t, u)
	ctx := context.Background()
	crt := u.ClientCert(t)
	ucli, userCloseFn, err := newUserClient(ctx, crt)
	require.NoError(t, err)
	defer userCloseFn()

	ppe := newPpePackage(t)
	arg := ppe.setPassphrase(t, u)

	err = ucli.SetPassphrase(ctx, arg)
	require.NoError(t, err)

	rcli, closeFn, err := newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()

	chal, err := rcli.GetLoginChallenge(ctx, u.uid)
	require.NoError(t, err)

	sk, err := ppe.sp.SecretKeySuite()
	require.NoError(t, err)
	sig, err := sk.Sign(&chal.Payload)
	require.NoError(t, err)

	larg := rem.LoginArg{
		Uid:       u.uid,
		Challenge: chal,
		Signature: *sig,
	}
	lres, err := rcli.Login(ctx, larg)
	require.NoError(t, err)
	typ, err := lres.SkwkBox.GetT()
	require.NoError(t, err)
	require.Equal(t, proto.BoxType_NACL, typ)
	require.Equal(t, lres.SkwkBox, arg.SkwkBox)
	require.Equal(t, lres.PassphraseBox, arg.PassphraseBox)

	// Test replay of login gets rejected
	_, err = rcli.Login(ctx, larg)
	require.Error(t, err)
	require.Equal(t, core.ReplayError{}, err)

	chal, err = rcli.GetLoginChallenge(ctx, u.uid)
	require.NoError(t, err)

	tryBadPassphrase := func(expectedErr error) {
		_, priv2, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		sig, err = core.SignWithEd21559Private(priv2, &chal.Payload)
		require.NoError(t, err)
		larg.Signature = *sig
		_, err = rcli.Login(ctx, larg)
		require.Error(t, err)
		require.Equal(t, expectedErr, err)
	}

	for i := 0; i < 3; i++ {
		tryBadPassphrase(core.BadPassphraseError{})
	}
	tryBadPassphrase(core.RateLimitError{})

}

func TestChangePassphrase(t *testing.T) {
	u := GenerateNewTestUser(t)
	require.NotNil(t, u)
	ctx := context.Background()
	crt := u.ClientCert(t)
	ucli, userCloseFn, err := newUserClient(ctx, crt)
	require.NoError(t, err)
	defer userCloseFn()

	ppe := newPpePackage(t)
	arg := ppe.setPassphrase(t, u)

	err = ucli.SetPassphrase(ctx, arg)
	require.NoError(t, err)

	rcli, closeFn, err := newRegClient(ctx)
	require.NoError(t, err)
	defer closeFn()

	chal, err := rcli.GetLoginChallenge(ctx, u.uid)
	require.NoError(t, err)

	sk, err := ppe.sp.SecretKeySuite()
	require.NoError(t, err)
	sig, err := sk.Sign(&chal.Payload)
	require.NoError(t, err)

	larg := rem.LoginArg{
		Uid:       u.uid,
		Challenge: chal,
		Signature: *sig,
	}
	_, err = rcli.Login(ctx, larg)
	require.NoError(t, err)

	cppArg := ppe.changePassphrase(t, u)

	err = ucli.ChangePassphrase(ctx, cppArg)
	require.NoError(t, err)

	chal, err = rcli.GetLoginChallenge(ctx, u.uid)
	require.NoError(t, err)
	sig, err = sk.Sign(&chal.Payload)
	require.NoError(t, err)

	larg = rem.LoginArg{
		Uid:       u.uid,
		Challenge: chal,
		Signature: *sig,
	}
	_, err = rcli.Login(ctx, larg)
	require.Error(t, err)
	require.Equal(t, core.BadPassphraseError{}, err)

	sk2, err := ppe.sp.SecretKeySuite()
	require.NoError(t, err)
	sig, err = sk2.Sign(&chal.Payload)
	require.NoError(t, err)
	larg.Signature = *sig
	_, err = rcli.Login(ctx, larg)
	require.NoError(t, err)
}
