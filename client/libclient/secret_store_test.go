// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func randomPlaintextSecretKeyBundle() lcl.StoredSecretKeyBundle {
	seed := core.RandomSecretSeed32()
	return lcl.NewStoredSecretKeyBundleWithPlaintext(
		lcl.NewSecretKeyBundleWithV1(
			seed,
		),
	)
}

func randomLabeledSecretKeyBundle(r proto.Role) lcl.LabeledSecretKeyBundle {
	return lcl.LabeledSecretKeyBundle{
		Fqur: proto.FQUserAndRole{
			Fqu:  core.RandomFQU(),
			Role: r,
		},
		KeyID:  core.RandomDeviceID(),
		Bundle: randomPlaintextSecretKeyBundle(),
	}
}

func testSecretStoreFilename() string {
	// Make a phony secret store in the system temp dir. 16 bytes of data means
	// we're not going to hit any collisions
	tdir := os.TempDir()
	fn := "ss-test." + core.RandomBase62String(16) + ".mpack"
	return filepath.Join(tdir, fn)
}

func newTestSecretStore() *SecretStore {
	return NewSecretStore(testSecretStoreFilename())
}

// there's not a good reason to delete a secret store in the main program
// but it's polite to clean up after ourselves for testing. if removal fails because
// nothing is there, don't worry about it.
func (s *SecretStore) cleanup() error {
	_ = os.Remove(s.path)
	return nil
}

func TestSaveAndLoad(t *testing.T) {

	ctx := context.Background()

	fullFn := testSecretStoreFilename()
	ss := NewSecretStore(fullFn)
	defer func() {
		err := ss.cleanup()
		require.NoError(t, err)
	}()
	require.NotNil(t, ss)

	// Ensure that it doesn't load, since it shouldn't be there
	err := ss.Load(ctx)
	require.Error(t, err)
	require.IsType(t, &fs.PathError{}, err)

	// Enusre it's the same error as when we open the file directly
	_, err = os.OpenFile(fullFn, os.O_RDONLY, 0o0)
	require.Error(t, err)
	require.IsType(t, &fs.PathError{}, err)

	// LoadOrCreate should work.
	err = ss.LoadOrCreate(ctx)
	require.NoError(t, err)

	role := proto.OwnerRole

	// Make 10 fake data rows
	var rows []lcl.LabeledSecretKeyBundle
	for i := 0; i < 10; i++ {
		rows = append(rows, randomLabeledSecretKeyBundle(role))
	}

	// Putting the first row should work
	err = ss.Put(rows[0])
	require.NoError(t, err)

	// It is not allowed to repeat a device key for the same user.
	tmp := rows[1]
	tmp.Fqur = rows[0].Fqur
	tmp.KeyID = rows[0].KeyID
	err = ss.Put(tmp)
	require.Error(t, err)
	require.Equal(t, core.SecretKeyExistsError{}, err)

	// Save and load the file and make sure we can reload it
	err = ss.Save(ctx)
	require.NoError(t, err)
	err = ss.Load(ctx)
	require.NoError(t, err)

	// This function tests that row in the test set matches what's in the file
	testRow := func(i int) {
		bun, err := ss.Get(SecretStoreGetArgs{
			Fqu:  rows[i].Fqur.Fqu,
			Role: role,
			Opts: SecretStoreGetOpts{
				NoProvisional: false,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, bun)
		eq, err := core.Eq(&bun.Bundle, &rows[i].Bundle)
		require.NoError(t, err)
		require.True(t, eq)
	}

	// A save and load
	cycle := func() {
		err = ss.Save(ctx)
		require.NoError(t, err)
		err = ss.Load(ctx)
		require.NoError(t, err)
	}

	// We only put the first row, so only row 0 should be there
	testRow(0)

	// Test user not found
	bun, err := ss.Get(
		SecretStoreGetArgs{
			Fqu:  rows[1].Fqur.Fqu,
			Role: role,
			Opts: SecretStoreGetOpts{
				NoProvisional: false,
			},
		})
	require.NoError(t, err)
	require.Nil(t, bun)

	// We can't update a row that's not there
	tmp = rows[1]
	tmp.Bundle = rows[2].Bundle
	err = ss.Update(tmp)
	require.Error(t, err)
	require.IsType(t, core.KeyNotFoundError{}, err)

	// Regenerate the data and update the row show the data
	rows[0].Bundle = randomPlaintextSecretKeyBundle()
	err = ss.Update(rows[0])
	require.NoError(t, err)

	testRow(0)
	cycle()
	testRow(0)

	// Put the rest of the data
	for _, r := range rows[1:] {
		err = ss.Put(r)
		require.NoError(t, err)
	}

	cycle()

	// Ok, all test rows should be there.
	for i := range rows {
		testRow(i)
	}

	// Test again we can't write over an existing key
	tmp = rows[1]
	tmp.KeyID = rows[1].KeyID
	tmp.Bundle = rows[1].Bundle
	err = ss.Put(tmp)
	require.Error(t, err)
	require.IsType(t, core.SecretKeyExistsError{}, err)

	// Test that we can make a second row for the same user/role pair,
	// and that on lookup, we'll get the second.
	tmp1 := randomLabeledSecretKeyBundle(role)
	tmp1.Provisional = true
	err = ss.Put(tmp1)
	require.NoError(t, err)

	// Test that we can write many provisional keys for the same user/role index
	tmp2 := randomLabeledSecretKeyBundle(role)
	tmp2.Fqur = tmp1.Fqur
	tmp2.Provisional = true
	err = ss.Put(tmp2)
	require.NoError(t, err)

	// We shouldn't get either of them back
	bun, err = ss.Get(
		SecretStoreGetArgs{
			Fqu:  tmp1.Fqur.Fqu,
			Role: role,
			Opts: SecretStoreGetOpts{
				NoProvisional: true,
			},
		},
	)
	require.NoError(t, err)
	require.Nil(t, bun)

	// This call doesn't care if the provisional bits are set, so should get the second
	// one back in this case
	bun, err = ss.Get(
		SecretStoreGetArgs{
			Fqu:  tmp1.Fqur.Fqu,
			Role: tmp1.Fqur.Role,
		})
	require.NoError(t, err)
	require.NotNil(t, bun)
	require.Equal(t, tmp2.Bundle, bun.Bundle)

	n, err := ss.ClearProvisionalBits(ctx, tmp2.Fqur.Fqu, []proto.DeviceID{tmp2.KeyID})
	require.NoError(t, err)
	require.Equal(t, 1, n)

	// Now should get the second one back!
	bun, err = ss.Get(
		SecretStoreGetArgs{
			Fqu:  tmp1.Fqur.Fqu,
			Role: tmp1.Fqur.Role,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, bun)
	require.Equal(t, tmp2.Bundle, bun.Bundle)

	// Remove the file and then ensure we can no longer load it
	os.Remove(fullFn)
	err = ss.Load(ctx)
	require.Error(t, err)
	require.IsType(t, &fs.PathError{}, err)
}

type secretUnlocker struct {
	passphrase proto.Passphrase
	box        proto.SecretBox
	stream     *StretchedPassphrase
}

func (s *secretUnlocker) GetPassphraseFromUser(ctx context.Context, i int) (proto.Passphrase, error) {
	if i >= 3 {
		return "", core.TooManyTriesError{}
	}
	return s.passphrase, nil
}

func (s *secretUnlocker) GetEncryptedSKWKList(ctx context.Context, u proto.FQUser, sp *StretchedPassphrase) (*proto.SecretBox, error) {
	if !s.stream.Eq(sp) {
		return nil, core.AuthError{}
	}
	return &s.box, nil
}

func (s *SecretStore) clearForTest(t *testing.T) {
	var err error
	s.data, err = newSecretStoreProto()
	require.NoError(t, err)
}

func TestDelete(t *testing.T) {
	fnm := testSecretStoreFilename()
	ss := NewSecretStore(fnm)
	defer func() {
		err := ss.cleanup()
		require.NoError(t, err)
	}()
	ctx := context.Background()
	err := ss.LoadOrCreate(ctx)
	require.NoError(t, err)
	// Remove the file and then ensure we can no longer load it
	defer os.Remove(fnm)

	// Make 10 fake data rows
	var rows []lcl.LabeledSecretKeyBundle
	role := proto.OwnerRole
	for i := 0; i < 10; i++ {
		rows = append(rows, randomLabeledSecretKeyBundle(role))
	}

	for _, r := range rows[0:9] {
		err = ss.Put(r)
		require.NoError(t, err)
	}
	err = ss.Save(ctx)
	require.NoError(t, err)

	ss.clearForTest(t)
	require.NoError(t, err)
	err = ss.Load(ctx)
	require.NoError(t, err)

	// Happy path
	err = ss.Delete(rows[0].Fqur.Fqu, role, rows[0].KeyID)
	require.NoError(t, err)
	err = ss.Save(ctx)
	require.NoError(t, err)
	res, err := ss.Get(SecretStoreGetArgs{Fqu: rows[0].Fqur.Fqu, Role: role})
	require.NoError(t, err)
	require.Nil(t, res)
	ss.clearForTest(t)
	err = ss.Load(ctx)
	require.NoError(t, err)

	res, err = ss.Get(SecretStoreGetArgs{Fqu: rows[0].Fqur.Fqu, Role: role})
	require.NoError(t, err)
	require.Nil(t, res)

	// Unhappy path --- not found
	err = ss.Delete(rows[9].Fqur.Fqu, role, rows[9].KeyID)
	require.Error(t, err)
	require.Equal(t, core.KeyNotFoundError{Which: "devkey"}, err)

	// Unhappy path --- wrong devkey
	err = ss.Delete(rows[1].Fqur.Fqu, role, rows[2].KeyID)
	require.Error(t, err)
	require.Equal(t, core.KeyMismatchError{}, err)
}

func TestPassphraseLock(t *testing.T) {

	fnm := testSecretStoreFilename()
	ss := NewSecretStore(fnm)
	defer func() {
		err := ss.cleanup()
		require.NoError(t, err)
	}()
	ctx := context.Background()
	err := ss.LoadOrCreate(ctx)
	require.NoError(t, err)

	// Remove the file and then ensure we can no longer load it
	defer os.Remove(fnm)

	// Write a random row in plaintext to the secret store file
	fqu := core.RandomFQU()
	seed := core.RandomSecretSeed32()
	did := core.RandomDeviceID()
	plaintextBundle := lcl.NewStoredSecretKeyBundleWithPlaintext(
		lcl.NewSecretKeyBundleWithV1(
			seed,
		),
	)
	role := proto.OwnerRole

	tok, err := core.NewPermissionToken()
	require.NoError(t, err)

	err = ss.Put(
		lcl.LabeledSecretKeyBundle{
			Fqur: proto.FQUserAndRole{
				Fqu:  fqu,
				Role: role,
			},
			KeyID:   did,
			Bundle:  plaintextBundle,
			SelfTok: tok,
		},
	)
	require.NoError(t, err)
	err = ss.Save(ctx)
	ss.clearForTest(t)
	require.NoError(t, err)
	err = ss.Load(ctx)
	require.NoError(t, err)

	passphrase := core.RandomPassphrase()
	sp, err := NewStretchedPassphrase(
		StretchOpts{IsTest: true},
		passphrase,
		core.RandomPassphraseSalt(),
		proto.PassphraseGeneration(1),
		proto.StretchVersion_TEST,
	)
	require.NoError(t, err)
	require.NotNil(t, sp)
	key := sp.SecretBoxKey()

	lst := core.RandomSKMWKList()
	// Write over the randomly generated FQUser with the right answer
	lst.Fqu = fqu

	// Next we seal the olist of
	box, err := core.SealIntoSecretBox(&lst, &key)
	require.NoError(t, err)
	require.NotNil(t, box)

	su := &secretUnlocker{
		passphrase: passphrase,
		box:        *box,
		stream:     sp,
	}
	require.NotNil(t, su)

	err = ss.Save(ctx)
	ss.clearForTest(t)
	require.NoError(t, err)
	err = ss.Load(ctx)
	require.NoError(t, err)
}
