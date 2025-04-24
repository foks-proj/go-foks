// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

//go:build darwin

package libclient

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/keybase/go-keychain"
)

var HasMacOSKeychain = true

type testKeychainItem struct {
	Account string
	Service string
}

type testKeychainCleaner struct {
	items []testKeychainItem
}

func (t *testKeychainCleaner) Add(account, service string) {
	t.items = append(t.items, testKeychainItem{
		Account: account,
		Service: service,
	})
}

func (t *testKeychainCleaner) clean() {
	for _, item := range t.items {
		_ = keychain.DeleteGenericPasswordItem(item.Service, item.Account)
	}
}

var testKeychainCleaner_ *testKeychainCleaner

func InitMacOSKeychainTest() {
	testKeychainCleaner_ = &testKeychainCleaner{}
}

func CleanupMacOSKeychainTest() {
	testKeychainCleaner_.clean()
}

// unlockMacOS unlocks the secret box passed with a key stored in the macOS keychain.
// There is a complication here, which is that we originally have "v1" labels for these
// keys,
func (s *SecretKeyMaterialManager) unlockMacOS(
	ctx context.Context,
	mac lcl.MacOSKeychainEncryptedSecretBundle,
) error {

	skl := func(v EncryptSeedMacOSVersion) (string, error) {
		return secretKeyLabel(
			proto.FQUserAndRole{
				Fqu:  s.user,
				Role: s.role,
			},
			s.liid,
			s.did,
			v,
		)
	}

	var l2, l1 string
	var err error

	l2, err = skl(EncryptSeedMacOSVersion2)
	if err != nil {
		return err
	}

	dat, err := keychain.GetGenericPassword(mac.Service, l2, "", "")
	if err != nil {
		return err
	}

	var needUpgrade bool

	if dat == nil {
		l1, err = skl(EncryptSeedMacOSVersion1)
		if err != nil {
			return err
		}
		dat, err = keychain.GetGenericPassword(mac.Service, l1, "", "")
		if err != nil {
			return err
		}
		if dat == nil {
			return core.MacOSKeychainError("not found")
		}
		needUpgrade = true
	}

	if len(dat) == 0 {
		return core.MacOSKeychainError("not found")
	}

	skey := dat
	key, err := base64.StdEncoding.DecodeString(string(skey))
	if err != nil {
		return err
	}

	var boxKey proto.SecretBoxKey
	if len(boxKey) != len(key) {
		return core.MacOSKeychainError(fmt.Sprintf("key data returned was not the right size (%d v %d)", len(key), len(boxKey)))
	}
	copy(boxKey[:], key)
	var ret lcl.SecretKeyBundle
	err = core.OpenSecretBoxInto(&ret, mac.SecretBox, &boxKey)
	if err != nil {
		return err
	}
	err = s.unbundle(ret)
	if err != nil {
		return err
	}

	if needUpgrade {
		_, err := addItem(boxKey, &mac.SecretBox, l2, false)
		if err != nil {
			return err
		}
		err = keychain.DeleteGenericPasswordItem(mac.Service, l1)
		if err != nil {
			return err
		}
	}
	return nil
}

func secretKeyLabel(
	fqur proto.FQUserAndRole,
	liid proto.LocalInstanceID,
	did proto.DeviceID,
	vers EncryptSeedMacOSVersion,
) (string, error) {
	switch vers {
	case EncryptSeedMacOSVersion1:
		return lcl.SecretKeyKeychainLabelV1{
			Fqur: fqur,
			Liid: liid,
		}.StringErr()
	case EncryptSeedMacOSVersion2:
		return SecretKeyLabelV2(fqur.Fqu, liid, did)
	default:
		return "", core.VersionNotSupportedError("secret key macOS version")
	}
}

func addItem(
	key proto.SecretBoxKey,
	box *proto.SecretBox,
	uns string,
	isTest bool,
) (
	*lcl.MacOSKeychainEncryptedSecretBundle,
	error,
) {
	mac := lcl.MacOSKeychainEncryptedSecretBundle{
		Service:   MacOSServiceName(isTest),
		Account:   uns,
		SecretBox: *box,
	}
	skey := base64.StdEncoding.EncodeToString(key[:])

	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(mac.Service)
	item.SetAccount(mac.Account)
	item.SetLabel("")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	item.SetAccessGroup("")
	item.SetData([]byte(skey))

	err := keychain.AddItem(item)
	if err != nil {
		return nil, err
	}
	if testKeychainCleaner_ != nil {
		testKeychainCleaner_.Add(mac.Account, mac.Service)
	}
	return &mac, nil
}

func EncryptSeedWithMacOSKeychain(
	ctx context.Context,
	seed proto.SecretSeed32,
	liid proto.LocalInstanceID,
	fqu proto.FQUser,
	role proto.Role,
	did proto.DeviceID,
	opts EncryptSeedMacOSOpts,
) (*lcl.StoredSecretKeyBundle, error) {
	var key proto.SecretBoxKey
	err := core.RandomFill(key[:])
	if err != nil {
		return nil, err
	}
	skb := lcl.NewSecretKeyBundleWithV1(seed)
	newBox, err := core.SealIntoSecretBox(&skb, &key)
	if err != nil {
		return nil, err
	}
	fqur := proto.FQUserAndRole{
		Fqu:  fqu,
		Role: role,
	}
	uns, err := secretKeyLabel(fqur, liid, did, opts.Vers)
	if err != nil {
		return nil, err
	}

	mac, err := addItem(key, newBox, uns, opts.IsTest)
	if err != nil {
		return nil, err
	}

	tmp := lcl.NewStoredSecretKeyBundleWithEncMacosKeychain(*mac)
	return &tmp, nil
}

func (s *SecretKeyMaterialManager) ClearMacOSKeychain(mac lcl.MacOSKeychainEncryptedSecretBundle) error {
	skl, err := secretKeyLabel(s.Row().Fqur, s.liid, s.did, EncryptSeedMacOSVersion2)
	if err != nil {
		return err
	}
	return keychain.DeleteGenericPasswordItem(mac.Service, skl)
}

func (s *SecretKeyMaterialManager) encryptForMacOSLocked(
	ctx context.Context,
	ss *SecretStore,
) error {
	liid, err := ss.LocalInstanceID()
	if err != nil {
		return err
	}
	opts := EncryptSeedMacOSOpts{
		IsTest: s.isTest,
		Vers:   EncryptSeedMacOSVersion2,
	}
	tmp, err := EncryptSeedWithMacOSKeychain(ctx, *s.seed, *liid, s.user, s.role, s.did, opts)
	if err != nil {
		return err
	}
	err = ss.UpdateAndSave(
		ctx,
		lcl.LabeledSecretKeyBundle{
			Fqur: proto.FQUserAndRole{
				Fqu:  s.user,
				Role: s.role,
			},
			Bundle:  *tmp,
			KeyID:   s.did,
			SelfTok: s.selfTok,
		},
	)
	if err != nil {
		return err
	}
	s.bun = tmp
	return nil
}

func (s *SecretKeyMaterialManager) EncryptForMacOS(
	ctx context.Context,
	ss *SecretStore,
) error {
	s.Lock()
	defer s.Unlock()
	return s.encryptForMacOSLocked(ctx, ss)
}
