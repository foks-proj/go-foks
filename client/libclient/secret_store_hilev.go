// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"runtime"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func StoreSecretWithDefaults(
	m MetaContext,
	row lcl.LabeledSecretKeyBundle,
	ss proto.SecretSeed32,
	pmi PassphraseManagerInterface,
	ppe *lcl.KexPPE,
) (*SecretKeyMaterialManager, error) {

	store := m.G().SecretStore()

	bun, err := makeSecretStoreBundleWithDefaults(
		m,
		row.Fqur.Fqu,
		row.Fqur.Role,
		ss,
		store,
		pmi,
		ppe,
		row.KeyID,
	)
	if err != nil {
		return nil, err
	}
	row.Bundle = *bun

	return storeBundle(m, row, store, false)
}

func UpdateSecretWithMode(
	m MetaContext,
	row lcl.LabeledSecretKeyBundle,
	ss proto.SecretSeed32,
	pmi PassphraseManagerInterface,
	puks []core.SharedPrivateSuiter,
	mode proto.SecretKeyStorageType,
) (*SecretKeyMaterialManager, error) {

	store := m.G().SecretStore()

	bun, err := makeSecretStoreBundle(
		m,
		row.Fqur.Fqu,
		row.Fqur.Role,
		ss,
		store,
		pmi,
		nil,
		puks,
		mode,
		row.KeyID,
	)
	if err != nil {
		return nil, err
	}
	row.Bundle = *bun

	return storeBundle(m, row, store, true)
}

func storeBundle(
	m MetaContext,
	row lcl.LabeledSecretKeyBundle,
	store *SecretStore,
	update bool,
) (*SecretKeyMaterialManager, error) {

	var err error
	if update {
		err = store.Update(row)
	} else {
		err = store.Put(row)
	}
	if err != nil {
		return nil, err
	}

	err = store.Save(m.Ctx())
	if err != nil {
		return nil, err
	}

	skm := NewSecretKeyMaterialManager(row.Fqur.Fqu, row.Fqur.Role)

	// If we're storing the row in a provisional form, we still need to load it back out.
	// Only insist on on provisional rows if we're storing a final row.
	err = skm.Load(m.Ctx(), store, SecretStoreGetOpts{NoProvisional: !row.Provisional})
	if err != nil {
		return nil, err
	}

	return skm, nil
}

func computeDefaultLocalKeyEncryptionMode(
	m MetaContext,
	hasPassphrase bool,
) (proto.SecretKeyStorageType, error) {
	var ret proto.SecretKeyStorageType
	modep, err := m.G().Cfg().DefaultLocalKeyEncryption()
	if err != nil {
		return ret, err
	}

	// Can only use passphrase mode if we have passphrase material loaded in.
	if modep != nil && (*modep != proto.SecretKeyStorageType_ENC_PASSPHRASE || hasPassphrase) {
		return *modep, nil
	}

	if HasMacOSKeychain {
		return proto.SecretKeyStorageType_ENC_MACOS_KEYCHAIN, nil
	}

	// Secrets manager can work on Linux, but in many cases, it doesn't.
	// It depeneds a lot on the distro and how the user configured the sytem.
	// We can make further improvements here down the road, but for now, linux
	// will get noise files.
	if runtime.GOOS == "windows" {
		return proto.SecretKeyStorageType_ENC_KEYCHAIN, nil
	}

	return proto.SecretKeyStorageType_ENC_NOISE_FILE, nil
}

func makeSecretStoreBundleWithDefaults(
	m MetaContext,
	fqu proto.FQUser,
	role proto.Role,
	ss proto.SecretSeed32,
	store *SecretStore,
	pmi PassphraseManagerInterface,
	ppe *lcl.KexPPE,
	did proto.DeviceID,
) (*lcl.StoredSecretKeyBundle, error) {

	mode, err := computeDefaultLocalKeyEncryptionMode(m, ((pmi != nil) || (ppe != nil)))
	if err != nil {
		return nil, err
	}

	return makeSecretStoreBundle(m, fqu, role, ss, store, pmi, ppe, nil, mode, did)
}

func makeSecretStoreBundle(
	m MetaContext,
	fqu proto.FQUser,
	role proto.Role,
	ss proto.SecretSeed32,
	store *SecretStore,
	pmi PassphraseManagerInterface,
	ppe *lcl.KexPPE,
	puks []core.SharedPrivateSuiter,
	mode proto.SecretKeyStorageType,
	did proto.DeviceID,
) (*lcl.StoredSecretKeyBundle, error) {

	switch {
	case mode == proto.SecretKeyStorageType_ENC_NOISE_FILE:
		return EncryptSeedWithNoiseFile(
			m.Ctx(),
			ss,
			store.Dir(),
		)
	case mode == proto.SecretKeyStorageType_PLAINTEXT:
		tmp := lcl.NewStoredSecretKeyBundleWithPlaintext(
			lcl.NewSecretKeyBundleWithV1(
				ss,
			),
		)
		return &tmp, nil
	case mode == proto.SecretKeyStorageType_ENC_KEYCHAIN:
		liid, err := store.LocalInstanceID()
		if err != nil {
			return nil, err
		}
		return EncryptSeedWithGenericKeychain(
			m.Ctx(),
			ss,
			*liid,
			fqu,
			did,
			EncryptSeedGenericOpts{
				IsTest: m.G().Cfg().TestingMode(),
			},
		)
	case mode == proto.SecretKeyStorageType_ENC_MACOS_KEYCHAIN:
		liid, err := store.LocalInstanceID()
		if err != nil {
			return nil, err
		}
		return EncryptSeedWithMacOSKeychain(
			m.Ctx(),
			ss,
			*liid,
			fqu,
			role,
			did,
			EncryptSeedMacOSOpts{
				IsTest: m.G().Cfg().TestingMode(),
				Vers:   EncryptSeedMacOSVersion2,
			},
		)
	case mode == proto.SecretKeyStorageType_ENC_PASSPHRASE && pmi != nil && len(puks) == 0:
		raw := pmi.RawPassphrase()
		if raw.IsZero() {
			return nil, core.InternalError("cannot encrypt with passphrase without passphrase")
		}
		ppm := NewPassphraseManager(fqu)

		err := ppm.SetPassphrase(m.Ctx(), pmi.PME(), raw, pmi.PUK())
		if err != nil {
			return nil, err
		}
		return EncryptWithPassphrase(
			m.Ctx(),
			ss,
			ppm,
		)
	case mode == proto.SecretKeyStorageType_ENC_PASSPHRASE && ppe != nil && len(puks) == 0:
		return EncryptWithPPE(
			m.Ctx(),
			ss,
			ppe,
		)
	case mode == proto.SecretKeyStorageType_ENC_PASSPHRASE && len(puks) > 0 && pmi != nil:
		return EncryptWithPUKs(
			m.Ctx(),
			fqu,
			ss,
			puks,
			pmi.PME(),
		)
	default:
		return nil, core.NotImplementedError{}
	}
}

func SecretStoreToggleHidden(
	m MetaContext,
	did proto.DeviceID,
	hidden bool,
) error {
	store := m.G().SecretStore()
	return store.ToggleHidden(m.Ctx(), did, hidden)
}
