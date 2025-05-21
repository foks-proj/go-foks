// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package kv

import (
	"sync"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type DirKeys struct {
	Seed proto.DirKeySeed
	Mac  proto.KVMacKey
	Box  proto.KVBoxKey
}

func Hmac(p core.CryptoPayloader, k *proto.KVMacKey) (*proto.HMAC, error) {
	return core.Hmac(p, (*proto.HMACKey)(k))
}

func SealIntoSecretBoxWithNonce(
	p core.CryptoPayloader,
	upper *proto.NaclNonce,
	k *proto.KVBoxKey,
) (
	proto.NaclCiphertext,
	error,
) {
	return core.SealIntoSecretBoxWithNonce(p, upper, (*proto.SecretBoxKey)(k))
}

func DeriveMACKey(s proto.SecretSeed32) (*proto.KVMacKey, error) {
	key := proto.HMACKey(s)
	derive := proto.NewKVKeyDerivationDefault(proto.KVKeyType_MAC)
	tmp, err := core.Hmac(&derive, &key)
	if err != nil {
		return nil, err
	}
	ret := (*proto.KVMacKey)(tmp)
	return ret, nil
}

func DeriveBoxKey(s proto.SecretSeed32) (*proto.KVBoxKey, error) {
	key := proto.HMACKey(s)
	derive := proto.NewKVKeyDerivationDefault(proto.KVKeyType_Box)
	tmp, err := core.Hmac(&derive, &key)
	if err != nil {
		return nil, err
	}
	ret := (*proto.KVBoxKey)(tmp)
	return ret, nil
}

func DeriveKeys(s proto.SecretSeed32) (*proto.KVMacKey, *proto.KVBoxKey, error) {
	mac, err := DeriveMACKey(proto.SecretSeed32(s))
	if err != nil {
		return nil, nil, err
	}
	box, err := DeriveBoxKey(proto.SecretSeed32(s))
	if err != nil {
		return nil, nil, err
	}
	return mac, box, nil
}

func NewDirKeys(s proto.DirKeySeed) (*DirKeys, error) {
	mac, box, err := DeriveKeys(proto.SecretSeed32(s))
	if err != nil {
		return nil, err
	}
	return &DirKeys{
		Seed: s,
		Mac:  *mac,
		Box:  *box,
	}, nil
}

func NewDirID() (*proto.DirID, error) {
	var ret proto.DirID
	err := core.RandomFill(ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func SealNameIntoBox(
	name proto.KVNamePlaintext,
	keys *DirKeys,
	dirID *proto.DirID,
) (
	*proto.SecretBox,
	error,
) {
	nonceInput := proto.KVNameNonceInput{
		ParentDir: *dirID,
		Name:      name,
	}
	hmac, err := Hmac(&nonceInput, &keys.Mac)
	if err != nil {
		return nil, err
	}
	var nbox proto.NaclSecretBox

	// take the first 16 bytes of the HMAC as the nonce
	copy(nbox.Nonce[:], hmac[:])

	ctext, err := SealIntoSecretBoxWithNonce(
		&name,
		&nbox.Nonce,
		&keys.Box,
	)
	if err != nil {
		return nil, err
	}
	nbox.Ciphertext = ctext
	ret := proto.NewSecretBoxWithNacl(
		nbox,
	)
	return &ret, nil
}

const MinPaddedSize = 32

func ConvergentPaddedEncryption(
	p core.CryptoPayloader,
	s *proto.SecretSeed32,
) (
	*proto.HMAC,
	proto.NaclCiphertext,
	error,
) {
	dm := proto.NewKVKeyDerivationDefault(proto.KVKeyType_MAC)
	macKey, err := core.GenericDeriveKey32(*s, &dm)
	if err != nil {
		return nil, nil, err
	}
	hmac, err := core.Hmac(p, (*proto.HMACKey)(macKey))
	if err != nil {
		return nil, nil, err
	}
	db := proto.NewKVKeyDerivationDefault(proto.KVKeyType_Box)
	boxKey, err := core.GenericDeriveKey32(*s, &db)
	if err != nil {
		return nil, nil, err
	}
	var nonce proto.NaclNonce
	copy(nonce[:], hmac[:])
	ctext, err := core.SealIntoSecretBoxWithNonceAndPadding(
		p,
		&nonce,
		(*proto.SecretBoxKey)(boxKey),
		MinPaddedSize,
	)
	if err != nil {
		return nil, nil, err
	}
	return hmac, ctext, nil
}

type KeyBundle struct {
	sync.Mutex
	seed proto.SecretSeed32
	mac  *proto.HMACKey
	box  *proto.SecretBoxKey
}

func NewKeyBundle(s *proto.SecretSeed32) *KeyBundle {
	return &KeyBundle{
		seed: *s,
	}
}

func (k *KeyBundle) MacKey() (*proto.HMACKey, error) {
	k.Lock()
	defer k.Unlock()
	if k.mac != nil {
		return k.mac, nil
	}
	dm := proto.NewKVKeyDerivationDefault(proto.KVKeyType_MAC)
	macKey, err := core.GenericDeriveKey32(k.seed, &dm)
	if err != nil {
		return nil, err
	}
	k.mac = (*proto.HMACKey)(macKey)
	return k.mac, nil
}

func (k *KeyBundle) Hmac(c core.CryptoPayloader) (*proto.HMAC, error) {
	mk, err := k.MacKey()
	if err != nil {
		return nil, err
	}
	return core.Hmac(c, mk)
}

func (k *KeyBundle) BoxPadded(c core.CryptoPayloader) (*proto.SecretBox, error) {
	bk, err := k.BoxKey()
	if err != nil {
		return nil, err
	}
	return core.SealIntoSecretBoxWithPadding(c, bk, MinPaddedSize)
}

func (k *KeyBundle) BoxPaddedWithNonce(c core.CryptoPayloader, n *proto.NaclNonce) (proto.NaclCiphertext, error) {
	bk, err := k.BoxKey()
	if err != nil {
		return nil, err
	}
	return core.SealIntoSecretBoxWithNonceAndPadding(c, n, bk, MinPaddedSize)
}

func (k *KeyBundle) Box(c core.CryptoPayloader) (*proto.SecretBox, error) {
	bk, err := k.BoxKey()
	if err != nil {
		return nil, err
	}
	return core.SealIntoSecretBox(c, bk)
}

func (k *KeyBundle) Unbox(cp core.CryptoPayloader, s proto.SecretBox) error {
	bk, err := k.BoxKey()
	if err != nil {
		return err
	}
	return core.OpenSecretBoxInto(cp, s, bk)
}

func (k *KeyBundle) BoxWithNonce(c core.CryptoPayloader, n *proto.NaclNonce) (proto.NaclCiphertext, error) {
	bk, err := k.BoxKey()
	if err != nil {
		return nil, err
	}
	return core.SealIntoSecretBoxWithNonce(c, n, bk)
}

func (k *KeyBundle) BoxKey() (*proto.SecretBoxKey, error) {
	k.Lock()
	defer k.Unlock()
	if k.box != nil {
		return k.box, nil
	}
	dm := proto.NewKVKeyDerivationDefault(proto.KVKeyType_Box)
	boxKey, err := core.GenericDeriveKey32(k.seed, &dm)
	if err != nil {
		return nil, err
	}
	k.box = (*proto.SecretBoxKey)(boxKey)
	return k.box, nil

}

func PaddedLen(n int64) (int64, error) {

	if n > 0xffffffff {
		return 0, core.TooBigError{}
	}
	if n < 0 {
		return 0, core.InternalError("negative length")
	}

	base2 := int64(MinPaddedInputSize)
	i := 0
	pad := int64(PadSpecs[i].Overhead)
	ret := base2 + pad // padded len w/ overhead

	for {
		if n <= ret {
			return ret, nil
		}
		base2 = base2 << 1
		if i < len(PadSpecs)-1 && base2 >= int64(PadSpecs[i+1].AtOrAbove) {
			i++
			pad = int64(PadSpecs[i].Overhead)
		}
		ret = base2 + pad
	}
}

func PaddedLenInv(n int64) (int64, error) {
	if n > 0xffffffff {
		return 0, core.TooBigError{}
	}
	if n < 0 {
		return 0, core.InternalError("negative length")
	}
	for i := len(PadSpecs) - 1; i >= 0; i-- {
		if n >= int64(PadSpecs[i].AtOrAbove) {
			return n - int64(PadSpecs[i].Overhead), nil
		}
	}
	return 0, core.InternalError("unreachable")
}

func PadChunk(b []byte) ([]byte, error) {
	n, err := PaddedLen(int64(len(b)))
	if err != nil {
		return nil, err
	}
	ret := make([]byte, n)
	copy(ret, b)
	return ret, nil
}

func Align(o proto.Offset, n proto.Offset) proto.Offset {
	return o - (o % n)
}
