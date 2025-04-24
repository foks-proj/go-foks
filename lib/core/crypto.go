// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/keybase/go-codec/codec"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

func OpenSecretBoxInto(res CryptoPayloader, box proto.SecretBox, key *proto.SecretBoxKey) error {
	t, err := box.GetT()
	if err != nil {
		return err
	}
	if t != proto.BoxType_NACL {
		return VersionNotSupportedError(fmt.Sprintf("can only open NACL box types; got %d", t))
	}
	nbox := box.Nacl()

	return OpenSecretBoxWithNonceInto(res, nbox.Ciphertext, &nbox.Nonce, key)
}

func OpenSecretBoxWithNonceInto(res CryptoPayloader, ctext proto.NaclCiphertext, partialNonce *proto.NaclNonce, key *proto.SecretBoxKey) error {

	var nonce [24]byte

	// Write the object type we're expecting into the nonce
	res.GetTypeUniqueID().EncodeToBytes(nonce[0:])
	// The last 2/3 of the nonce comes over the Wire
	copy(nonce[8:], partialNonce[:])

	buf, ok := secretbox.Open(nil, ctext[:], &nonce, (*[32]byte)(key))
	if !ok {
		return DecryptionError{}
	}
	err := DecodeFromBytes(res, buf)
	if err != nil {
		return err
	}
	return nil
}

func roundUpBase2(n int, min int) int {
	if n <= min {
		return min
	}
	ret := min * 2
	for ret < n {
		ret *= 2
	}
	return ret
}

func Padlen(n int, min int) int {
	return roundUpBase2(n, min) - n
}

func SealIntoSecretBoxWithNonceAndPadding(
	obj CryptoPayloader,
	upper *proto.NaclNonce,
	key *proto.SecretBoxKey,
	padMin int,
) (
	proto.NaclCiphertext,
	error,
) {
	// The first 8 bytes of the 24-byte nonce are the object ID compiled into the
	// protocol. This way the protocol compiler will manage it for us. We just have
	// to be sure we never duplicate these things
	var nonce [24]byte
	copy(nonce[8:], upper[:])
	obj.GetTypeUniqueID().EncodeToBytes(nonce[0:])

	return SealIntoSecretBoxWithRawNonceAndPadding(obj, &nonce, key, padMin)
}

func SealIntoSecretBoxWithRawNonceAndPadding(
	obj CryptoPayloader,
	nonce *[24]byte,
	key *proto.SecretBoxKey,
	padMin int,
) (
	proto.NaclCiphertext,
	error,
) {

	msg, err := EncodeToBytes(obj)
	if err != nil {
		return nil, err
	}

	return SealMsgIntoSecretBoxWtihRawNonceAndPadding(msg, nonce, key, padMin)
}

func SealMsgIntoSecretBoxWtihRawNonceAndPadding(
	msg []byte,
	nonce *[24]byte,
	key *proto.SecretBoxKey,
	padMin int,
) (
	proto.NaclCiphertext,
	error,
) {

	if padMin > 0 {
		if pl := Padlen(len(msg), padMin); pl > 0 {
			msg = append(msg, make([]byte, pl)...)
		}
	}

	return proto.NaclCiphertext(
		secretbox.Seal(nil, msg, nonce, ((*[32]byte)(key))),
	), nil
}

func SealIntoSecretBoxWithNonce(obj CryptoPayloader, upper *proto.NaclNonce, key *proto.SecretBoxKey) (proto.NaclCiphertext, error) {
	return SealIntoSecretBoxWithNonceAndPadding(obj, upper, key, 0)
}

func SealIntoSecretBox(obj CryptoPayloader, key *proto.SecretBoxKey) (*proto.SecretBox, error) {
	return SealIntoSecretBoxWithPadding(obj, key, 0)
}

func SealIntoSecretBoxWithPadding(obj CryptoPayloader, key *proto.SecretBoxKey, padMin int) (*proto.SecretBox, error) {
	var nbox proto.NaclSecretBox
	err := RandomFill(nbox.Nonce[:])
	if err != nil {
		return nil, err
	}
	ctext, err := SealIntoSecretBoxWithNonceAndPadding(obj, &nbox.Nonce, key, padMin)
	if err != nil {
		return nil, err
	}
	nbox.Ciphertext = ctext
	ret := proto.NewSecretBoxWithNacl(nbox)
	return &ret, nil
}

func RandomSecretBoxKey() (*proto.SecretBoxKey, error) {
	var ret proto.SecretBoxKey
	err := RandomFill(ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func RandomFill(b []byte) error {
	n, err := rand.Read(b[:])
	if err != nil {
		return err
	}
	if n != len(b) {
		return InternalError("short read from rnadom in secret box key creation")
	}
	return nil
}

func RandomBytes(n int) ([]byte, error) {
	ret := make([]byte, n)
	err := RandomFill(ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func Curve25519DHExchange(
	sk *proto.Curve25519SecretKey,
	pk *proto.Curve25519PublicKey,
) (
	*proto.SecretBoxKey,
	error,
) {
	var ret proto.SecretBoxKey
	box.Precompute((*[32]byte)(&ret), (*[32]byte)(pk), (*[32]byte)(sk))
	return &ret, nil
}

// Simple one-off boxes with Nacl. Won't be useful for shared team keys
// because those are (1) done in groups and; (2) can use yubikeys.
func SealIntoNaclBox(
	obj CryptoPayloader,
	sk *proto.Curve25519SecretKey,
	pk *proto.Curve25519PublicKey,
	opts BoxOpts,
) (*proto.Box, error) {

	var nbox proto.NaclBox

	// The first 8 bytes of the 24-byte nonce are the object ID compiled into the
	// protocol. This way the protocol compiler will manage it for us. We just have
	// to be sure we never duplicate these things
	var nonce [24]byte
	var randomTop proto.NaclNonce

	obj.GetTypeUniqueID().EncodeToBytes(nonce[:])
	err := RandomFill(randomTop[:])
	if err != nil {
		return nil, err
	}
	copy(nonce[8:], randomTop[:])

	nbox.Nonce = &randomTop
	if opts.IncludePublicKey {
		nbox.Pk = sk.PublicKey()
	}

	msg, err := EncodeToBytes(obj)
	if err != nil {
		return nil, err
	}

	nbox.Ciphertext = box.Seal(
		nil,
		msg,
		&nonce,
		((*[32]byte)(pk)),
		((*[32]byte)(sk)),
	)

	ret := proto.NewBoxWithNacl(nbox)
	return &ret, nil
}

func OpenNaclBox(
	obj CryptoPayloader,
	pbox proto.Box,
	rcvr *proto.Curve25519SecretKey,
	sndr *proto.Curve25519PublicKey,
) (
	*proto.Curve25519PublicKey,
	error,
) {
	t, err := pbox.GetT()
	if err != nil {
		return nil, err
	}
	if t != proto.BoxType_NACL {
		return nil, BoxError("cannot open nacl box with wrong type")
	}
	nbox := pbox.Nacl()

	var nonce [24]byte
	obj.GetTypeUniqueID().EncodeToBytes(nonce[:])
	copy(nonce[8:], nbox.Nonce[:])

	pk := sndr
	if pk == nil {
		pk = nbox.Pk
	}
	if pk == nil {
		return nil, BoxError("cannot open nacl box without public key")
	}

	plaintext, ok := box.Open(
		nil,
		nbox.Ciphertext[:],
		&nonce,
		((*[32]byte)(pk)),
		((*[32]byte)(rcvr)),
	)
	if !ok {
		return nil, DecryptionError{}
	}

	err = DecodeFromBytes(obj, plaintext)
	if err != nil {
		return nil, err
	}
	return pk, nil
}

func Hash(o Codecable) (*proto.StdHash, error) {
	var ret proto.StdHash
	err := HashInto(o, ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func PrefixedHash(o CryptoPayloader) (*proto.StdHash, error) {
	var ret proto.StdHash
	err := PrefixedHashInto(o, ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func PrefixedHashInto(o CryptoPayloader, out []byte) error {
	mh := Codec()
	h := sha512.New512_256()
	var buf [8]byte
	o.GetTypeUniqueID().EncodeToBytes(buf[:])
	n, err := h.Write(buf[:])
	if err != nil {
		return err
	}
	if n != 8 {
		return errors.New("short write")
	}
	enc := codec.NewEncoder(h, mh)
	err = o.Encode(enc)
	if err != nil {
		return nil
	}
	tmp := h.Sum(nil)
	if len(tmp) != len(out) {
		return InternalError("hash len mismatch")
	}
	copy(out[:], tmp)
	return nil
}

// We mainly use SHA512/256, but for hybrid encryption key swizzling,
// we use SHA3 since it's what the IETF draft / paper prescribe.
func PrefixedSHA3HashInto(o CryptoPayloader, out []byte) error {
	mh := Codec()
	h := sha3.New256()
	var buf [8]byte
	o.GetTypeUniqueID().EncodeToBytes(buf[:])
	n, err := h.Write(buf[:])
	if err != nil {
		return err
	}
	if n != len(buf) {
		return errors.New("short write")
	}
	enc := codec.NewEncoder(h, mh)
	err = o.Encode(enc)
	if err != nil {
		return nil
	}
	tmp := h.Sum(nil)
	if len(tmp) != len(out) {
		return InternalError("hash len mismatch")
	}
	copy(out[:], tmp)
	return nil
}

func HashInto(o Codecable, out []byte) error {
	mh := Codec()
	h := sha512.New512_256()
	enc := codec.NewEncoder(h, mh)
	err := o.Encode(enc)
	if err != nil {
		return nil
	}
	tmp := h.Sum(nil)
	if len(tmp) != len(out) {
		return InternalError("hash len mismatch")
	}
	copy(out[:], tmp)
	return nil
}

func Hmac(obj CryptoPayloader, key *proto.HMACKey) (*proto.HMAC, error) {
	mh := Codec()
	hm := hmac.New(sha512.New512_256, (*key)[:])
	var buf [8]byte
	obj.GetTypeUniqueID().EncodeToBytes(buf[:])
	n, err := hm.Write(buf[:])
	if err != nil {
		return nil, err
	}
	if n != 8 {
		return nil, errors.New("short write")
	}
	enc := codec.NewEncoder(hm, mh)
	err = obj.Encode(enc)
	if err != nil {
		return nil, err
	}
	tmp := hm.Sum(nil)
	var ret proto.HMAC
	copy(ret[:], tmp)
	return &ret, nil
}

func LinkHash(l *proto.LinkOuter) (*proto.LinkHash, error) {
	var ret proto.LinkHash
	err := LinkHashInto(l, ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func HostchainLinkHash(l *proto.HostchainLinkOuter) (*proto.LinkHash, error) {
	var ret proto.LinkHash
	err := PrefixedHashInto(l, ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func LinkHashInto(l *proto.LinkOuter, out []byte) error {
	return PrefixedHashInto(l, out)
}
