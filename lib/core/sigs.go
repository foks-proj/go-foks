// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"math/big"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/keybase/go-codec/codec"
)

type EntityPublicEd25519 struct {
	proto.EntityID
}

type EntityPublicECDSA struct {
	proto.EntityID
}

type EntityPublic interface {
	Verifier
	GetEntityID() proto.EntityID
}

type EntityIDer interface {
	EntityID() proto.EntityID
}

func ImportEntityPublicSubclass(e EntityIDer) (EntityPublic, error) {
	return ImportEntityPublic(e.EntityID())
}

func ImportEntityPublic(e proto.EntityID) (EntityPublic, error) {
	if len(e) == 0 {
		return nil, PublicKeyError("empty entity id")
	}
	typ := e.Type()
	switch {
	case typ.IsEd25519():
		return EntityPublicEd25519{e}, nil
	case typ == proto.EntityType_Yubi:
		return EntityPublicECDSA{e}, nil
	default:
		return nil, PublicKeyError(fmt.Sprintf("entity type not supported: %d", e[0]))
	}
}

type EntityPublicRole struct {
	Ep   EntityPublic
	Role RoleKey
}

func NewEntityPublicRole(ep EntityPublic, r RoleKey) *EntityPublicRole {
	return &EntityPublicRole{Ep: ep, Role: r}
}

type Verifiable interface {
	Encode(rpc.Encoder) error
	GetTypeUniqueID() rpc.TypeUniqueID
	AssertNormalized() error
}

type Verifier interface {
	Verify(s proto.Signature, obj Verifiable) error
}

func EncodeVerifiableToBytes(obj Verifiable) ([]byte, error) {
	var b bytes.Buffer
	mh := Codec()
	err := obj.GetTypeUniqueID().Encode(&b)
	if err != nil {
		return nil, err
	}
	enc := codec.NewEncoder(&b, mh)
	err = obj.Encode(enc)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (e EntityPublicEd25519) Verify(s proto.Signature, obj Verifiable) error {
	key := e.PublicKeyEd25519()
	if key == nil {
		return VerifyError("cannot get public verification key")
	}
	return VerifyWithEd25519Public(key, s, obj)
}

func VerifyWithEd25519Public(key ed25519.PublicKey, s proto.Signature, obj Verifiable) error {
	typ, err := s.GetT()
	if err != nil {
		return err
	}
	if typ != proto.SignatureType_EDDSA {
		return VerifyError("wrong signature type")
	}
	msg, err := EncodeVerifiableToBytes(obj)
	if err != nil {
		return err
	}
	sig := s.Eddsa()
	ok := ed25519.Verify(key, msg, sig[:])
	if !ok {
		return VerifyError("signature verification failed")
	}
	return nil
}

func ECDSASigPayload(obj Verifiable) ([]byte, error) {
	msg, err := EncodeVerifiableToBytes(obj)
	if err != nil {
		return nil, err
	}
	data := sha512.Sum512_256(msg)
	return data[:], nil
}

func VerifyWithECDSAPublic(key *ecdsa.PublicKey, s proto.Signature, obj Verifiable) error {
	var sig struct {
		R, S *big.Int
	}
	t, err := s.GetT()
	if err != nil {
		return err
	}
	if t != proto.SignatureType_ECDSA {
		return VerifyError("wrong type of signature; wanted ECDSA")
	}
	rawSig := s.Ecdsa()
	if _, err := asn1.Unmarshal(rawSig, &sig); err != nil {
		return err
	}
	data, err := ECDSASigPayload(obj)
	if err != nil {
		return err
	}
	if !ecdsa.Verify(key, data, sig.R, sig.S) {
		return VerifyError("sig check failed")
	}
	return nil
}

func (e EntityPublicEd25519) GetEntityID() proto.EntityID {
	return e.EntityID
}

func (e EntityPublicECDSA) GetEntityID() proto.EntityID {
	return e.EntityID
}

func (e EntityPublicECDSA) Verify(s proto.Signature, obj Verifiable) error {
	pk, err := e.EntityID.ExportToPublicKey()
	if err != nil {
		return err
	}
	ecdsaPubkey, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return VerifyError("cannot verify with given public key")
	}
	return VerifyWithECDSAPublic(ecdsaPubkey, s, obj)
}

var _ EntityPublic = EntityPublicEd25519{}
var _ EntityPublic = EntityPublicECDSA{}

type Signer interface {
	Verifier
	Sign(obj Verifiable) (*proto.Signature, error)
}

type EntityPrivate interface {
	Signer
	EntityPublic() (EntityPublic, error)
	PrivateKeyForCert() (crypto.PrivateKey, error)
}

type DHKeypair struct {
	Seed proto.Curve25519SecretKey
}

type EntityPrivateEd25519 struct {
	typ  proto.EntityType
	seed proto.Ed25519SecretKey
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (e *EntityPrivateEd25519) PrivateKey() ed25519.PrivateKey {
	return e.priv
}

func (e *EntityPrivateEd25519) PrivateKeyForCert() (crypto.PrivateKey, error) {
	return e.priv, nil
}

func (e *EntityPrivateEd25519) PublicKey() ed25519.PublicKey {
	return e.pub
}

func (e *EntityPrivateEd25519) PrivateSeed() proto.Ed25519SecretKey {
	return e.seed
}

func (e EntityPrivateEd25519) Type() proto.EntityType {
	return e.typ
}

func NewEntityPrivateEd25519WithCryptoPrivate(typ proto.EntityType, priv crypto.PrivateKey) (*EntityPrivateEd25519, error) {
	edPriv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, proto.EntityError("cannot convert private key to ed25519")
	}
	pub := edPriv.Public().(ed25519.PublicKey)
	ret := &EntityPrivateEd25519{
		typ:  typ,
		priv: edPriv,
		pub:  pub,
	}
	seed := edPriv.Seed()
	if len(ret.seed) != len(seed) {
		return nil, proto.EntityError("invalid seed length")
	}
	copy(ret.seed[:], seed)
	return ret, nil
}

func NewEntityPrivateEd25519WithSeed(typ proto.EntityType, seed proto.Ed25519SecretKey) *EntityPrivateEd25519 {
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return &EntityPrivateEd25519{
		typ:  typ,
		seed: seed,
		priv: priv,
		pub:  pub,
	}
}

func NewEntityPrivateEd25519(typ proto.EntityType) (*EntityPrivateEd25519, error) {
	var seed proto.Ed25519SecretKey
	err := RandomFill(seed[:])
	if err != nil {
		return nil, err
	}
	return NewEntityPrivateEd25519WithSeed(typ, seed), nil
}

func (e *EntityPrivateEd25519) EntityPublic() (EntityPublic, error) {
	id, err := e.typ.MakeEntityID(e.pub)
	if err != nil {
		return nil, err
	}
	return EntityPublicEd25519{
		EntityID: id,
	}, nil
}

func (e *EntityPrivateEd25519) Sign(obj Verifiable) (*proto.Signature, error) {
	return SignWithEd21559Private(e.priv, obj)
}

func SignWithEd21559Private(priv ed25519.PrivateKey, obj Verifiable) (*proto.Signature, error) {
	msg, err := EncodeVerifiableToBytes(obj)
	if err != nil {
		return nil, err
	}
	rawSig := ed25519.Sign(priv, msg)
	var sig proto.Ed25519Signature
	if len(rawSig) != len(sig) {
		return nil, SignatureError("wrong size signature output")
	}
	copy(sig[:], rawSig)

	ret := proto.NewSignatureWithEddsa(sig)
	return &ret, nil
}

func (e *EntityPrivateEd25519) Verify(s proto.Signature, obj Verifiable) error {
	return VerifyWithEd25519Public(e.pub, s, obj)
}

var _ EntityPrivate = (*EntityPrivateEd25519)(nil)

type StackedVerifiable interface {
	Verifiable
	GetSignatures() []proto.Signature
	SetSignatures(s []proto.Signature)
}

func VerifyStackedSignature(s StackedVerifiable, keys []Verifier) error {
	sigs := s.GetSignatures()
	defer s.SetSignatures(sigs)
	if len(keys) == 0 {
		return VerifyError("cannot verify with 0 keys")
	}
	if len(sigs) != len(keys) {
		return VerifyError("wrong number of keys")
	}
	var stack []proto.Signature
	for i, key := range keys {
		s.SetSignatures(stack)
		if err := key.Verify(sigs[i], s); err != nil {
			return err
		}
		stack = append(stack, sigs[i])
	}
	return nil
}

func SignStacked(s StackedVerifiable, keys []Signer) error {
	var stack []proto.Signature
	s.SetSignatures(stack)
	for _, key := range keys {
		sig, err := key.Sign(s)
		if err != nil {
			return err
		}
		stack = append(stack, *sig)
		s.SetSignatures(stack)
	}
	return nil
}
