// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type VerifiableBlob[T any] interface {
	Verifiable
	AllocAndDecode(f rpc.DecoderFactory) (T, error)
	Bytes() []byte
}

type VerifiableObj[T Verifiable] interface {
	AssertNormalized() error
	EncodeTyped(f rpc.EncoderFactory) (T, error)
}

func Verify2[P any, C VerifiableBlob[P]](v Verifier, sig proto.Signature, efv C) (P, error) {
	var zed P
	err := AssertCanonicalMsgpack(efv.Bytes())
	if err != nil {
		return zed, err
	}
	err = v.Verify(sig, efv)
	if err != nil {
		return zed, err
	}
	return efv.AllocAndDecode(DecoderFactory{})
}

func Sign2[C Verifiable, P VerifiableObj[C]](k Signer, obj P) (*proto.Signature, C, error) {
	var zed C
	o, err := obj.EncodeTyped(EncoderFactory{})
	if err != nil {
		return nil, zed, err
	}
	err = obj.AssertNormalized()
	if err != nil {
		return nil, zed, err
	}
	sig, err := k.Sign(o)
	if err != nil {
		return nil, o, err
	}

	return sig, o, nil
}
