// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto/hmac"

	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/keybase/go-codec/codec"
)

func Codec() *codec.MsgpackHandle {
	var mh codec.MsgpackHandle
	mh.WriteExt = true
	return &mh
}

type Encodeable interface {
	Encode(rpc.Encoder) error
}

type Codecable interface {
	Encodeable
	Decode(rpc.Decoder) error
}

type CryptoPayloader interface {
	Codecable
	GetTypeUniqueID() rpc.TypeUniqueID
}

func DecodeFromBytes(t Codecable, b []byte) error {
	mh := Codec()
	dec := codec.NewDecoderBytes(b, mh)
	err := t.Decode(dec)
	return err
}

func EncodeToBytes(t Encodeable) ([]byte, error) {
	var b []byte
	mh := Codec()
	enc := codec.NewEncoderBytes(&b, mh)
	err := t.Encode(enc)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func Clone[
	T any,
	PT interface {
		Codecable
		*T
	},
](o PT) (PT, error) {
	b, err := EncodeToBytes(o)
	if err != nil {
		return nil, err
	}
	tmp := new(T)
	dest := PT(tmp)
	err = DecodeFromBytes(dest, b)
	if err != nil {
		return nil, err
	}
	return dest, nil
}

func Eq(o1 Codecable, o2 Codecable) (bool, error) {
	b1, err := EncodeToBytes(o1)
	if err != nil {
		return false, err
	}
	b2, err := EncodeToBytes(o2)
	if err != nil {
		return false, err
	}
	res := hmac.Equal(b1, b2)
	return res, nil
}

type DecoderFactory struct{}

func (f DecoderFactory) NewDecoderBytes(o any, i []byte) rpc.Decoder {
	mh := Codec()
	return codec.NewDecoderBytes(i, mh)
}

type EncoderFactory struct{}

func (e EncoderFactory) NewEncoderBytes(out *[]byte) rpc.Encoder {
	mh := Codec()
	return codec.NewEncoderBytes(out, mh)
}

var _ rpc.DecoderFactory = DecoderFactory{}
var _ rpc.EncoderFactory = EncoderFactory{}
