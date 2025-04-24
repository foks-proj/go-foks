// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"crypto/rand"
	"errors"

	lcl "github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/keybase/saltpack/encoding/basex"
)

func randomReadPanic(b []byte) {
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
}

func RandomPassphraseSalt() proto.PassphraseSalt {
	var ret proto.PassphraseSalt
	_, err := rand.Read(ret[:])
	if err != nil {
		panic(err)
	}
	return ret
}

func RandomUID() proto.UID {
	var ret proto.UID
	ret[0] = byte(proto.EntityType_User)
	randomReadPanic(ret[1:])
	return ret
}

func RandomDeviceID() proto.DeviceID {
	var ret [33]byte
	ret[0] = byte(proto.EntityType_Device)
	randomReadPanic(ret[1:])
	return proto.DeviceID(ret[:])
}

func RandomHostID() proto.HostID {
	var ret proto.HostID
	ret[0] = byte(proto.EntityType_Host)
	randomReadPanic(ret[1:])
	return ret
}

func RandomSecretSeed32() proto.SecretSeed32 {
	var ret proto.SecretSeed32
	randomReadPanic(ret[:])
	return ret
}

func RandomHash() proto.StdHash {
	var ret proto.StdHash
	randomReadPanic(ret[:])
	return ret
}

func RandomMerkleRootHash() proto.MerkleRootHash {
	var ret proto.MerkleRootHash
	randomReadPanic(ret[:])
	return ret
}

func RandomBase62String(n int) string {
	b := make([]byte, n)
	randomReadPanic(b)
	return basex.Base62StdEncoding.EncodeToString(b)
}

func RandomFQU() proto.FQUser {
	return proto.FQUser{
		Uid:    RandomUID(),
		HostID: RandomHostID(),
	}
}

func randomSKMWK() lcl.SKMWK {
	var skmwk lcl.SKMWK
	_, err := rand.Read(skmwk[:])
	if err != nil {
		panic(err)
	}
	return skmwk
}

func RandomSKMWKList() lcl.SKMWKList {
	return lcl.SKMWKList{
		Fqu: proto.FQUser{
			Uid:    RandomUID(),
			HostID: RandomHostID(),
		},
		Keys: []lcl.SKMWK{
			randomSKMWK(),
			randomSKMWK(),
		},
	}
}

func RandomUsername(l int) (string, error) {
	buf := make([]byte, l)
	n, err := rand.Read(buf[:])
	if err != nil {
		return "", err
	}
	if n != l {
		return "", errors.New("short read")
	}
	suffx := basex.Base58StdEncoding.EncodeToString(buf[:])
	return "u" + suffx, nil
}

func RandomPassphrase() proto.Passphrase {
	return proto.Passphrase(RandomBase62String(8))
}

func RandomDomain() (string, error) {
	var buf [6]byte
	err := RandomFill(buf[:])
	if err != nil {
		return "", err
	}
	s := Base36Encoding.EncodeToString(buf[:])
	ret := "d-" + s + ".io"
	return ret, nil
}
