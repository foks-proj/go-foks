// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"io"
	"os"
	"path/filepath"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func RandomFillFile(fh *os.File, size int) (*proto.StdHash, error) {
	buf := make([]byte, 4*1024)
	h := sha512.New512_256()
	for i := 0; i < size; i += len(buf) {
		err := core.RandomFill(buf)
		if err != nil {
			return nil, err
		}
		_, err = fh.Write(buf)
		if err != nil {
			return nil, err
		}
		h.Write(buf)
	}
	tmp := h.Sum(nil)
	var ret proto.StdHash
	copy(ret[:], tmp)
	return &ret, nil
}

func HashFile(fn string) (*proto.StdHash, error) {
	fh, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	h := sha512.New512_256()
	buf := make([]byte, 4*1024)
	for {
		n, err := fh.Read(buf)
		if n == 0 && err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		h.Write(buf[:n])
	}
	tmp := h.Sum(nil)
	var ret proto.StdHash
	copy(ret[:], tmp)
	return &ret, nil
}

func EncryptSeedWithNoiseFile(
	ctx context.Context,
	seed proto.SecretSeed32,
	dir string,
) (*lcl.StoredSecretKeyBundle, error) {

	nmRaw, err := core.RandomBytes(10)
	if err != nil {
		return nil, err
	}
	nm := core.Base36Encoding.EncodeToString(nmRaw) + ".noise"
	fh, err := os.CreateTemp(dir, nm+".")
	if err != nil {
		return nil, err
	}
	defer func() {
		fh.Close()
		os.Remove(fh.Name())
	}()

	hash, err := RandomFillFile(fh, 1024*1024*4)
	if err != nil {
		return nil, err
	}
	fh.Close()
	err = os.Rename(fh.Name(), filepath.Join(dir, nm))
	if err != nil {
		return nil, err
	}
	var key proto.SecretBoxKey
	if len(key) != len(hash) {
		return nil, core.InternalError("secret key size != hash size")
	}
	copy(key[:], hash[:])
	skb := lcl.NewSecretKeyBundleWithV1(seed)
	newBox, err := core.SealIntoSecretBox(&skb, &key)
	if err != nil {
		return nil, err
	}
	bun := lcl.NoiseFileEncryptedSecretBundle{
		Filename:  nm,
		SecretBox: *newBox,
	}
	tmp := lcl.NewStoredSecretKeyBundleWithEncNoiseFile(bun)
	return &tmp, nil
}

func ClearNoiseFile(
	ctx context.Context,
	dir string,
	fn string,
) (err error) {
	fn = filepath.Join(dir, fn)
	fh, err := os.OpenFile(fn, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() {
		if fh != nil {
			tmp := fh.Close()
			if err == nil && tmp != nil {
				err = tmp
			}
		}
	}()
	stat, err := fh.Stat()
	if err != nil {
		return err
	}
	sz := stat.Size()

	for j := 0; j < 3; j++ {
		_, err := fh.Seek(0, 0)
		if err != nil {
			return err
		}
		var buf [4 * 1024]byte
		for i := int64(0); i < sz; i += int64(len(buf)) {
			_, err := rand.Read(buf[:])
			if err != nil {
				return err
			}
			_, err = fh.Write(buf[:])
			if err != nil {
				return err
			}
		}
	}
	err = fh.Close()
	fh = nil
	if err != nil {
		return err
	}
	return os.Remove(fn)
}

func (s *SecretKeyMaterialManager) unlockNoise(
	ctx context.Context,
	noise lcl.NoiseFileEncryptedSecretBundle,
) error {

	dir := s.secretStoreDir
	file := filepath.Join(dir, noise.Filename)
	hsh, err := HashFile(file)
	if err != nil {
		return err
	}
	var key proto.SecretBoxKey
	if len(key) != len(hsh) {
		return core.InternalError("secret key size != hash size")
	}
	copy(key[:], hsh[:])
	var ret lcl.SecretKeyBundle
	err = core.OpenSecretBoxInto(&ret, noise.SecretBox, &key)
	if err != nil {
		return err
	}
	err = s.unbundle(ret)
	if err != nil {
		return err
	}
	return nil
}
