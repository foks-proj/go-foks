// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"

	"github.com/foks-proj/go-foks/lib/cks"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type CertPackage struct {
	Priv    crypto.PrivateKey
	Pub     crypto.PublicKey
	CertID  proto.PKIXCertID
	Certs   []*x509.Certificate
	CertRaw [][]byte
}

type CAScope int

const (
	CASCopeNone           CAScope = 0
	CASCopeClientInternal CAScope = 1 // API servers, internal CA root
	CASCopeClientExternal CAScope = 2 // Front-end API servers, Client CA root
	CAScopeExternal       CAScope = 3 // for front-end API servers
)

func (c CAScope) String() string {
	switch c {
	case CASCopeClientExternal:
		return "cli_external"
	case CASCopeClientInternal:
		return "cli_internal"
	case CAScopeExternal:
		return "external"
	default:
		return "none"
	}
}

func readX509Bytes(f core.Path) ([][]byte, error) {
	raw, err := f.ReadFile()
	if err != nil {
		return nil, err
	}
	var ret [][]byte
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		ret = append(ret, block.Bytes)
		raw = rest
	}
	return ret, nil
}

func ReadCertPackageFromFiles(kc core.KeyCertFilePair) (*CertPackage, error) {

	raw, err := readX509Bytes(kc.Key)
	if err != nil {
		return nil, err
	}
	if len(raw) != 1 {
		return nil, core.X509Error("expected exactly one key in the key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(raw[0])
	if err != nil {
		return nil, err
	}
	pubber, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return nil, core.X509Error("key is not a public key")
	}
	pub := pubber.Public()
	keyId, err := core.ComputePKIXCertID(pub)
	if err != nil {
		return nil, err
	}

	certRaw, err := readX509Bytes(kc.Cert)
	if err != nil {
		return nil, err
	}
	var flat []byte
	for _, b := range certRaw {
		flat = append(flat, b...)
	}
	certs, err := x509.ParseCertificates(flat)
	if err != nil {
		return nil, err
	}
	return &CertPackage{
		Pub:     pub,
		Priv:    key,
		Certs:   certs,
		CertRaw: certRaw,
		CertID:  keyId,
	}, nil
}

func readSecretKeyDecodePEM(block *pem.Block) (crypto.PrivateKey, error) {
	caPrivKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, core.X509Error("failed to parse private key from PEM")
	}
	return caPrivKey, nil
}

func ReadSecretKeyFromFile(ctx context.Context, fn core.Path) (crypto.PrivateKey, error) {
	raw, err := fn.ReadFile()
	if err != nil {
		return nil, err
	}

	// First try PEM
	if block, _ := pem.Decode([]byte(raw)); block != nil {
		return readSecretKeyDecodePEM(block)
	}

	// Next try base64-encoded Snowpack (as in HostKey output).
	// If it's not this, it's a failure, so can return errors.
	hk, err := ReadHostKeyFromFile(ctx, fn)
	if err != nil {
		return nil, err
	}
	return hk.PrivateKey(), nil
}

func ReadCertFromFile(f core.Path) ([]byte, error) {

	caCertPEM, err := f.ReadFile()
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(caCertPEM))
	if block == nil {
		return nil, errors.New("cannot decode PEM certificate")
	}
	return block.Bytes, nil
}

func MakeCertificate(
	ctx context.Context,
	hosts []string,
	caKeyFile core.Path,
	caCertFile core.Path,
	keyOutFile core.Path,
	certOutFile core.Path,
	logger func(string, ...interface{}),
	opts core.X509WriteOpts) error {

	caPrivKey, err := ReadSecretKeyFromFile(ctx, caKeyFile)
	if err != nil {
		return errors.New("reading private key: " + err.Error())
	}

	caCertRaw, err := ReadCertFromFile(caCertFile)
	if err != nil {
		return err
	}

	return MakeCertificateWithCAKeyAndCert(
		hosts, caPrivKey, caCertRaw, keyOutFile, certOutFile, logger, opts,
	)
}

func MakeCertificateWithCAKeyAndCert(
	hosts []string,
	caPrivKey crypto.PrivateKey,
	caCertRaw []byte,
	keyOutFile core.Path,
	certOutFile core.Path,
	logger func(string, ...interface{}),
	opts core.X509WriteOpts,
) error {

	if opts.MkdirP {
		err := certOutFile.MakeParentDirs()
		if err != nil {
			return err
		}
		err = keyOutFile.MakeParentDirs()
		if err != nil {
			return err
		}
	}

	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	template, err := core.CertTemplate(hosts)
	if err != nil {
		return err
	}

	caCert, err := x509.ParseCertificate(caCertRaw)
	if err != nil {
		return err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, pubKey, caPrivKey)
	if err != nil {
		return err
	}

	err = core.WriteSingleCertBytesX509(certOutFile, derBytes, opts)
	if err != nil {
		return err
	}

	logger("📜 wrote %s", certOutFile)

	err = core.WriteSecretKeyX509(keyOutFile, priv, opts)
	if err != nil {
		return err
	}

	logger("🔑 wrote %s", keyOutFile)
	return nil
}

func GenCA(keyFile, certFile core.Path) error {
	caPrivKey, caBytes, err := core.GenCAInMem()
	if err != nil {
		return err
	}
	return WriteCACertAndKeyPEM(caPrivKey, caBytes, keyFile, certFile)
}

func WriteCACertPEM(caBytes []byte, certFile core.Path) error {
	pubFh, err := os.OpenFile(certFile.String(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}

	// pem encode
	err = pem.Encode(pubFh, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return err
	}
	err = pubFh.Close()
	if err != nil {
		return err
	}
	return nil
}

func WriteCACertAndKeyPEM(caPrivKey crypto.PrivateKey, caBytes []byte, keyFile core.Path, certFile core.Path) error {

	err := WriteCACertPEM(caBytes, certFile)
	if err != nil {
		return err
	}

	err = WriteCAKeyPEM(caPrivKey, keyFile)
	if err != nil {
		return err
	}

	return nil
}

func WriteCAKeyPEM(caPrivKey crypto.PrivateKey, keyFile core.Path) error {

	privFh, err := os.OpenFile(keyFile.String(), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	b, err := x509.MarshalPKCS8PrivateKey(caPrivKey)
	if err != nil {
		return err
	}
	err = pem.Encode(privFh, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})
	if err != nil {
		return err
	}

	err = privFh.Close()
	if err != nil {
		return err
	}
	return nil
}

func EmulateLetsEncrypt(
	m MetaContext,
	hosts []proto.Hostname,
	aliases []proto.Hostname,
	caCertRaw []byte,
	caKey crypto.PrivateKey,
	typ proto.CKSAssetType,
	inTest bool,
) error {
	bits := core.Sel(inTest, 1024, 2048)
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	pkixer, err := m.G().Config().PKIXConfig(m.Ctx())
	if err != nil {
		return err
	}
	name := pkixer.Name()
	template, err := core.CertTemplateWithPKIX(hosts, name)
	if err != nil {
		return err
	}
	pub := priv.Public()
	keyid, err := core.ComputePKIXCertID(pub)
	if err != nil {
		return err
	}
	template.SubjectKeyId = keyid.Bytes()
	caCert, err := x509.ParseCertificate(caCertRaw)
	if err != nil {
		return err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caKey)
	if err != nil {
		return err
	}
	rawkey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}

	data := &cks.X509Bundle{
		Key:     proto.NewCKSCertKeyWithX509(rawkey),
		Cert:    proto.NewCKSCertChainFromSingle(certBytes),
		KeyID:   keyid.EntityID(),
		Primary: true,
		Etime:   template.NotAfter,
	}

	return m.G().CertMgr().PutExternallyGeneratedCert(m, typ, aliases, data)
}
