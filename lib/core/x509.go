// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"

	proto "github.com/foks-proj/go-foks/proto/lib"
)

type KeyCertFilePair struct {
	Key  Path
	Cert Path
}

func GenCAInMem() (crypto.PrivateKey, []byte, error) {

	// create our private and public key
	caPubKey, caPrivKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	cert, err := GenCAFromKeyPair(caPubKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}
	return caPrivKey, cert, nil
}

const SubjectOrg = "ne43, Inc."

func GenCAFromKeyPair(caPubKey crypto.PublicKey, caPrivKey crypto.PrivateKey) ([]byte, error) {
	subject := pkix.Name{
		Organization: []string{SubjectOrg},
		Country:      []string{"US"},
		Province:     []string{"New York"},
	}

	cert, _, err := GenCAFromKeyPairAndSubject(caPubKey, caPrivKey, nil, subject)
	return cert, err
}

func GenCAFromKeyPairAndSubject(
	caPubKey crypto.PublicKey,
	caPrivKey crypto.PrivateKey,
	keyId proto.EntityID,
	subject pkix.Name,
) (
	[]byte,
	time.Time,
	error,
) {

	etime := time.Now().AddDate(10, 0, 0)

	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              etime,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	if keyId != nil {
		ca.SubjectKeyId = keyId.Bytes()
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPubKey, caPrivKey)
	if err != nil {
		return nil, time.Time{}, err
	}
	return caBytes, etime, nil
}

func RandomSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	return serialNumber, nil

}

func addHosts(
	hosts []proto.Hostname,
	ips *([]net.IP),
	dnsNames *([]string),
) {
	for _, h := range hosts {
		if ip := h.ToIPAddr(); ip != nil {
			*ips = append(*ips, ip)
		} else {
			*dnsNames = append(*dnsNames, h.String())
		}
	}
}

func CSRTemplate(hosts []string) (*x509.CertificateRequest, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{SubjectOrg},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	hns := Map(hosts, func(h string) proto.Hostname { return proto.Hostname(h) })
	addHosts(hns, &template.IPAddresses, &template.DNSNames)
	return template, nil
}

const CertTemplateDuration = 10 * 365 * 24 * time.Hour

func CertTemplateWithPKIX(
	hosts []proto.Hostname,
	pkix pkix.Name,
) (
	*x509.Certificate,
	error,
) {
	serialNumber, err := RandomSerialNumber()
	if err != nil {
		return nil, err
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(CertTemplateDuration),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	addHosts(hosts, &template.IPAddresses, &template.DNSNames)
	return &template, nil
}

func CertTemplate(hosts []string) (*x509.Certificate, error) {
	hns := Map(hosts, func(h string) proto.Hostname { return proto.Hostname(h) })
	return CertTemplateWithPKIX(hns, pkix.Name{Organization: []string{SubjectOrg}})
}

func MakeCertificateInMem(
	hosts []string,
	caPriv crypto.PrivateKey,
	caBytes []byte,
) (
	crypto.PrivateKey,
	[]byte,
	error,
) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template, err := CertTemplate(hosts)
	if err != nil {
		return nil, nil, err
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caPriv)
	if err != nil {
		return nil, nil, err
	}

	return priv, derBytes, nil
}

type CAPool struct {
	in        []string
	raw       []string
	useSystem bool
	pool      *x509.CertPool
	isLoaded  bool
}

func (c *CAPool) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	var v []string
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}
	c.load(v)
	return nil
}

func (c *CAPool) load(v []string) {
	c.in = v
	c.raw = make([]string, 0, len(v))
	for _, ca := range v {
		if ca == "-" {
			c.useSystem = true
		} else {
			c.raw = append(c.raw, ca)
		}
	}
	c.isLoaded = true
}

func (c *CAPool) IsLoaded() bool {
	return c.isLoaded
}

func NewCAPool(v []string) *CAPool {
	ret := &CAPool{}
	ret.load(v)
	return ret
}

func NewSystemCAPool() *CAPool {
	return &CAPool{
		useSystem: true,
		isLoaded:  true,
	}
}

func (c CAPool) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.in)
}

type CAPoolType int

const (
	CAPoolTypeNone            CAPoolType = 0
	CAPoolTypeClientCA        CAPoolType = 1
	CAPoolTypeDefaultToSystem CAPoolType = 2
)

func (c *CAPool) Raw() []string {
	return c.raw
}

func (c *CAPool) CompileReturnRaw(ctx context.Context, typ CAPoolType) (*x509.CertPool, []string, error) {
	pool, err := c.Compile(ctx, typ)
	if err != nil {
		return nil, nil, err
	}
	return pool, c.raw, nil
}

func (c *CAPool) Compile(ctx context.Context, typ CAPoolType) (*x509.CertPool, error) {

	if len(c.raw) == 0 {
		if typ == CAPoolTypeDefaultToSystem {
			return x509.SystemCertPool()
		} else {
			newPool := x509.NewCertPool()
			return newPool, nil
		}
	}

	if c.pool != nil {
		return c.pool, nil
	}

	if c.useSystem && typ == CAPoolTypeClientCA {
		return nil, TLSError("cannot use system CA for client mTLS CA")
	}
	var dat []string

	for _, ca := range c.raw {
		f, err := ExpandX509File(ctx, ca)
		if err != nil {
			return nil, err
		}
		dat = append(dat, f)
	}

	var pool *x509.CertPool

	if c.useSystem {
		tmp, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		pool = tmp.Clone()
	} else {
		pool = x509.NewCertPool()
	}

	for _, cert := range dat {
		ok := pool.AppendCertsFromPEM([]byte(cert))
		if !ok {
			return nil, TLSError("failed to append cert")
		}
	}
	c.pool = pool
	return pool, nil
}

type X509WriteOpts struct {
	OverwriteOk bool
	MkdirP      bool
}

func (x X509WriteOpts) OpenFlags() int {
	flags := os.O_WRONLY | os.O_CREATE
	if x.OverwriteOk {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	return flags

}

func checkFile(f Path, opts X509WriteOpts) error {
	fi, err := f.Stat()
	if err != nil {
		// Not found
		if _, ok := err.(*os.PathError); ok {
			return nil
		}
		return err
	}
	if fi.IsDir() {
		return TLSError("file is a directory")
	}
	if !opts.OverwriteOk {
		return TLSError("file exists")
	}
	return nil
}

func x509Prep(
	f Path,
	opts X509WriteOpts,
) error {
	if opts.MkdirP {
		err := f.MakeParentDirs()
		if err != nil {
			return err
		}
	}
	err := checkFile(f, opts)
	if err != nil {
		return err
	}
	return nil
}

func WriteSecretKeyX509(
	f Path,
	k crypto.PrivateKey,
	opts X509WriteOpts,
) error {
	err := x509Prep(f, opts)
	if err != nil {
		return err
	}
	tmp, err := f.AdjacentTemp()
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	privBytes, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	if err := pem.Encode(tmp, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}
	err = tmp.Close()
	if err != nil {
		return err
	}
	err = os.Rename(tmp.Name(), f.String())
	if err != nil {
		return err
	}
	return nil
}

func WriteSingleCertBytesX509(
	f Path,
	certs []byte,
	opts X509WriteOpts,
) error {
	return WriteCertsBytesX509(f, [][]byte{certs}, opts)
}

func WriteCertsBytesX509(
	f Path,
	certs [][]byte,
	opts X509WriteOpts,
) error {
	err := x509Prep(f, opts)
	if err != nil {
		return err
	}
	tmp, err := f.AdjacentTemp()
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	for _, cert := range certs {
		if err := pem.Encode(tmp, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return err
		}
	}
	err = tmp.Close()
	if err != nil {
		return err
	}
	err = os.Rename(tmp.Name(), f.String())
	if err != nil {
		return err
	}
	return nil
}
