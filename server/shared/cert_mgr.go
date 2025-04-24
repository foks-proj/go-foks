// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/foks-proj/go-foks/lib/cks"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
)

type CertManager interface {
	GenCA(m MetaContext, typ proto.CKSAssetType) error
	PutCert(m MetaContext, tx pgx.Tx, idx cks.Index, dat *cks.X509Bundle) error
	GenCAWithCertGenerator(m MetaContext, typ proto.CKSAssetType, cg *CertGenerator) ([]byte, error)
	PutExternallyGeneratedCert(m MetaContext, typ proto.CKSAssetType, aliases []proto.Hostname, data *cks.X509Bundle) error
	GenServerCert(m MetaContext, allHosts []proto.Hostname, aliases []proto.Hostname, caType proto.CKSAssetType, certType proto.CKSAssetType) error
	Primary(m MetaContext, tx Querier, typ proto.CKSAssetType) (*cks.X509Bundle, error)
	ServerCert(m MetaContext, tx Querier, hn proto.Hostname, typ proto.CKSAssetType) (*cks.X509Bundle, error)
	AllCerts(m MetaContext, tx Querier, typ []proto.CKSAssetType, host proto.Hostname) ([]*x509.Certificate, error)
	Pool(m MetaContext, tx Querier, typ proto.CKSAssetType, host proto.Hostname) (*x509.CertPool, error)
	MakeGetConfigForClient(m MetaContext, cfg *tls.Config, styp proto.ServerType) func(*tls.ClientHelloInfo) (*tls.Config, error)
	AddCertsToPool(MetaContext, Querier, *x509.CertPool, []proto.CKSAssetType, proto.Hostname) error
	PoolForBaseHost(MetaContext, Querier, []proto.CKSAssetType) (*x509.CertPool, error)
}

type EmptyCertManager struct{}

var emptyErr = core.InternalError("empty cert manager should not be called")

func (e *EmptyCertManager) GenCA(m MetaContext, typ proto.CKSAssetType) error { return emptyErr }
func (e *EmptyCertManager) PutCert(m MetaContext, tx pgx.Tx, idx cks.Index, dat *cks.X509Bundle) error {
	return emptyErr
}
func (e *EmptyCertManager) GenCAWithCertGenerator(m MetaContext, typ proto.CKSAssetType, cg *CertGenerator) ([]byte, error) {
	return nil, emptyErr
}
func (e *EmptyCertManager) PutExternallyGeneratedCert(m MetaContext, typ proto.CKSAssetType, aliases []proto.Hostname, data *cks.X509Bundle) error {
	return emptyErr
}
func (e *EmptyCertManager) GenServerCert(m MetaContext, allHosts []proto.Hostname, aliases []proto.Hostname, caType proto.CKSAssetType, certType proto.CKSAssetType) error {
	return emptyErr
}
func (e *EmptyCertManager) Primary(m MetaContext, tx Querier, typ proto.CKSAssetType) (*cks.X509Bundle, error) {
	return nil, emptyErr
}
func (e *EmptyCertManager) ServerCert(m MetaContext, tx Querier, hn proto.Hostname, typ proto.CKSAssetType) (*cks.X509Bundle, error) {
	return nil, emptyErr
}
func (e *EmptyCertManager) AllCerts(m MetaContext, tx Querier, typ []proto.CKSAssetType, host proto.Hostname) ([]*x509.Certificate, error) {
	return nil, emptyErr
}
func (e *EmptyCertManager) Pool(m MetaContext, tx Querier, typ proto.CKSAssetType, host proto.Hostname) (*x509.CertPool, error) {
	return nil, emptyErr
}
func (e *EmptyCertManager) MakeGetConfigForClient(m MetaContext, cfg *tls.Config, styp proto.ServerType) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, emptyErr }
}
func (e *EmptyCertManager) AddCertsToPool(MetaContext, Querier, *x509.CertPool, []proto.CKSAssetType, proto.Hostname) error {
	return emptyErr
}
func (e *EmptyCertManager) PoolForBaseHost(MetaContext, Querier, []proto.CKSAssetType) (*x509.CertPool, error) {
	return nil, emptyErr
}

var _ CertManager = (*EmptyCertManager)(nil)
