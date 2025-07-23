// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/foks-proj/go-foks/lib/cks"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
)

type CertGenerator struct {
	*core.EntityPrivateEd25519

	cert []byte

	eid   proto.EntityID
	pub   core.EntityPublic
	etime time.Time
}

func NewCertGenerator(typ proto.EntityType) (*CertGenerator, error) {
	epriv, err := core.NewEntityPrivateEd25519(typ)
	if err != nil {
		return nil, err
	}
	epub, err := epriv.EntityPublic()
	if err != nil {
		return nil, err
	}
	eid := epub.GetEntityID()
	return &CertGenerator{
		EntityPrivateEd25519: epriv,
		eid:                  eid,
		pub:                  epub,
	}, nil
}

func (h *CertGenerator) GenCA(m MetaContext) error {
	pkix, err := m.G().Config().PKIXConfig(m.Ctx())
	if err != nil {
		return err
	}
	cert, etime, err := core.GenCAFromKeyPairAndSubject(h.PublicKey(), h.PrivateKey(), h.eid, pkix.Name())
	if err != nil {
		return err
	}
	h.cert = cert
	h.etime = etime
	return nil
}

func (h *CertGenerator) GenServerCert(m MetaContext, ca *cks.X509Bundle, hosts []proto.Hostname) error {
	pkix, err := m.G().Config().PKIXConfig(m.Ctx())
	if err != nil {
		return err
	}
	template, err := core.CertTemplateWithPKIX(hosts, pkix.Name())
	if err != nil {
		return err
	}

	caBuilt, err := ca.BuildCert()
	if err != nil {
		return err
	}

	template.SubjectKeyId = h.eid.Bytes()
	template.AuthorityKeyId = ca.KeyID.Bytes()

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caBuilt.Leaf, h.PublicKey(), caBuilt.PrivateKey)
	if err != nil {
		return err
	}
	h.cert = certBytes
	h.etime = template.NotAfter
	return nil
}

func (k *CertGenerator) Cert() []byte { return k.cert }

func (k *CertGenerator) CKSData(pri bool) (*cks.X509Bundle, error) {
	if k.cert == nil {
		return nil, core.InternalError("no cert")
	}
	return &cks.X509Bundle{
		Key:     proto.NewCKSCertKeyWithEd25519(k.PrivateSeed()),
		KeyID:   k.eid,
		Cert:    proto.NewCKSCertChainFromSingle(k.cert),
		Etime:   k.etime,
		Primary: pri,
	}, nil
}

func (k *CertGenerator) ToV1() *HostKey {
	return NewHostKeyUnbacked(*k.EntityPrivateEd25519)
}

type CKSStorage struct {
	g *GlobalContext
}

func NewCKSStorage(g *GlobalContext) *CKSStorage {
	return &CKSStorage{g: g}
}

func (c *CKSStorage) Put(
	ctx context.Context,
	tx cks.Tx,
	id cks.Index,
	data cks.EncData,
) error {

	if tx == nil {
		db, err := c.g.Db(ctx, DbTypeServerConfig)
		if err != nil {
			return err
		}
		defer db.Release()
		tx = db
	}

	if id.Type == proto.CKSAssetType_None {
		return core.InternalError("refusing to insert a cert of type 'none' into x509_assets table")
	}

	dbe, ok := tx.(DbExecer)
	if !ok {
		return core.InternalError("not a db execer")
	}

	now := c.g.Clock().Now().UTC()
	boxBytes, err := core.EncodeToBytes(&data.KeyBox)
	if err != nil {
		return err
	}

	if data.Primary {
		// Ensure that there is only one primary cert for this host.
		_, err := dbe.Exec(ctx,
			`UPDATE x509_assets SET pri=false WHERE short_host_id=$1 AND typ=$2`,
			id.HostID.Short.ExportToDB(),
			id.Type.String(),
		)
		if err != nil {
			return err
		}
	}
	certBytes, err := core.EncodeToBytes(&data.Cert)
	if err != nil {
		return err
	}

	// we can get a conflict if we are refreshing a cert that already exists, as we
	// do about once ever 2 months via Let's Encrypt.
	tag, err := dbe.Exec(ctx,
		`INSERT INTO x509_assets (short_host_id, typ, key_id, active, pri, ctime, etime, keybox, cert_chain)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 ON CONFLICT (short_host_id, typ, key_id) 
		 DO UPDATE SET active=$4, pri=$5, ctime=$6, etime=$7, keybox=$8, cert_chain=$9`,
		id.HostID.Short.ExportToDB(),
		id.Type.String(),
		data.KeyID.ExportToDB(),
		true,
		data.Primary,
		now,
		data.Etime,
		boxBytes,
		certBytes,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("x509_assets")
	}
	return nil
}

func (c *CKSStorage) Get(ctx context.Context, tx cks.Tx, id cks.Index) ([]cks.EncData, error) {

	if tx == nil {
		db, err := c.g.Db(ctx, DbTypeServerConfig)
		if err != nil {
			return nil, err
		}
		defer db.Release()
		tx = db
	}

	rq, ok := tx.(Querier)
	if !ok {
		return nil, core.InternalError("not a db querier")
	}
	rows, err := rq.Query(ctx,
		`SELECT key_id, pri, keybox, cert_chain, etime 
		 FROM x509_assets 
		 WHERE short_host_id=$1 AND typ=$2 AND active=true`,
		id.HostID.Short.ExportToDB(),
		id.Type.String(),
	)

	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []cks.EncData
	for rows.Next() {
		var keyIDBytes, boxBytes, certBytes []byte
		var etime time.Time
		var primary bool

		err = rows.Scan(&keyIDBytes, &primary, &boxBytes, &certBytes, &etime)
		if err != nil {
			return nil, err
		}
		var certchain proto.CKSCertChain
		err = core.DecodeFromBytes(&certchain, certBytes)
		if err != nil {
			return nil, err
		}
		row := cks.EncData{
			Primary: primary,
			Etime:   etime,
			Cert:    certchain,
		}
		eid, err := proto.ImportEntityIDFromBytes(keyIDBytes)
		if err != nil {
			return nil, err
		}
		row.KeyID = eid
		err = core.DecodeFromBytes(&row.KeyBox, boxBytes)
		if err != nil {
			return nil, err
		}
		ret = append(ret, row)
	}
	return ret, nil
}

var _ cks.Storer = (*CKSStorage)(nil)

type CKS struct {
	*cks.CKS
}

type hostmapper struct {
	g *GlobalContext
}

func (h *hostmapper) HostIDForHostname(ctx context.Context, host proto.Hostname) (*core.HostID, error) {
	m := NewMetaContext(ctx, h.g)
	gmap := h.g.HostIDMap()
	ret, err := gmap.LookupByHostnameWithFallbackBehavior(m, host, HostnameLookupFallbackNone)

	if err == nil {
		return ret, nil
	}
	if !errors.Is(err, core.HostIDNotFoundError{}) {
		return nil, err
	}

	ret, err = gmap.LookupByAlias(m, host)
	if err == nil {
		return ret, nil
	}
	if !errors.Is(err, core.HostIDNotFoundError{}) {
		return nil, err
	}

	tmp := m.G().HostID()
	m.Warnw("TLS SNI hostmapper", "host", host, "err", "not found", "fallback", tmp.Short)

	return &tmp, nil
}

func PutAlias(m MetaContext, tx cks.Tx, host proto.Hostname) error {

	settings, err := m.G().Config().Settings(m.Ctx())
	if err != nil {
		return err
	}

	// It's a security risk to allow certs with DNS aliases to clobber other certs,
	// but it's very useful in testing. Therefore, we disallow it outside of testing.
	if !settings.Testing {
		return core.InternalError("DNS aliasing for certs only allowed in test")
	}

	if tx == nil {
		db, err := m.Db(DbTypeServerConfig)
		if err != nil {
			return err
		}
		defer db.Release()
		tx = db
	}

	dbe, ok := tx.(DbExecer)
	if !ok {
		return core.InternalError("not a db execer")
	}
	now := m.Clock().Now().UTC()

	tag, err := dbe.Exec(m.Ctx(),
		`INSERT INTO server_aliases (root_short_host_id, alias, short_host_id, ctime)
		 VALUES ($1, $2, $3, $4)`,
		m.G().ShortHostID().ExportToDB(),
		host.String(),
		m.ShortHostID().ExportToDB(),
		now,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return core.InsertError("server_aliases")
	}
	return nil
}

func NewCKS(ctx context.Context, gLocked *GlobalContext) (*CKS, error) {
	storage := CKSStorage{g: gLocked}
	mapper := hostmapper{g: gLocked}
	cfg, err := gLocked.cfg.CKSConfig(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := cfg.EncKeys()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, core.ConfigError("no CKS keys")
	}
	kr := cks.NewKeyring()
	err = kr.AddAll(keys)
	if err != nil {
		return nil, err
	}
	return &CKS{
		CKS: cks.NewCKS(kr, &storage, &mapper, time.Minute, gLocked.clock),
	}, nil
}

func (c *CKS) PutCert(
	m MetaContext,
	tx DbExecer,
	id cks.Index,
	dat *cks.X509Bundle,
) error {
	return c.CKS.PutCert(m.Ctx(), tx, id, dat)
}

func (c *CKS) GetCert(
	m MetaContext,
	tx Querier,
	id cks.Index,
) (*cks.CertSet, error) {
	return c.CKS.GetCert(m.Ctx(), tx, id)
}

func (c *CKS) GetCertByHostname(
	m MetaContext,
	tx Querier,
	host proto.Hostname,
	typ proto.CKSAssetType,
) (*cks.CertSet, error) {
	return c.CKS.GetCertByHostname(m.Ctx(), tx, host, typ)
}

type CertVaultCKS struct {
	cks *CKS
}

var _ CertManager = (*CertVaultCKS)(nil)

func NewCertVaultCKS(ctx context.Context, gLocked *GlobalContext) (*CertVaultCKS, error) {
	cks, err := NewCKS(ctx, gLocked)
	if err != nil {
		return nil, err
	}
	return &CertVaultCKS{cks: cks}, nil
}

func (c *CertVaultCKS) CKS() *CKS {
	return c.cks
}

func (c *CertVaultCKS) GenCA(
	m MetaContext,
	typ proto.CKSAssetType,
) error {
	cg, err := NewCertGenerator(proto.EntityType_HostTLSCA)
	if err != nil {
		return err
	}
	_, err = c.GenCAWithCertGenerator(m, typ, cg)
	if err != nil {
		return err
	}
	return nil
}

func (c *CertVaultCKS) PutCert(
	m MetaContext,
	tx pgx.Tx,
	idx cks.Index,
	dat *cks.X509Bundle,
) error {
	return c.cks.PutCert(m, tx, idx, dat)
}

func (c *CertVaultCKS) GenCAWithCertGenerator(
	m MetaContext,
	typ proto.CKSAssetType,
	cg *CertGenerator,
) (
	[]byte,
	error,
) {
	err := cg.GenCA(m)
	if err != nil {
		return nil, err
	}
	dat, err := cg.CKSData(true)
	if err != nil {
		return nil, err
	}
	idx := cks.Index{HostID: m.HostID(), Type: typ}
	err = RetryTxServerConfigDB(m, "GenCA", func(m MetaContext, tx pgx.Tx) error {
		return c.cks.PutCert(m, tx, idx, dat)
	})
	if err != nil {
		return nil, err
	}
	return cg.Cert(), nil
}

func (c *CertVaultCKS) PutExternallyGeneratedCert(
	m MetaContext,
	typ proto.CKSAssetType,
	aliases []proto.Hostname,
	data *cks.X509Bundle,
) error {
	idx := cks.Index{HostID: m.HostID(), Type: typ}
	return RetryTxServerConfigDB(m, "PutExternallyGeneratedCert", func(m MetaContext, tx pgx.Tx) error {
		err := c.cks.PutCert(m, tx, idx, data)
		if err != nil {
			return err
		}
		for _, host := range aliases {
			err = PutAlias(m, tx, host)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *CertVaultCKS) GenServerCert(
	m MetaContext,
	allHosts []proto.Hostname,
	aliases []proto.Hostname,
	caType proto.CKSAssetType,
	certType proto.CKSAssetType,
) error {
	cg, err := NewCertGenerator(proto.EntityType_X509Cert)
	if err != nil {
		return err
	}
	return RetryTxServerConfigDB(m, "GenServerCert", func(m MetaContext, tx pgx.Tx) error {
		ca, err := c.Primary(m, tx, caType)
		if err != nil {
			return err
		}
		err = cg.GenServerCert(m, ca, allHosts)
		if err != nil {
			return err
		}
		idx := cks.Index{HostID: m.HostID(), Type: certType}
		cdat, err := cg.CKSData(true)
		if err != nil {
			return err
		}
		err = c.cks.PutCert(m, tx, idx, cdat)
		if err != nil {
			return err
		}
		for _, host := range aliases {
			err = PutAlias(m, tx, host)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *CertVaultCKS) Primary(
	m MetaContext,
	tx Querier,
	typ proto.CKSAssetType,
) (*cks.X509Bundle, error) {
	set, err := c.cks.GetCert(m, tx, cks.Index{HostID: m.HostID(), Type: typ})
	if err != nil {
		return nil, err
	}
	if set.Primary == nil {
		return nil, core.KeyNotFoundError{Which: "primary x509 asset"}
	}
	return set.Primary, nil
}

func (c *CertVaultCKS) ServerCert(
	m MetaContext,
	tx Querier,
	hn proto.Hostname,
	typ proto.CKSAssetType,
) (*cks.X509Bundle, error) {
	var set *cks.CertSet
	var err error

	if !hn.IsZero() {
		set, err = c.cks.GetCertByHostname(m, tx, hn, typ)
	} else {
		set, err = c.cks.GetCert(m, tx, cks.Index{HostID: m.HostID(), Type: typ})
	}
	if err != nil {
		return nil, err
	}
	if set.Primary == nil {
		return nil, core.KeyNotFoundError{Which: "primary x509 asset for " + hn.String()}
	}
	return set.Primary, nil
}

func (c *CertVaultCKS) AddCertsToPool(
	m MetaContext,
	tx Querier,
	pool *x509.CertPool,
	typ []proto.CKSAssetType,
	host proto.Hostname,
) error {
	certs, err := c.AllCerts(m, tx, typ, host)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return nil

}

func (c *CertVaultCKS) AllCerts(
	m MetaContext,
	tx Querier,
	typ []proto.CKSAssetType,
	host proto.Hostname,
) (
	[]*x509.Certificate,
	error,
) {
	var ret []*x509.Certificate
	for _, t := range typ {
		set, err := c.cks.GetCertByHostname(m, tx, host, t)
		if err != nil {
			return nil, err
		}
		for _, cert := range set.Certs {
			c, err := cert.BuildCert()
			if err != nil {
				return nil, err
			}
			ret = append(ret, c.Leaf)
		}
	}
	return ret, nil
}

func (c *CertVaultCKS) PoolForBaseHost(
	m MetaContext,
	tx Querier,
	typs []proto.CKSAssetType,
) (
	*x509.CertPool,
	error,
) {
	ret := x509.NewCertPool()
	var zhn proto.Hostname
	err := c.AddCertsToPool(m, tx, ret, typs, zhn)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (c *CertVaultCKS) Pool(
	m MetaContext,
	tx Querier,
	typ proto.CKSAssetType,
	host proto.Hostname,
) (
	*x509.CertPool,
	error,
) {
	var set *cks.CertSet
	var err error

	if typ.IsFrontendCA() && !host.IsZero() {
		set, err = c.cks.GetCertByHostname(m, tx, host, typ)
	} else {
		set, err = c.cks.GetCert(m, tx, cks.Index{HostID: m.HostID(), Type: typ})
	}

	if err != nil {
		return nil, err
	}
	pool, err := set.BuildPool()
	if err != nil {
		return nil, err
	}
	return pool, nil
}

func (c *CertVaultCKS) MakeGetConfigForClient(
	m MetaContext,
	cfg *tls.Config,
	styp proto.ServerType,
) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	m = m.Background()
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		hn := proto.Hostname(hello.ServerName)

		ret := cfg.Clone()

		ccat := styp.ClientCAType()
		if ccat == proto.CKSAssetType_InternalClientCA ||
			ccat == proto.CKSAssetType_ExternalClientCA {
			pool, err := c.Pool(m, nil, ccat, hn)
			if err != nil {
				return nil, err
			}
			ret.ClientAuth = tls.RequireAndVerifyClientCert
			ret.ClientCAs = pool
		}

		sct := styp.ServerCertType()

		var dat *cks.X509Bundle
		var err error

		switch sct {
		case proto.CKSAssetType_HostchainFrontendX509Cert,
			proto.CKSAssetType_RootPKIFrontendX509Cert:
			dat, err = c.ServerCert(m, nil, hn, sct)
		case proto.CKSAssetType_BackendX509Cert,
			proto.CKSAssetType_RootPKIBeaconX509Cert:
			dat, err = c.Primary(m, nil, sct)
		default:
		}

		if err != nil {
			return nil, err
		}
		if dat == nil {
			return nil, core.InternalError(
				fmt.Sprintf("unsupported server cert type %s %s",
					sct.String(),
					styp.String(),
				),
			)
		}
		cert, err := dat.BuildCert()
		if err != nil {
			return nil, err
		}
		ret.GetCertificate = nil
		ret.Certificates = []tls.Certificate{*cert}
		return ret, nil
	}
}

// StoreToCertMgr stores the cert to the DB-backed cert manager, encrypting the private key
// as necessary. It uses the cert.PrivateKey cert.Certificate, and cert.Leaf fields of the
// tls.Certificate struct but ignore the rest. The cert.Certificate field should contain a
// cert chain from the Root CAs, including the leaf cert. This function does not check
// the correspondence between the given hostname from the Cert, and that implied by
// the given HostID.
func StoreCertToCertMgr(
	m MetaContext,
	hostId proto.HostID,
	typ proto.CKSAssetType,
	cert *tls.Certificate,
) error {
	rawkey, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	pubber, ok := cert.PrivateKey.(interface{ Public() crypto.PublicKey })
	if !ok {
		return core.AutocertFailedError{Err: errors.New("bad private key")}
	}
	pub := pubber.Public()
	keyid, err := core.ComputePKIXCertID(pub)
	if err != nil {
		return err
	}

	data := &cks.X509Bundle{
		Key:     proto.NewCKSCertKeyWithX509(rawkey),
		Cert:    proto.CKSCertChain{Certs: cert.Certificate},
		Primary: true,
		Etime:   cert.Leaf.NotAfter,
		KeyID:   keyid.EntityID(),
	}

	coreHostID, err := m.G().HostIDMap().LookupByHostID(m, hostId)
	if err != nil {
		return err
	}

	m = m.WithHostID(coreHostID)

	err = m.G().CertMgr().PutExternallyGeneratedCert(
		m,
		typ,
		nil,
		data,
	)
	if err != nil {
		return err
	}
	return nil
}

func storeAutocert(
	m MetaContext,
	pkg AutocertPackage,
	cert *tls.Certificate,
) error {
	return StoreCertToCertMgr(m, pkg.HostID, pkg.ServerType.ServerCertType(), cert)
}
