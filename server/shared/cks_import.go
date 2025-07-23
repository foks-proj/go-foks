package shared

import (
	"crypto/tls"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type CKSCertImporter struct {
	typ  proto.CKSAssetType
	phn  *proto.ParsedHostname
	cp   *CertPackage
	chid *core.HostID
}

func NewCKSCertImporter() *CKSCertImporter {
	return &CKSCertImporter{}
}

func (c *CKSCertImporter) Configure(
	key core.Path,
	cert core.Path,
	typ proto.CKSAssetType,
	host string,
) error {
	c.typ = typ

	cp, err := ReadCertPackageFromFiles(core.KeyCertFilePair{
		Key:  key,
		Cert: cert,
	})
	c.cp = cp
	if err != nil {
		return err
	}
	if len(c.cp.Certs) == 0 {
		return core.X509Error("no certs in the cert chain")
	}
	if len(host) != 0 {
		phn, err := proto.HostString(host).Parse()
		if err != nil {
			return core.BadArgsError(fmt.Sprintf("invalid host: %s", host))
		}
		c.phn = phn
	}
	return nil
}

func (c *CKSCertImporter) checkHostname(m MetaContext) error {
	mapper := m.G().HostIDMap()

	if c.phn != nil {
		isName, err := c.phn.GetS()
		if err != nil {
			return err
		}
		if isName {
			hn := c.phn.True().Hostname()
			hid, err := mapper.LookupByHostname(m, hn)
			if err != nil {
				return err
			}
			c.chid = hid
		} else {
			hid := c.phn.False()
			chid, err := mapper.LookupByHostID(m, hid)
			if err != nil {
				return err
			}
			c.chid = chid
		}
	} else {
		tmp := m.HostID()
		c.chid = &tmp
	}

	hn, err := mapper.Hostname(m, c.chid.Short)
	if err != nil {
		return err
	}
	var found bool
	for _, n := range c.cp.Certs[0].DNSNames {
		if proto.Hostname(n).NormEq(hn) {
			found = true
			break
		}
	}
	if !found {
		return core.X509Error(fmt.Sprintf("certificate does not match host: %s", hn))
	}
	return nil
}

func (c *CKSCertImporter) runImport(m MetaContext) error {

	cert := tls.Certificate{
		PrivateKey:  c.cp.Priv,
		Leaf:        c.cp.Certs[0],
		Certificate: c.cp.CertRaw,
	}

	err := StoreCertToCertMgr(m, c.chid.Id, c.typ, &cert)
	if err != nil {
		return err
	}
	return nil
}

func (c *CKSCertImporter) Run(m MetaContext) error {
	err := c.checkHostname(m)
	if err != nil {
		return err
	}
	err = c.runImport(m)
	if err != nil {
		return err
	}
	return nil
}
