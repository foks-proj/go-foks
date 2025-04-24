// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"time"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func IssueCertChain(m MetaContext, uhc UserHostContext, key core.DevicePublicKeyer) ([][]byte, error) {
	checker := func(m MetaContext, db *pgxpool.Conn, uhc UserHostContext, key core.DevicePublicKeyer) error {
		_, err := checkClientKeyValidExternal(m, db, uhc, key)
		return err
	}
	return issueCertChain(m, uhc, key, proto.CKSAssetType_ExternalClientCA, checker)
}

func IssueCertChainInternal(m MetaContext, uhc UserHostContext, key core.DevicePublicKeyer) ([][]byte, error) {
	return issueCertChain(m, uhc, key, proto.CKSAssetType_InternalClientCA, checkClientKeyValidInternal)
}

func checkSubkeyValidForCert(m MetaContext, db *pgxpool.Conn, uhc UserHostContext, key core.DevicePublicKeyer) (*proto.Role, error) {
	if key.Type() != proto.EntityType_Subkey {
		return nil, core.AuthError{}
	}
	var rt, lev int
	err := db.QueryRow(m.Ctx(),
		`SELECT D.role_type, D.viz_level FROM subkeys AS S
		 JOIN device_keys AS D
		 ON (S.parent=D.verify_key AND s.short_host_id=D.short_host_id)
		 WHERE S.verify_key=$1 AND S.short_host_id=$2
		 AND D.uid=$3 AND D.key_state='valid' AND S.key_state='valid'`,
		key.ExportToDB(),
		int(uhc.HostID.Short),
		uhc.Uid.ExportToDB(),
	).Scan(&rt, &lev)
	if err == pgx.ErrNoRows {
		return nil, core.AuthError{}
	}
	if err != nil {
		m.Errorw("checkSubkeyValidForCert", "err", err)
		return nil, core.AuthError{}
	}
	role, err := proto.ImportRoleFromDB(rt, lev)
	if err != nil {
		return nil, err
	}
	return role, nil
}

func checkClientKeyValidExternal(m MetaContext, configDb *pgxpool.Conn, uhc UserHostContext, key core.DevicePublicKeyer) (*proto.Role, error) {

	if uhc.HostID == nil {
		m.Errorw("checkClientKeyValidExternalWithUserDB", "err", "uhc.HostID == nil")
		return nil, core.AuthError{}
	}

	userDb, err := m.G().Db(m.Ctx(), DbTypeUsers)
	if err != nil {
		return nil, err
	}
	defer userDb.Release()

	if key.Type() == proto.EntityType_Subkey {
		return checkSubkeyValidForCert(m, userDb, uhc, key)
	}

	var rt, lev int

	err = userDb.QueryRow(m.Ctx(),
		`SELECT role_type, viz_level FROM device_keys 
		WHERE short_host_id=$1 AND verify_key=$2 AND uid=$3 AND key_state='valid'`,
		int(uhc.HostID.Short),
		key.ExportToDB(),
		uhc.Uid.ExportToDB(),
	).Scan(&rt, &lev)

	if err == pgx.ErrNoRows {
		m.Errorw("checkClientKeyValidExternalWithUserDB", "err", "no key found")
		return nil, core.AuthError{}
	}

	if err != nil {
		m.Errorw("checkClientKeyValidExternalWithUserDB", "err", err)
		return nil, core.AuthError{}
	}
	role, err := proto.ImportRoleFromDB(rt, lev)
	if err != nil {
		m.Errorw("checkClientKeyValidExternalWithUserDB", "err", err)
		return nil, core.AuthError{}
	}

	return role, nil
}

func checkClientKeyValidInternal(m MetaContext, db *pgxpool.Conn, uhc UserHostContext, key core.DevicePublicKeyer) error {
	var i int
	err := db.QueryRow(m.Ctx(),
		`SELECT 1 FROM service_keys
		 WHERE service_id=$1 AND key_id=$2 AND key_state='valid'`,
		uhc.Uid.ExportToDB(),
		key.ExportToDB(),
	).Scan(&i)

	if err != nil || i != 1 {
		m.Errorw("checkClientKeyValidateInternal", "err", err)
		return core.AuthError{}
	}
	return nil
}

func issueCertChain(
	m MetaContext,
	uhc UserHostContext,
	key core.DevicePublicKeyer,
	typ proto.CKSAssetType,
	chk func(m MetaContext, db *pgxpool.Conn, uhc UserHostContext, key core.DevicePublicKeyer) error,
) ([][]byte, error) {

	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()

	if uhc.HostID == nil {
		m.Errorw("issueCertChain", "err", "uhc.HostID == nil")
		return nil, core.InternalError("uhc.HostID is nil in issueCertChain")
	}
	if uhc.HostID.Short == 0 {
		m.Errorw("issueCertChain", "err", "uhc.HostID.Short == 0")
		return nil, core.InternalError("uhc.HostID.Short is 0 in issueCertChain")
	}

	err = chk(m, db, uhc, key)
	if err != nil {
		return nil, err
	}
	ca, err := m.G().CertMgr().Primary(m, db, typ)
	if err != nil {
		return nil, err
	}

	serialNumber, err := core.RandomSerialNumber()
	if err != nil {
		return nil, err
	}

	skid := proto.SubjectKeyID{
		Fqu: proto.FQUser{
			Uid:    uhc.Uid,
			HostID: uhc.HostID.Id,
		},
		KeyType: key.Type(),
	}
	subjectKeyId, err := core.EncodeToBytes(&skid)
	if err != nil {
		return nil, err
	}

	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber:   serialNumber,
		Subject:        pkix.Name{},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(10, 0, 0),
		SubjectKeyId:   subjectKeyId,
		AuthorityKeyId: ca.KeyID.Bytes(),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}

	pk, err := key.ExportToPublicKey()
	if err != nil {
		return nil, err
	}

	caCert, err := ca.BuildCert()
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert.Leaf, pk, caCert.PrivateKey)
	if err != nil {
		m.Errorw("IssueCert", "err", err, "stage", "CreateCertificate")
		return nil, err
	}
	return [][]byte{certBytes}, nil
}

func CheckKeyValid(m MetaContext, uhc UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return checkClientKeyValidExternal(m, nil, uhc, key)
}

func CheckKeyValidGuest(m MetaContext, uhc UserHostContext, key proto.EntityID) (*proto.Role, error) {

	// As a guest, can only claim to be the guest/ffff UID, which won't have nay
	// rows in the DB
	if !uhc.Uid.IsGuest() {
		return nil, core.AuthError{}
	}
	return nil, nil
}

func CheckKeyValidInternal(m MetaContext, uhc UserHostContext, key core.DevicePublicKeyer) error {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	return checkClientKeyValidInternal(m, db, uhc, key)
}
