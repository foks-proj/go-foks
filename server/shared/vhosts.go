// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type vHostInit struct {
	vhostId       *proto.VHostID
	hn            proto.Hostname
	ufsMap        map[proto.ServerType]proto.Hostname
	hk            *HostKey
	parent        *HostChain
	hc            *HostChain
	beacon        *GlobalService
	merklePoke    func() error              // merkle pipeline hook
	makeProbeCert func(m MetaContext) error // make a probe cert works in test; in prod, we need to ask let's encrypt
	skipBeacon    bool
	config        proto.HostConfig
}

func (v *vHostInit) genHostKey(m MetaContext) error {
	parent := v.parent
	if parent == nil {
		parent = m.G().HostChain()
	}
	hc := NewHostChain().
		WithConfig(v.config).
		WithParentVanity(parent, v.hn)
	if v.vhostId != nil {
		hc = hc.WithVHostID(*v.vhostId)
	}
	err := hc.Forge(m, "")
	if err != nil {
		return err
	}
	v.hc = hc
	v.hk = hc.Key(proto.EntityType_Host)

	return nil
}

func (v *vHostInit) initMerkleTree(m MetaContext) error {
	s := NewSQLStorage(m)
	err := merkle.InitTree(m, s)
	if err != nil {
		return err
	}
	return nil
}

func (v *vHostInit) writePublicZone(m MetaContext) error {
	k := v.hc.MetadataSigner()
	if k == nil {
		return core.InternalError("no metadata signer key")
	}
	ufsMap := v.ufsMap
	if ufsMap == nil {
		ufsMap = make(map[proto.ServerType]proto.Hostname)
	}
	if !v.hn.IsZero() {
		ufsMap[proto.ServerType_Probe] = v.hn
	}
	return StorePublicZoneWithProbe(m, *k, ufsMap)
}

func (v *vHostInit) checkLimits(m MetaContext) error {
	db, err := m.Db(DbTypeUsers)
	if err != nil {
		return err
	}
	defer db.Release()
	err = CheckSeatLimits(m, db)
	if err != nil {
		return err
	}
	return nil
}

func (v *vHostInit) makeVHostID(m MetaContext) error {
	if v.vhostId != nil {
		return nil
	}
	tmp, err := proto.RandomID16er[proto.VHostID]()
	if err != nil {
		return err
	}
	v.vhostId = tmp
	return nil
}

func (v *vHostInit) initX509(m MetaContext) error {
	ca := m.G().CertMgr()
	err := ca.GenCA(m, proto.CKSAssetType_ExternalClientCA)
	if err != nil {
		return err
	}
	names := make(map[proto.Hostname]struct{})
	for _, hn := range v.ufsMap {
		hn = hn.Normalize()
		names[hn] = struct{}{}
	}
	var aliases []proto.Hostname
	primary := v.hn.Normalize()
	for hn := range names {
		if hn != primary {
			aliases = append(aliases, hn)
		}
	}
	names[primary] = struct{}{}
	var allNames []proto.Hostname
	for hn := range names {
		allNames = append(allNames, hn)
	}
	err = ca.GenServerCert(
		m,
		allNames,
		aliases,
		proto.CKSAssetType_HostchainFrontendCA,
		proto.CKSAssetType_HostchainFrontendX509Cert,
	)
	if err != nil {
		return err
	}

	// this behavior varies based on prod vs test
	if v.makeProbeCert != nil {
		err = v.makeProbeCert(m)
		if err != nil {
			return err
		}
	}

	return nil
}

func (v *vHostInit) run(m MetaContext) error {
	err := v.checkLimits(m)
	if err != nil {
		return err
	}
	err = v.makeVHostID(m)
	if err != nil {
		return err
	}
	err = v.genHostKey(m)
	if err != nil {
		return err
	}

	m = m.WithHostID(v.hc.HostIDp())

	err = v.initX509(m)
	if err != nil {
		return err
	}

	err = v.initMerkleTree(m)
	if err != nil {
		return err
	}

	err = GenerateNewChallengeHMACKeys(m)
	if err != nil {
		return err
	}

	err = v.writePublicZone(m)
	if err != nil {
		return err
	}

	err = v.merklePoke()
	if err != nil {
		return err
	}

	err = v.doBeacon(m)
	if err != nil {
		return err
	}
	return nil
}

func (v *vHostInit) doBeacon(m MetaContext) error {

	if v.skipBeacon {
		return nil
	}
	err := BeaconRegisterCli(m, v.hn, v.beacon)
	if err != nil {
		return err
	}
	return nil
}

type VHostInitOpts struct {
	Beacon        *GlobalService
	Config        proto.HostConfig
	MerklePoke    func() error
	MakeProbeCert func(m MetaContext) error
	Icr           proto.InviteCodeRegime // invite code regime, if any
}

func VHostInit(
	m MetaContext,
	hn proto.Hostname,
	opts VHostInitOpts,
) (
	*core.HostID,
	error,
) {

	ufsMap := make(map[proto.ServerType]proto.Hostname)
	for _, st := range proto.FrontFacingServers {
		ufsMap[st] = hn
	}

	i := &vHostInit{
		hn:            hn,
		beacon:        opts.Beacon,
		merklePoke:    opts.MerklePoke,
		makeProbeCert: opts.MakeProbeCert,
		config:        opts.Config,
		ufsMap:        ufsMap,
	}
	err := i.run(m)
	if err != nil {
		return nil, err
	}
	return i.hc.HostIDp(), nil
}

func VHostInitChildChainWithInviteCode(
	m MetaContext,
	v proto.Hostname,
	inviteCode rem.MultiUseInviteCode,
	caCert core.KeyCertFilePair,
	config proto.HostConfig,
) (
	*core.HostID,
	error,
) {
	beacon, err := m.G().Config().BeaconGlobalService(m.Ctx())
	if err != nil {
		return nil, err
	}

	hostID, err := VHostInit(m, v,
		VHostInitOpts{
			Beacon:     beacon,
			MerklePoke: func() error { return PokeMerklePipeline(m) },
			Config:     config,
		},
	)
	if err != nil {
		return nil, err
	}
	m = m.WithHostID(hostID)
	if len(inviteCode) > 0 {
		err = InsertMultiuseInviteCode(m, inviteCode)
		if err != nil {
			return nil, err
		}
	}

	return hostID, nil
}

// VHostSetUserViewership sets the viewership mode for the active host in MetaContext.
// Should only be called by VHost admins. Permissions are checked in the caller.
func VHostSetUserViewership(
	m MetaContext,
	v proto.ViewershipMode,
) error {
	return vhostSetViewership(m, v, "user")
}

func vhostSetViewership(
	m MetaContext,
	v proto.ViewershipMode,
	which string,
) error {
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()

	q := `UPDATE host_config
	      SET ` + which + `_viewing=$1
		  WHERE short_host_id=$2`
	_, err = db.Exec(m.Ctx(), q,
		v.String(),
		m.ShortHostID().ExportToDB(),
	)
	if err != nil {
		return err
	}
	m.G().HostIDMap().ClearConfig(m, m.ShortHostID())

	return nil
}
