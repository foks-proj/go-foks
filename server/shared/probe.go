// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

func (g *GlobalContext) PublicZone(
	ctx context.Context,
	hostnameMap map[proto.ServerType]proto.Hostname, // UFS = "Using-Facing Server"
) (
	proto.PublicZone,
	error,
) {
	var ret proto.PublicZone

	makeExtAddr := func(typ proto.ServerType) (*proto.TCPAddr, error) {
		_, ext, _, err := g.ListenParams(ctx, typ)
		if err != nil {
			return nil, err
		}
		if hostnameMap == nil {
			return &ext, nil
		}
		rewriteHostname, ok := hostnameMap[typ]
		if !ok || rewriteHostname.IsZero() {
			return &ext, nil
		}
		ext, err = ext.WithHostname(rewriteHostname)
		if err != nil {
			return nil, err
		}
		return &ext, nil
	}

	for _, srv := range []struct {
		typ  proto.ServerType
		slot *proto.TCPAddr
	}{
		{proto.ServerType_Probe, &ret.Services.Probe},
		{proto.ServerType_Reg, &ret.Services.Reg},
		{proto.ServerType_User, &ret.Services.User},
		{proto.ServerType_MerkleQuery, &ret.Services.MerkleQuery},
		{proto.ServerType_KVStore, &ret.Services.KvStore},
		{proto.ServerType_RealTime, &ret.Services.Realtime},
	} {
		ext, err := makeExtAddr(srv.typ)
		if err != nil {
			return ret, err
		}
		*srv.slot = *ext
	}
	ret.Ttl = proto.DurationSecs(60)
	return ret, nil
}

func StorePublicZone(m MetaContext, hk HostKey) error {
	return StorePublicZoneWithProbe(m, hk, nil)
}

func StorePublicZoneWithProbe(
	m MetaContext,
	hk HostKey,
	hostmap map[proto.ServerType]proto.Hostname,
) error {
	z, err := m.G().PublicZone(m.Ctx(), hostmap)
	if err != nil {
		return err
	}
	m.Infow("StorePublicZoneWithProbe", "publicZone", z)
	sig, blob, err := core.Sign2(&hk, &z)
	if err != nil {
		return err
	}
	spz := proto.SignedPublicZone{
		Inner: *blob,
		Sig:   *sig,
	}
	return m.PutKV(&spz, KVKeyPublicZone)
}

func LoadPublicZone(m MetaContext) (proto.SignedPublicZone, error) {
	var ret proto.SignedPublicZone
	err := m.GetKV(&ret, KVKeyPublicZone)
	return ret, err
}

func resolveVHostForProbe(m MetaContext, arg rem.ProbeArg) (MetaContext, error) {
	var hid, hid2 *core.HostID
	var isIP bool
	if !arg.Hostname.IsZero() {
		var err error
		hid, err = m.GetVHost(arg.Hostname)
		if err != nil {
			return m, err
		}
		isIP = arg.Hostname.IsIPAddr()
	}

	if arg.HostID != nil {
		var err error
		hid2, err = m.GetHostID(*arg.HostID)
		if err != nil {
			return m, err
		}
	}

	switch {
	case hid == nil && hid2 != nil:
		hid = hid2
	case hid != nil && hid2 != nil && isIP:
		hid = hid2
	case hid != nil && hid2 != nil && !isIP:
		if !hid.Eq(hid2) {
			return m, core.HostMismatchError{Which: "hostID"}
		}
	}
	if hid != nil {
		m = m.WithHostID(hid)
	}
	return m, nil
}

func LoadProbe(m MetaContext, arg rem.ProbeArg) (rem.ProbeRes, error) {
	var ret rem.ProbeRes

	// Probe might be for a virtual host, distinguished from the primary
	// host on the basis of the DNS hostname.
	m, err := resolveVHostForProbe(m, arg)
	if err != nil {
		return ret, err
	}

	mcli, err := m.MerkleCli()
	if err != nil {
		return ret, err
	}

	func() {
		m := m.WithLogTag("call")
		m.Infow("LoadProbe", "call", "GetCurrentRootSigned")
		ret.MerkleRoot, err = mcli.GetCurrentRootSigned(m.Ctx(), m.HostID().IDp())
		m.Infow("LoadProbe", "reply", "GetCurrentRootSigned", "err", err)
	}()

	if err != nil {
		return ret, err
	}
	ret.Zone, err = LoadPublicZone(m)
	if err != nil {
		return ret, err
	}
	ret.Hostchain, err = LoadHostchain(m, arg.HostchainLastSeqno, ret.MerkleRoot)
	if err != nil {
		return ret, err
	}

	return ret, nil
}
