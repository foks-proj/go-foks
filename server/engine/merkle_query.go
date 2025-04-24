// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

type MerkleQueryServer struct {
	shared.BaseRPCServer
	eng *merkle.Engine
}

func (b *MerkleQueryServer) NewClientConn(xp rpc.Transporter, uhc shared.UserHostContext) shared.ClientConn {
	return &MerkleQueryClientConn{
		srv:            b,
		xp:             xp,
		BaseClientConn: shared.NewBaseClientConn(b.G(), uhc),
	}
}

func (s *MerkleQueryServer) ToRPCServer() shared.RPCServer { return s }
func (s *MerkleQueryServer) ServerType() proto.ServerType {
	return proto.ServerType_MerkleQuery
}

func (s *MerkleQueryServer) RequireAuth() shared.AuthType { return shared.AuthTypeNone }
func (s *MerkleQueryServer) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return shared.CheckKeyValidGuest(m, uhc, key)
}

func (s *MerkleQueryServer) Setup(m shared.MetaContext) error {
	stor := shared.NewSQLStorage(m)
	s.eng = merkle.NewEngine(stor)
	return nil
}

type MerkleQueryClientConn struct {
	shared.BaseClientConn
	srv *MerkleQueryServer
	xp  rpc.Transporter
}

func (c *MerkleQueryClientConn) RegisterProtocols(m shared.MetaContext, srv *rpc.Server) error {
	return srv.RegisterV2(rem.MerkleQueryProtocol(c))
}

func (c *MerkleQueryClientConn) ErrorWrapper() func(error) proto.Status {
	return core.ErrorToStatus
}

func (c *MerkleQueryClientConn) Lookup(ctx context.Context, arg rem.MerkleLookupArg) (proto.MerklePathCompressed, error) {
	var ret proto.MerklePathCompressed
	m, err := shared.NewMetaContextFromArg(ctx, c, arg.HostID)
	if err != nil {
		return ret, err
	}
	path, err := c.srv.eng.LookupPath(m, arg)
	if err != nil {
		return ret, err
	}
	err = path.Compress(&ret)
	if err != nil {
		return ret, err
	}
	return ret, err
}

// Used mainly for testing
func (c *MerkleQueryClientConn) Reset(ctx context.Context) error {
	c.xp.Close()
	return nil
}

func (c *MerkleQueryClientConn) MLookup(ctx context.Context, arg rem.MerkleMLookupArg) (proto.MerklePathsCompressed, error) {
	var ret proto.MerklePathsCompressed
	m, err := shared.NewMetaContextFromArg(ctx, c, arg.HostID)
	if err != nil {
		return ret, err
	}
	path, err := c.srv.eng.LookupPaths(m, arg)
	if err != nil {
		return ret, err
	}
	err = path.Compress(&ret)
	if err != nil {
		return ret, err
	}
	return ret, nil
}

func (c *MerkleQueryClientConn) CheckKeyExists(ctx context.Context, arg rem.CheckKeyExistsArg) (rem.MerkleExistsRes, error) {
	var ret rem.MerkleExistsRes
	m, err := shared.NewMetaContextFromArg(ctx, c, arg.HostID)
	if err != nil {
		return ret, err
	}
	return c.srv.eng.CheckKeyExists(m, arg.Key)
}

func (c *MerkleQueryClientConn) GetHistoricalRoots(ctx context.Context, arg rem.GetHistoricalRootsArg) (rem.GetHistoricalRootsRes, error) {
	var ret rem.GetHistoricalRootsRes
	m, err := shared.NewMetaContextFromArg(ctx, c, arg.HostID)
	if err != nil {
		return ret, err
	}
	ret.Roots, ret.Hashes, err = c.srv.eng.GetHistoricalRoots(m, arg.Full, arg.Hashes)
	return ret, err
}

func (c *MerkleQueryClientConn) GetCurrentRoot(ctx context.Context, hid *proto.HostID) (proto.MerkleRoot, error) {
	var ret proto.MerkleRoot
	m, err := shared.NewMetaContextFromArg(ctx, c, hid)
	if err != nil {
		return ret, err
	}
	return c.srv.eng.GetCurrentRoot(m)
}

func (c *MerkleQueryClientConn) GetCurrentRootHash(ctx context.Context, hid *proto.HostID) (proto.TreeRoot, error) {
	var ret proto.TreeRoot
	m, err := shared.NewMetaContextFromArg(ctx, c, hid)
	if err != nil {
		return ret, err
	}
	tmp, err := c.srv.eng.GetCurrentRootHash(m)
	if err != nil {
		return ret, nil
	}
	if tmp != nil {
		ret = *tmp
	}
	return ret, err
}

func (c *MerkleQueryClientConn) GetCurrentRootSigned(ctx context.Context, hid *proto.HostID) (proto.SignedMerkleRoot, error) {
	var ret proto.SignedMerkleRoot
	m, err := shared.NewMetaContextFromArg(ctx, c, hid)
	if err != nil {
		return ret, err
	}
	return c.srv.eng.GetCurrentSignedRoot(m)
}

func (c *MerkleQueryClientConn) GetCurrentRootSignedEpno(ctx context.Context, hid *proto.HostID) (proto.MerkleEpno, error) {
	var ret proto.MerkleEpno
	m, err := shared.NewMetaContextFromArg(ctx, c, hid)
	if err != nil {
		return ret, err
	}
	return c.srv.eng.GetCurrentSignedRootEpno(m)
}

func (c *MerkleQueryClientConn) ConfirmRoot(ctx context.Context, arg rem.ConfirmRootArg) error {
	m, err := shared.NewMetaContextFromArg(ctx, c, &arg.HostID)
	if err != nil {
		return err
	}
	return c.srv.eng.ConfirmRoot(m, arg.Root)

}

func (c *MerkleQueryClientConn) Probe(ctx context.Context, arg rem.ProbeArg) (rem.ProbeRes, error) {
	m := shared.NewMetaContextConn(ctx, c)
	return shared.LoadProbe(m, arg)
}

func (m *MerkleQueryClientConn) SelectVHost(ctx context.Context, hid proto.HostID) error {
	return shared.SelectVHost(ctx, m, hid)
}

var _ shared.ClientConn = (*MerkleQueryClientConn)(nil)
var _ shared.RPCServer = (*MerkleQueryServer)(nil)
var _ rem.MerkleQueryInterface = (*MerkleQueryClientConn)(nil)
var _ rem.ProbeInterface = (*MerkleQueryClientConn)(nil)
