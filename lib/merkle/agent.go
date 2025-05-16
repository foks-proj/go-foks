// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package merkle

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type AgentLocalStorage interface {
	GetRootHashFromCache(ctx context.Context, ep proto.MerkleEpno) (*proto.MerkleRootHash, error)
	GetRootFromCache(ctx context.Context, ep proto.MerkleEpno) (*proto.MerkleRoot, error)
	GetLatestRootFromCache(ctx context.Context) (*proto.MerkleRoot, error)
	Store(ctx context.Context, ep proto.MerkleEpno, h *proto.MerkleRootHash, r *proto.MerkleRoot, latest bool) error
}

type Agent struct {
	AgentLocalStorage
	wcw    core.WithContextWarner
	gcli   *core.RpcClient
	hostID proto.HostID
}

func NewAgent(
	wcw core.WithContextWarner,
	s AgentLocalStorage,
	gcli *core.RpcClient,
	hostID proto.HostID,
) *Agent {
	return &Agent{
		AgentLocalStorage: s,
		wcw:               wcw,
		gcli:              gcli,
		hostID:            hostID,
	}
}

func (a Agent) cli() rem.MerkleQueryClient {
	return rem.MerkleQueryClient{
		Cli:            a.gcli,
		ErrorUnwrapper: rem.MerkleQueryErrorUnwrapper(core.StatusToError),
		MakeArgHeader:  core.MakeProtoHeader,
		CheckResHeader: core.MakeCheckProtoResHeader(a.wcw),
	}
}

func (a *Agent) GetRootsFromServer(ctx context.Context, roots []proto.MerkleEpno, hashes []proto.MerkleEpno) ([]proto.MerkleRoot, []proto.MerkleRootHash, error) {
	arg := rem.GetHistoricalRootsArg{
		HostID: &a.hostID,
		Full:   roots,
		Hashes: hashes,
	}
	res, err := a.cli().GetHistoricalRoots(ctx, arg)
	if err != nil {
		return nil, nil, err
	}
	return res.Roots, res.Hashes, nil
}

func (a *Agent) GetLatestRootAndValidate(ctx context.Context) (*proto.MerkleRoot, error) {
	root, err := a.cli().GetCurrentRoot(ctx, &a.hostID)
	if err != nil {
		return nil, err
	}
	return a.GotLatestRoot(ctx, &root)
}

func (a *Agent) GetLatestRootFromServer(ctx context.Context) (proto.MerkleRoot, error) {
	return a.cli().GetCurrentRoot(ctx, &a.hostID)
}

func (a *Agent) GetLatestTreeRootFromServer(ctx context.Context) (proto.TreeRoot, error) {
	var ret proto.TreeRoot
	root, err := a.GetLatestRootAndValidate(ctx)
	if err != nil {
		return ret, err
	}
	err = HashRoot(root, &ret.Hash)
	if err != nil {
		return ret, err
	}
	t, err := root.GetV()
	if err != nil {
		return ret, err
	}
	if t != proto.MerkleRootVersion_V1 {
		return ret, core.VersionNotSupportedError("merkle root version")
	}
	ret.Epno = root.V1().Epno
	return ret, nil
}

func (a *Agent) GotLatestRoot(ctx context.Context, root *proto.MerkleRoot) (*proto.MerkleRoot, error) {
	err := CheckAndStoreLatestRoot(ctx, a, root)
	if err != nil {
		return nil, err
	}
	return root, nil
}

func (a *Agent) Lookup(ctx context.Context, arg rem.MerkleLookupArg) (proto.MerklePathCompressed, error) {
	return a.cli().Lookup(ctx, arg)
}

func (a *Agent) HostID() proto.HostID {
	return a.hostID
}

func (a *Agent) Shutdown() {}

func (a *Agent) Reset() {
	a.gcli.Reset()
}

var _ ClientInterface = (*Agent)(nil)
