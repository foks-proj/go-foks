// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/merkle"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

type MerklePipelineSubclass interface {
	initBackgroundLoop(m shared.MetaContext) error
	pollReadyHosts(m shared.MetaContext) ([]core.ShortHostID, error)
	doOnePollForHost(m shared.MetaContext) error
}

type MerklePipelineBaseServer struct {
	shared.BaseRPCServer
	cfg    shared.MerkleBuilderServerConfigger
	pokeCh chan chan<- error
	lock   *shared.Lock
	sub    MerklePipelineSubclass

	// Can be either batcher or builder or Signer
	serverType proto.ServerType

	// merkle storage engine that abstracts away the SQL, in most cases...
	stor *shared.SQLStorage
	eng  *merkle.Engine
}

func (s *MerklePipelineBaseServer) RequireAuth() shared.AuthType { return shared.AuthTypeInternal }
func (s *MerklePipelineBaseServer) CheckDeviceKey(m shared.MetaContext, uhc shared.UserHostContext, key proto.EntityID) (*proto.Role, error) {
	return nil, shared.CheckKeyValidInternal(m, uhc, key)
}

func (b *MerklePipelineBaseServer) Setup(m shared.MetaContext) error {
	var err error
	b.cfg, err = m.G().Config().MerkleBuilderServerConfig(m.Ctx())
	if err != nil {
		return err
	}
	b.pokeCh = make(chan chan<- error)
	b.lock, err = shared.NewLock(b.GetHostID().Short, b.serverType)
	if err != nil {
		return err
	}
	b.stor = shared.NewSQLStorage(m)
	b.eng = merkle.NewEngine(b.stor)
	return nil
}

func (s *MerklePipelineBaseServer) ServerType() proto.ServerType {
	return s.serverType
}

func (s *MerklePipelineBaseServer) InitLoop(m shared.MetaContext) error {
	return s.sub.initBackgroundLoop(m)
}
func (s *MerklePipelineBaseServer) GetName() string                         { return "MerklePipelineBaseServer" }
func (s *MerklePipelineBaseServer) GetLock() *shared.Lock                   { return s.lock }
func (s *MerklePipelineBaseServer) GetConfig() shared.ServerLooperConfigger { return s.cfg }
func (s *MerklePipelineBaseServer) GetPokeCh() chan chan<- error            { return s.pokeCh }

var _ shared.Looper = (*MerklePipelineBaseServer)(nil)

func (s *MerklePipelineBaseServer) RunBackgroundLoops(m shared.MetaContext, shutdownCh chan<- error) error {
	return s.RunBackgroundLoopsWithLooper(m, shutdownCh, s)
}

var batchPrefix = "/merkle/batch"
var BatchStateKey = batchPrefix + "/state"

func (s *MerklePipelineBaseServer) readBatchState(
	m shared.MetaContext,
	tx pgx.Tx,
) (
	*proto.MerkleBatcherState,
	error,
) {
	var raw []byte
	err := tx.QueryRow(
		m.Ctx(),
		`SELECT v FROM raft_kv_store WHERE short_host_id=$1 AND k = $2`,
		m.ShortHostID().ExportToDB(),
		BatchStateKey,
	).Scan(&raw)
	if err != nil && err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state proto.MerkleBatcherState
	err = core.DecodeFromBytes(&state, raw)
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func BatchKey(n proto.MerkleBatchNo) string {
	return fmt.Sprintf("%s/%d", batchPrefix, n)
}

func (s *MerklePipelineBaseServer) PollReadyHosts(
	m shared.MetaContext,
) (
	[]core.ShortHostID,
	error,
) {
	return s.sub.pollReadyHosts(m)
}

func (s *MerklePipelineBaseServer) DoOnePollForHost(m shared.MetaContext) error {
	return s.sub.doOnePollForHost(m)
}

func (s *MerklePipelineBaseServer) Shutdown(m shared.MetaContext) error {
	m.Infow("Shutdown", "stage", "releaseRunlock")
	err := s.lock.Release(m)
	if err != nil {
		m.Warnw("runPollLop", "stage", "releaseRunlock", "err", err)
	}
	return nil
}

func (s *MerklePipelineBaseServer) Poke(ctx context.Context) error {
	retCh := make(chan error)
	s.pokeCh <- retCh
	return <-retCh
}
