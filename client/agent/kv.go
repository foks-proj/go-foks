// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"context"

	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

func (c *AgentConn) kvInit(ctx context.Context, cfg lcl.KVConfig) (libkv.MetaContext, *libkv.Minder, error) {
	m := libkv.NewMetaContext(c.MetaContext(ctx))
	ret, err := libkv.InitReq(m, cfg.ActingAs)
	if err != nil {
		return m, nil, err
	}
	return m, ret, nil
}

func (c *AgentConn) ClientKVMkdir(ctx context.Context, arg lcl.ClientKVMkdirArg) (proto.DirID, error) {
	var ret proto.DirID
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return ret, err
	}
	tmp, err := tm.Mkdir(m, arg.Cfg, arg.Path)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *AgentConn) ClientKVPutFirst(
	ctx context.Context,
	arg lcl.ClientKVPutFirstArg,
) (
	proto.KVNodeID,
	error,
) {
	var zed proto.KVNodeID
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return zed, err
	}
	pfr, err := tm.PutFileFirst(m, arg.Cfg, arg.Path, arg.Chunk, arg.Final)
	if err != nil {
		return zed, err
	}
	return pfr.NodeID, nil
}

func (c *AgentConn) ClientKVPutChunk(
	ctx context.Context,
	arg lcl.ClientKVPutChunkArg,
) error {
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return err
	}
	err = tm.PutFileChunk(m, arg.Cfg, arg.Id, arg.Chunk, arg.Offset, arg.Final)
	if err != nil {
		return err
	}
	return nil
}

func (c *AgentConn) ClientKVGetFile(
	ctx context.Context,
	arg lcl.ClientKVGetFileArg,
) (
	lcl.GetFileRes,
	error,
) {
	var ret lcl.GetFileRes
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return ret, err
	}
	tmp, err := tm.GetFile(m, arg.Cfg, arg.Path)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *AgentConn) ClientKVGetFileChunk(
	ctx context.Context,
	arg lcl.ClientKVGetFileChunkArg,
) (
	lcl.GetFileChunkRes,
	error,
) {
	var ret lcl.GetFileChunkRes
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return ret, err
	}
	tmp, err := tm.GetFileChunk(m, arg.Cfg, arg.Id, arg.Offset)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *AgentConn) ClientKVSymlink(
	ctx context.Context,
	arg lcl.ClientKVSymlinkArg,
) (
	proto.KVNodeID,
	error,
) {
	var ret proto.KVNodeID
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return ret, err
	}
	tmp, err := tm.Symlink(m, arg.Cfg, arg.Path, arg.Target)
	if err != nil {
		return ret, err
	}
	return tmp.NodeID, nil
}

func (c *AgentConn) ClientKVReadlink(
	ctx context.Context,
	arg lcl.ClientKVReadlinkArg,
) (
	proto.KVPath,
	error,
) {
	var ret proto.KVPath
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return ret, err
	}
	tmp, err := tm.Readlink(m, arg.Cfg, arg.Path)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *AgentConn) ClientKVMv(
	ctx context.Context,
	arg lcl.ClientKVMvArg,
) error {
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return err
	}
	err = tm.Mv(m, arg.Cfg, arg.Src, arg.Dst)
	if err != nil {
		return err
	}
	return nil
}

func (c *AgentConn) ClientKVStat(
	ctx context.Context,
	arg lcl.ClientKVStatArg,
) (
	lcl.KVStat,
	error,
) {
	var ret lcl.KVStat
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return ret, err
	}
	tmp, err := tm.Stat(m, arg.Cfg, arg.Path)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *AgentConn) ClientKVUnlink(
	ctx context.Context,
	arg lcl.ClientKVUnlinkArg,
) error {
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return err
	}
	return tm.Unlink(m, arg.Cfg, arg.Path)
}

func (c *AgentConn) ClientKVList(
	ctx context.Context,
	arg lcl.ClientKVListArg,
) (
	lcl.CliKVListRes,
	error,
) {
	var ret lcl.CliKVListRes
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return ret, err
	}
	opts := rem.KVListOpts{
		Start: arg.Nxt,
		Num:   arg.Num,
	}
	tmp, err := tm.List(m, arg.Cfg, arg.Path, arg.DirID, opts)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *AgentConn) ClientKVRm(
	ctx context.Context,
	arg lcl.ClientKVRmArg,
) error {
	m, tm, err := c.kvInit(ctx, arg.Cfg)
	if err != nil {
		return err
	}
	err = tm.Unlink(m, arg.Cfg, arg.Path)
	if err != nil {
		return err
	}
	return nil
}

func (c *AgentConn) ClientKVUsage(
	ctx context.Context,
	arg lcl.KVConfig,
) (
	proto.KVUsage,
	error,
) {
	var ret proto.KVUsage
	m, tm, err := c.kvInit(ctx, arg)
	if err != nil {
		return ret, err
	}
	tmp, err := tm.GetUsage(m, arg)
	if err != nil {
		return ret, err
	}
	return *tmp, nil
}

func (c *AgentConn) ClientKVRestStart(
	ctx context.Context,
	arg lcl.ClientKVRestStartArg,
) (
	lcl.KVRestListenInfo,
	error,
) {
	var zed lcl.KVRestListenInfo
	ret, err := libkv.StartRestServer(
		libkv.NewMetaContext(c.MetaContext(ctx)),
		arg,
	)
	if err != nil {
		return zed, err
	}
	return *ret, nil
}

func (c *AgentConn) ClientKVRestStop(
	ctx context.Context,
) error {
	return libkv.StopRestServer(
		libkv.NewMetaContext(c.MetaContext(ctx)))
}

var _ lcl.KVInterface = (*AgentConn)(nil)
