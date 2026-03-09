// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

type mcpKV struct {
	m   libclient.MetaContext
	cli lcl.KVClient
}

func mcpKVMakeConfig(team string, mkdirP bool, overwrite bool, recursive bool) (lcl.KVConfig, error) {
	var fqt *proto.FQTeamParsed
	if team != "" {
		var err error
		fqt, err = core.ParseFQTeam(proto.FQTeamString(team))
		if err != nil {
			return lcl.KVConfig{}, err
		}
	}
	return lcl.KVConfig{
		ActingAs:    fqt,
		MkdirP:      mkdirP,
		OverwriteOk: overwrite,
		Recursive:   recursive,
	}, nil
}

func mcpKVMakePath(s string) proto.KVPath {
	if len(s) == 0 || s[0] != '/' {
		s = "/" + s
	}
	return proto.KVPath(s)
}

func mcpKVTextResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

func mcpKVErrorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: err.Error()},
		},
	}
}

type mcpKVListInput struct {
	Path string `json:"path" jsonschema:"directory path to list (e.g. /)"`
	Team string `json:"team,omitempty" jsonschema:"team to act on behalf of (omit for personal store)"`
}

func (k *mcpKV) list(ctx context.Context, req *mcp.CallToolRequest, input mcpKVListInput) (*mcp.CallToolResult, any, error) {
	cfg, err := mcpKVMakeConfig(input.Team, false, false, false)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	path := mcpKVMakePath(input.Path)
	num := k.m.G().Cfg().KVListPageSize()
	var entries []lcl.KVListEntry
	var dirID *proto.DirID
	nxt := proto.NewKVListPaginationWithNone()
	for {
		res, err := k.cli.ClientKVList(ctx, lcl.ClientKVListArg{
			Cfg:   cfg,
			Path:  path,
			Num:   num,
			Nxt:   nxt,
			DirID: dirID,
		})
		if err != nil {
			return mcpKVErrorResult(err), nil, nil
		}
		entries = append(entries, res.Ents...)
		if res.Nxt == nil {
			break
		}
		dirID = &res.Nxt.Id
		nxt = res.Nxt.Nxt
	}
	var sb strings.Builder
	for _, ent := range entries {
		var typ string
		switch ent.Typ {
		case proto.KVNodeType_File, proto.KVNodeType_SmallFile:
			typ = "file"
		case proto.KVNodeType_Dir:
			typ = "dir"
		case proto.KVNodeType_Symlink:
			typ = "symlink"
		default:
			typ = "unknown"
		}
		mtime := ent.Mtime.Import().UTC().Format("2006-01-02T15:04:05Z")
		fmt.Fprintf(&sb, "%s\t%s\t%s\n", ent.Name, typ, mtime)
	}
	return mcpKVTextResult(sb.String()), nil, nil
}

type mcpKVGetInput struct {
	Path   string `json:"path" jsonschema:"file path to read"`
	Team   string `json:"team,omitempty" jsonschema:"team to act on behalf of (omit for personal store)"`
	Base64 bool   `json:"base64,omitempty" jsonschema:"if true, base64-encode output data"`
}

func (k *mcpKV) get(ctx context.Context, req *mcp.CallToolRequest, input mcpKVGetInput) (*mcp.CallToolResult, any, error) {
	cfg, err := mcpKVMakeConfig(input.Team, false, false, false)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	path := mcpKVMakePath(input.Path)
	var buf bytes.Buffer
	err = libkv.GetFile(
		&buf,
		func() (lcl.GetFileRes, error) {
			return k.cli.ClientKVGetFile(ctx, lcl.ClientKVGetFileArg{
				Cfg:  cfg,
				Path: path,
			})
		},
		func(id proto.FileID, offset proto.Offset) (lcl.GetFileChunkRes, error) {
			return k.cli.ClientKVGetFileChunk(ctx, lcl.ClientKVGetFileChunkArg{
				Id:     id,
				Cfg:    cfg,
				Offset: offset,
			})
		},
	)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	data := buf.Bytes()
	if input.Base64 {
		return mcpKVTextResult(base64.StdEncoding.EncodeToString(data)), nil, nil
	}
	if isProbablyBinary(data) {
		return nil, nil, TerminalError("refusing to output binary data over MCP; try supplying base64:true flag")
	}
	return mcpKVTextResult(string(data)), nil, nil
}

type mcpKVPutInput struct {
	Path      string `json:"path" jsonschema:"file path to write"`
	Content   string `json:"content" jsonschema:"content to write (text, or base64-encoded if base64 flag is set)"`
	Team      string `json:"team,omitempty" jsonschema:"team to act on behalf of (omit for personal store)"`
	MkdirP    bool   `json:"mkdir_p,omitempty" jsonschema:"create parent directories if they do not exist"`
	Overwrite bool   `json:"overwrite,omitempty" jsonschema:"overwrite existing file"`
	Base64    bool   `json:"base64,omitempty" jsonschema:"if true, content is base64-encoded binary data"`
}

func (k *mcpKV) put(ctx context.Context, req *mcp.CallToolRequest, input mcpKVPutInput) (*mcp.CallToolResult, any, error) {
	cfg, err := mcpKVMakeConfig(input.Team, input.MkdirP, input.Overwrite, false)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	path := mcpKVMakePath(input.Path)
	var rdr *bytes.Reader
	if input.Base64 {
		decoded, err := base64.StdEncoding.DecodeString(input.Content)
		if err != nil {
			return mcpKVErrorResult(fmt.Errorf("invalid base64: %w", err)), nil, nil
		}
		rdr = bytes.NewReader(decoded)
	} else {
		rdr = bytes.NewReader([]byte(input.Content))
	}
	err = libkv.PutFile(
		rdr,
		func(data []byte, isFinal bool) (proto.KVNodeID, error) {
			return k.cli.ClientKVPutFirst(ctx, lcl.ClientKVPutFirstArg{
				Cfg:   cfg,
				Path:  path,
				Chunk: data,
				Final: isFinal,
			})
		},
		func(id proto.FileID, data []byte, offset proto.Offset, final bool) error {
			return k.cli.ClientKVPutChunk(ctx, lcl.ClientKVPutChunkArg{
				Cfg:    cfg,
				Id:     id,
				Chunk:  data,
				Offset: offset,
				Final:  final,
			})
		},
		0,
	)
	if err != nil {
		err = core.ErrorAsWriteError(err)
		return mcpKVErrorResult(err), nil, nil
	}
	return mcpKVTextResult("ok"), nil, nil
}

type mcpKVMkdirInput struct {
	Path   string `json:"path" jsonschema:"directory path to create"`
	Team   string `json:"team,omitempty" jsonschema:"team to act on behalf of (omit for personal store)"`
	MkdirP bool   `json:"mkdir_p,omitempty" jsonschema:"create parent directories if they do not exist"`
}

func (k *mcpKV) mkdir(ctx context.Context, req *mcp.CallToolRequest, input mcpKVMkdirInput) (*mcp.CallToolResult, any, error) {
	cfg, err := mcpKVMakeConfig(input.Team, input.MkdirP, false, false)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	path := mcpKVMakePath(input.Path)
	res, err := k.cli.ClientKVMkdir(ctx, lcl.ClientKVMkdirArg{
		Cfg:  cfg,
		Path: path,
	})
	err = core.ErrorAsWriteError(err)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	did, err := res.KVNodeID().StringErr()
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	return mcpKVTextResult(fmt.Sprintf("DirID: %s", did)), nil, nil
}

type mcpKVRmInput struct {
	Path      string `json:"path" jsonschema:"path to remove"`
	Team      string `json:"team,omitempty" jsonschema:"team to act on behalf of (omit for personal store)"`
	Recursive bool   `json:"recursive,omitempty" jsonschema:"remove directories recursively"`
}

func (k *mcpKV) rm(ctx context.Context, req *mcp.CallToolRequest, input mcpKVRmInput) (*mcp.CallToolResult, any, error) {
	cfg, err := mcpKVMakeConfig(input.Team, false, false, input.Recursive)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	path := mcpKVMakePath(input.Path)
	err = k.cli.ClientKVRm(ctx, lcl.ClientKVRmArg{
		Cfg:  cfg,
		Path: path,
	})
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	return mcpKVTextResult("ok"), nil, nil
}

type mcpKVMvInput struct {
	Src  string `json:"src" jsonschema:"source path"`
	Dst  string `json:"dst" jsonschema:"destination path"`
	Team string `json:"team,omitempty" jsonschema:"team to act on behalf of (omit for personal store)"`
}

func (k *mcpKV) mv(ctx context.Context, req *mcp.CallToolRequest, input mcpKVMvInput) (*mcp.CallToolResult, any, error) {
	cfg, err := mcpKVMakeConfig(input.Team, false, false, false)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	src := mcpKVMakePath(input.Src)
	dst := mcpKVMakePath(input.Dst)
	err = k.cli.ClientKVMv(ctx, lcl.ClientKVMvArg{
		Cfg: cfg,
		Src: src,
		Dst: dst,
	})
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	return mcpKVTextResult("ok"), nil, nil
}

type mcpKVStatInput struct {
	Path string `json:"path" jsonschema:"path to stat"`
	Team string `json:"team,omitempty" jsonschema:"team to act on behalf of (omit for personal store)"`
}

func (k *mcpKV) stat(ctx context.Context, req *mcp.CallToolRequest, input mcpKVStatInput) (*mcp.CallToolResult, any, error) {
	cfg, err := mcpKVMakeConfig(input.Team, false, false, false)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	path := mcpKVMakePath(input.Path)
	res, err := k.cli.ClientKVStat(ctx, lcl.ClientKVStatArg{
		Cfg:  cfg,
		Path: path,
	})
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	return mcpKVTextResult(string(data)), nil, nil
}

type mcpKVUsageInput struct {
	Team string `json:"team,omitempty" jsonschema:"team to act on behalf of (omit for personal store)"`
}

func (k *mcpKV) usage(ctx context.Context, req *mcp.CallToolRequest, input mcpKVUsageInput) (*mcp.CallToolResult, any, error) {
	cfg, err := mcpKVMakeConfig(input.Team, false, false, false)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	res, err := k.cli.ClientKVUsage(ctx, cfg)
	if err != nil {
		return mcpKVErrorResult(err), nil, nil
	}
	text := fmt.Sprintf("Num Files: %d\nTotal Size: %d",
		res.Small.Num+res.Large.Base.Num,
		res.Small.Sum+res.Large.Base.Sum,
	)
	return mcpKVTextResult(text), nil, nil
}

func newMCPKVServer(m libclient.MetaContext, gcli rpc.GenericClient) *mcp.Server {
	kv := &mcpKV{
		m:   m,
		cli: libclient.NewRpcTypedClient[lcl.KVClient](m, gcli),
	}

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "foks-kv",
		Version: core.CurrentSoftwareVersion.String(),
	}, nil)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "list",
		Description: "List contents of a directory in the FOKS encrypted key-value store",
	}, kv.list)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get",
		Description: "Read file contents from the FOKS encrypted key-value store",
	}, kv.get)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "put",
		Description: "Write file contents to the FOKS encrypted key-value store",
	}, kv.put)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "mkdir",
		Description: "Create a directory in the FOKS encrypted key-value store",
	}, kv.mkdir)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "rm",
		Description: "Remove a file or directory from the FOKS encrypted key-value store",
	}, kv.rm)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "mv",
		Description: "Move or rename an entry in the FOKS encrypted key-value store",
	}, kv.mv)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "stat",
		Description: "Get metadata for an entry in the FOKS encrypted key-value store",
	}, kv.stat)

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "usage",
		Description: "Show storage usage for the FOKS encrypted key-value store",
	}, kv.usage)

	return srv
}

func mcpKVCmd(m libclient.MetaContext, top *cobra.Command) {
	cmd := &cobra.Command{
		Use:          "kv",
		Short:        "Run MCP server for key-value store operations",
		Long:         "Run an MCP (Model Context Protocol) server over stdio exposing FOKS KV store operations",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			gcli, cleanFn, err := runMCPServer(m)
			if err != nil {
				return err
			}
			defer cleanFn()
			srv := newMCPKVServer(m, gcli)
			var transport mcp.Transport
			if mcpUI := m.G().UIs().MCP; mcpUI != nil {
				transport = mcpUI.Transport()
			} else {
				transport = &mcp.StdioTransport{}
			}
			return srv.Run(m.Ctx(), transport)
		},
	}
	top.AddCommand(cmd)
}
