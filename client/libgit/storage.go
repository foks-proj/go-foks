// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libgit

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libkv"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/go-git/go-git/v5/storage"
)

type StorageOpts struct {
	ListPageSize uint64
}

type Storage struct {
	adptr *adapter

	ObjectStorage
	ReferenceStorage
	ShallowStorage
	IndexStorage
	ConfigStorage
	ModuleStorage
}

func NewStorage(
	g *libclient.GlobalContext,
	fs *libkv.Minder,
	auOverride *libclient.UserContext,
	actingAs *proto.FQTeamParsed,
	repoName proto.GitRepo,
	opts StorageOpts,
) *Storage {
	adptr := newAdapter(g, fs, auOverride, actingAs, repoName, opts)
	return newStorageWithAdapter(adptr)
}

func newStorageWithAdapter(adptr *adapter) *Storage {
	return &Storage{
		adptr:            adptr,
		ObjectStorage:    ObjectStorage{adptr: adptr},
		ReferenceStorage: ReferenceStorage{adptr: adptr},
		ShallowStorage:   ShallowStorage{adptr: adptr},
		IndexStorage:     IndexStorage{adptr: adptr},
		ConfigStorage:    ConfigStorage{adptr: adptr},
		ModuleStorage:    ModuleStorage{adptr: adptr},
	}
}

func (s *Storage) NewPackSyncRemote() *PackSyncRemote {
	return newPackSyncRemote(s.adptr)
}

var _ storage.Storer = (*Storage)(nil)
