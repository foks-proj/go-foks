// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libgit

import (
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/go-git/go-git/v5/storage"
)

type ModuleStorage struct {
	adptr *adapter
}

func (m ModuleStorage) Module(name string) (storage.Storer, error) {
	adapter := m.adptr.module(proto.GitRepo(name))
	return newStorageWithAdapter(adapter), nil
}

var _ storage.ModuleStorer = (*ModuleStorage)(nil)
