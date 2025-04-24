// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libgit

import (
	"bytes"
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

type IndexStorage struct {
	adptr *adapter
}

const indexFilename = "index"

func (i *IndexStorage) SetIndex(idx *index.Index) error {
	var buf bytes.Buffer
	err := index.NewEncoder(&buf).Encode(idx)
	if err != nil {
		return err
	}
	return i.adptr.putDataToPath(context.Background(), indexFilename, &buf)
}

func (i *IndexStorage) Index() (*index.Index, error) {
	var buf bytes.Buffer
	idx := &index.Index{Version: 2}
	err := i.adptr.getDataFromPath(context.Background(), indexFilename, &buf)
	if _, ok := err.(core.NotFoundError); ok {
		return idx, nil
	}
	if err != nil {
		return nil, err
	}
	err = index.NewDecoder(&buf).Decode(idx)
	return idx, err
}

var _ storer.IndexStorer = (*IndexStorage)(nil)
