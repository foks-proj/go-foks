// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libgit

import (
	"bufio"
	"bytes"
	"context"
	"strings"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/storer"
)

type ShallowStorage struct {
	adptr *adapter
}

func (s *ShallowStorage) SetShallow(v []plumbing.Hash) error {
	var sw strings.Builder
	for _, h := range v {
		sw.WriteString(h.String() + "\n")
	}
	rdr := bytes.NewReader([]byte(sw.String()))
	return s.adptr.putDataToPath(context.Background(), "shallow", rdr)
}

func (s *ShallowStorage) Shallow() ([]plumbing.Hash, error) {
	var buf bytes.Buffer
	err := s.adptr.getDataFromPath(context.Background(), "shallow", &buf)
	if core.IsKVNoentError(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(&buf)
	var hashes []plumbing.Hash
	for scanner.Scan() {
		hashes = append(hashes, plumbing.NewHash(scanner.Text()))
	}
	return hashes, scanner.Err()
}

var _ storer.ShallowStorer = (*ShallowStorage)(nil)
