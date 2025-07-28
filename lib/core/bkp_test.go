// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackupKey(t *testing.T) {
	var bk BackupKey
	seed, err := GenerateBackupSeed()
	require.NoError(t, err)
	err = bk.FromSeed(*seed)
	require.NoError(t, err)
	words, err := bk.Export()
	require.NoError(t, err)
	fmt.Printf("words: %v\n", words)
	var bk2 BackupKey
	err = bk2.Import(words)
	require.NoError(t, err)
	require.Equal(t, bk.Name(), bk2.Name())
	require.Equal(t, bk.seed, bk2.seed)
}
