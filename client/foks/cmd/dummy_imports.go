// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package cmd

// If we run `go mod tidy` on macOS, we do not want to delete these linux-specific imports
// from the go.mod file. This file is a workaround to prevent that. Rather ugly tho!

import (
	"context"

	"github.com/coreos/go-systemd/v22/dbus"
)

func Dummy() {
	_, _ = dbus.NewUserConnectionContext(context.Background())
}
