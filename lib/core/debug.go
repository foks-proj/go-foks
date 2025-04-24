// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"fmt"
	"os"
)

func DebugStop() {
	flag := os.Getenv("FOKS_DEBUG_STOP")
	if flag == "" || flag == "0" {
		return
	}
	pid := os.Getpid()
	fmt.Fprintf(os.Stderr, "FOKS_DEBUG_STOP: pid %d\n", pid)
	fmt.Fprintf(os.Stderr, "Attach debugger and press any key to continue...")
	var buf [1]byte

	// Read any one byte and then go
	_, _ = os.Stdin.Read(buf[:])
}
