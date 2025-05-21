// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

//go:build !windows

package lcl

//go:generate go tool github.com/foks-proj/go-snowpack-compiler/snowpc -l go -p lcl -I ../../proto-src/lcl -O . -v
//go:generate go fmt .
