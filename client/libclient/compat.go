// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
)

func MakeProtoHeader() lcl.Header {
	return lcl.NewHeaderWithV1(
		lcl.HeaderV1{
			Semver: core.CurrentClientVersion,
		},
	)
}

func MakeCheckProtoResHeader(errio IOStreamer) func(context.Context, lcl.Header) error {
	return func(ctx context.Context, h lcl.Header) error {
		v, err := h.GetV()
		if err != nil {
			return err
		}
		if v != lcl.HeaderVersion_V1 {
			return core.VersionNotSupportedError(
				fmt.Sprintf("not supported: proto header version %d; please upgrade", v))
		}
		return nil
	}
}
