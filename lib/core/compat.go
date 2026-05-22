// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"context"
	"fmt"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
)

func MakeProtoHeader() proto.Header {
	return proto.NewHeaderWithV1(
		proto.HeaderV1{
			Vers: CurrentCompatibilityVersion,
		},
	)
}

func CheckProtoHeader(h proto.Header) error {
	v, err := h.GetV()
	if err != nil {
		return err
	}
	if v != proto.HeaderVersion_V1 {
		return VersionNotSupportedError(fmt.Sprintf("not supported: proto header version %d; please upgrade", v))
	}
	cv := h.V1().Vers
	if cv != CurrentCompatibilityVersion {
		return VersionNotSupportedError(fmt.Sprintf("not supported: compatibility version %d; please upgrade", cv))
	}
	return nil
}

type WithContextWarner interface {
	WarnwWithContext(ctx context.Context, msg string, keysAndValues ...interface{})
}

func CheckProtoArgHeader(ctx context.Context, h proto.Header, wcw WithContextWarner) error {
	v, err := h.GetV()
	if err != nil {
		return err
	}
	if v != proto.HeaderVersion_V1 {
		return VersionNotSupportedError(fmt.Sprintf("client not supported: proto header version %d", v))
	}
	cv := h.V1().Vers
	switch cv {
	case CurrentCompatibilityVersion:
		return nil
	case proto.CompatibilityVersion(0):
		return VersionNotSupportedError("client is too old: compatibility version 0; please upgrade")
	default:
		if wcw != nil {
			wcw.WarnwWithContext(ctx, "ClientVersion",
				"versionDiff",
				int(CurrentCompatibilityVersion-cv),
				"clientVersion", cv,
				"serverVersion", CurrentCompatibilityVersion,
			)
		}
	}
	return nil
}

func CheckProtoResHeader(ctx context.Context, h proto.Header, wcw WithContextWarner) error {
	v, err := h.GetV()
	if err != nil {
		return err
	}
	if v != proto.HeaderVersion_V1 {
		return VersionNotSupportedError(fmt.Sprintf("server not supported: proto header version %d; please ask for upgrade", v))
	}
	cv := h.V1().Vers
	switch cv {
	case CurrentCompatibilityVersion:
		return nil
	case proto.CompatibilityVersion(0):
		return VersionNotSupportedError("server is too old: compatibility version 0; please ask for upgrade")
	default:
		if wcw != nil {
			wcw.WarnwWithContext(ctx, "ServerVersion",
				"versionDiff",
				int(CurrentCompatibilityVersion-cv),
				"clientVersion", CurrentCompatibilityVersion,
				"serverVersion", cv,
			)
		}
	}
	return nil
}

func MakeCheckProtoResHeader(wcw WithContextWarner) func(context.Context, proto.Header) error {
	return func(ctx context.Context, h proto.Header) error {
		return CheckProtoResHeader(ctx, h, wcw)
	}
}

func NewRegClient(gcli rpc.GenericClient, wcw WithContextWarner) rem.RegClient {
	return rem.RegClient{
		Cli:            gcli,
		ErrorUnwrapper: StatusToError,
		MakeArgHeader:  MakeProtoHeader,
		CheckResHeader: MakeCheckProtoResHeader(wcw),
	}
}

func NewProbeClient(gcli rpc.GenericClient, wcw WithContextWarner) rem.ProbeClient {
	return rem.ProbeClient{
		Cli:            gcli,
		ErrorUnwrapper: StatusToError,
		MakeArgHeader:  MakeProtoHeader,
		CheckResHeader: MakeCheckProtoResHeader(wcw),
	}
}

func NewMerkleQueryClient(gcli rpc.GenericClient, wcw WithContextWarner) rem.MerkleQueryClient {
	return rem.MerkleQueryClient{
		Cli:            gcli,
		ErrorUnwrapper: StatusToError,
		MakeArgHeader:  MakeProtoHeader,
		CheckResHeader: MakeCheckProtoResHeader(wcw),
	}
}

func NewUserClient(gcli rpc.GenericClient, wcw WithContextWarner) rem.UserClient {
	return rem.UserClient{
		Cli:            gcli,
		ErrorUnwrapper: StatusToError,
		MakeArgHeader:  MakeProtoHeader,
		CheckResHeader: MakeCheckProtoResHeader(wcw),
	}
}

func NewKVStoreClient(gcli rpc.GenericClient, wcw WithContextWarner) rem.KVStoreClient {
	return rem.KVStoreClient{
		Cli:            gcli,
		ErrorUnwrapper: StatusToError,
		MakeArgHeader:  MakeProtoHeader,
		CheckResHeader: MakeCheckProtoResHeader(wcw),
	}
}

func NewBeaconClient(gcli rpc.GenericClient, wcw WithContextWarner) rem.BeaconClient {
	return rem.BeaconClient{
		Cli:            gcli,
		ErrorUnwrapper: StatusToError,
		MakeArgHeader:  MakeProtoHeader,
		CheckResHeader: MakeCheckProtoResHeader(wcw),
	}
}

func NewLogSendClient(gcli rpc.GenericClient, wcw WithContextWarner) rem.LogSendClient {
	return rem.LogSendClient{
		Cli:            gcli,
		ErrorUnwrapper: StatusToError,
		MakeArgHeader:  MakeProtoHeader,
		CheckResHeader: MakeCheckProtoResHeader(wcw),
	}
}

func NewRealTimeClient(gcli rpc.GenericClient, wcw WithContextWarner) rem.RealTimeClient {
	return rem.RealTimeClient{
		Cli:            gcli,
		ErrorUnwrapper: StatusToError,
		MakeArgHeader:  MakeProtoHeader,
		CheckResHeader: MakeCheckProtoResHeader(wcw),
	}
}
