// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package engine

import (
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

func (r *RegClientConn) withInvite(
	ctx context.Context,
	i proto.TeamInvite,
	f func(m shared.MetaContext, hsh proto.TeamCertHash, cert *rem.TeamCertAndMetadata) error,
) error {
	v, err := i.GetV()
	if err != nil {
		return err
	}
	if v != proto.TeamInviteVersion_V1 {
		return core.VersionNotSupportedError("team invite")
	}
	i1 := i.V1()
	m, err := shared.NewMetaContextFromArg(ctx, r, &i1.Host)
	if err != nil {
		return err
	}
	cert, err := shared.LoadTeamCertByHash(m, i1.Hsh)
	if err != nil {
		return err
	}
	return f(m, i1.Hsh, cert)
}

func (r *RegClientConn) LookupTeamCertByHash(
	ctx context.Context,
	i proto.TeamInvite,
) (
	rem.TeamCertAndMetadata,
	error,
) {
	var ret rem.TeamCertAndMetadata
	err := r.withInvite(ctx, i,
		func(m shared.MetaContext, hsh proto.TeamCertHash, cert *rem.TeamCertAndMetadata) error {
			ret = *cert
			return nil
		})
	return ret, err
}

func (r *RegClientConn) AcceptInviteRemote(
	ctx context.Context,
	arg rem.AcceptInviteRemoteArg,
) (proto.TeamRSVPRemote, error) {
	var ret proto.TeamRSVPRemote
	err := r.withInvite(ctx, arg.I,
		func(m shared.MetaContext, hsh proto.TeamCertHash, cert *rem.TeamCertAndMetadata) error {
			err := shared.RetryTxUserDB(m, "AcceptInvite", func(m shared.MetaContext, tx pgx.Tx) error {
				tmp, err := shared.RemoteAcceptInvite(m, tx, hsh, cert.Cert, arg.Jr)
				if err != nil {
					return err
				}
				ret = *tmp
				return nil
			})
			return err
		})
	return ret, err

}

var _ rem.TeamGuestInterface = (*RegClientConn)(nil)
