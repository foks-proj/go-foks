// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package team

import proto "github.com/foks-proj/go-foks/proto/lib"

var UserSrcRole = proto.OwnerRole
var AdHocTeamName = proto.Name("-")

// AdHocTeamImmutableMsg is returned (wrapped in core.TeamError) by both the
// client and the server when something tries to edit an ad-hoc team. Ad-hoc
// teams have a fixed membership set at creation time and admit no later edits.
const AdHocTeamImmutableMsg = "ad-hoc teams have fixed membership and cannot be edited"
