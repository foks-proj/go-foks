package realtime

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/jackc/pgx/v5"
)

// AuthorizeUserForTeam is at first, in Stage 1a, very conservative. It only
// authorizes users who are direct members of a team, and local team members.
// Returns the role of the user in that team. Requires that the user is
// using an Owner device (and won't look for devices at source roles lower than
// owner).
func AuthorizeUserForTeam(
	m shared.MetaContext,
	db shared.Querier,
	team proto.TeamID,
) (
	*core.RoleKey,
	error,
) {
	ownerType, ownerViz, err := proto.OwnerRole.ExportToDB()
	if err != nil {
		return nil, err
	}
	var rt, vl int

	err = db.QueryRow(
		m.Ctx(),
		`SELECT dst_role_type, dst_viz_level
		FROM team_members
		WHERE short_host_id=$1
		AND team_id=$2
		AND member_id=$3
		AND member_host_id=$4
		AND src_role_type=$5
		AND src_viz_level=$6
		AND active=true
		ORDER BY seqno DESC
		LIMIT 1`,
		m.ShortHostID(),
		team.ExportToDB(),
		m.UID().ExportToDB(),
		shared.ExportHostP(nil),
		ownerType,
		ownerViz,
	).Scan(&rt, &vl)
	if err == pgx.ErrNoRows {
		return nil, core.PermissionError("no authorization for team")
	}
	if err != nil {
		return nil, err
	}
	var ret proto.Role
	err = ret.ImportFromDB(rt, vl)
	if err != nil {
		return nil, err
	}
	rk, err := core.ImportRole(ret)
	if err != nil {
		return nil, err
	}
	return rk, nil
}
