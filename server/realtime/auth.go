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

// activeTeamMembers returns the subset of uids that are active, direct, local
// user members of the team, with their roles. Same membership rules as
// AuthorizeUserForTeam, for users other than the caller.
func activeTeamMembers(
	m shared.MetaContext,
	db shared.Querier,
	team proto.TeamID,
	uids []proto.UID,
) (
	map[proto.UID]core.RoleKey,
	error,
) {
	ret := make(map[proto.UID]core.RoleKey, len(uids))
	if len(uids) == 0 {
		return ret, nil
	}
	ownerType, ownerViz, err := proto.OwnerRole.ExportToDB()
	if err != nil {
		return nil, err
	}
	raw := make([][]byte, len(uids))
	for i, u := range uids {
		raw[i] = u.ExportToDB()
	}
	rows, err := db.Query(
		m.Ctx(),
		`SELECT DISTINCT ON (member_id) member_id, dst_role_type, dst_viz_level
		 FROM team_members
		 WHERE short_host_id=$1
		 AND team_id=$2
		 AND member_host_id=$3
		 AND src_role_type=$4
		 AND src_viz_level=$5
		 AND active=true
		 AND member_id = ANY($6)
		 ORDER BY member_id, seqno DESC`,
		m.ShortHostID(),
		team.ExportToDB(),
		shared.ExportHostP(nil),
		ownerType,
		ownerViz,
		raw,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var memRaw []byte
		var rt, vl int
		err = rows.Scan(&memRaw, &rt, &vl)
		if err != nil {
			return nil, err
		}
		var pid proto.PartyID
		err = pid.ImportFromDB(memRaw)
		if err != nil {
			return nil, err
		}
		if !pid.IsUser() {
			continue
		}
		uid, err := pid.UID()
		if err != nil {
			return nil, err
		}
		rk, err := core.ImportRoleKeyFromDB(rt, vl)
		if err != nil {
			return nil, err
		}
		ret[uid] = *rk
	}
	err = rows.Err()
	if err != nil {
		return nil, err
	}
	return ret, nil
}
