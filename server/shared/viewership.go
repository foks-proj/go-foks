package shared

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type HostViewership struct {
	HostID      core.ShortHostID
	UserViewing proto.ViewershipMode
}

func GetViewership(m MetaContext, hosts []core.ShortHostID) ([]HostViewership, error) {
	iHosts := core.Map(hosts, func(h core.ShortHostID) int {
		return int(h)
	})

	q := `SELECT short_host_id, user_viewing FROM host_config`
	args := []any{}
	if len(iHosts) > 0 {
		q += ` WHERE host_id = ANY($1)`
		args = append(args, iHosts)
	}
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return nil, err
	}
	defer db.Release()
	rows, err := db.Query(m.Ctx(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ret []HostViewership
	for rows.Next() {
		var uvs string
		var host int
		if err := rows.Scan(&host, &uvs); err != nil {
			return nil, err
		}
		item := HostViewership{
			HostID: core.ShortHostID(host),
		}
		err := item.UserViewing.ImportFromDB(uvs)
		if err != nil {
			return nil, err
		}
		ret = append(ret, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ret, nil
}

func SetViewership(m MetaContext, mode proto.ViewershipMode, hosts []core.ShortHostID) error {
	if len(hosts) == 0 {
		hv, err := GetViewership(m, nil)
		if err != nil {
			return err
		}
		if len(hv) == 0 {
			return core.HostIDNotFoundError{}
		}
		if len(hv) > 1 {
			return core.BadArgsError("need to specify hostID since there are multiple hosts")
		}
		hosts = []core.ShortHostID{hv[0].HostID}
	}
	db, err := m.Db(DbTypeServerConfig)
	if err != nil {
		return err
	}
	defer db.Release()
	q := `UPDATE host_config SET user_viewing = $1 WHERE short_host_id = ANY($2)`
	args := []any{
		mode.String(),
		core.Map(hosts, func(h core.ShortHostID) int { return int(h) })}
	_, err = db.Exec(m.Ctx(), q, args...)
	if err != nil {
		return err
	}
	return nil
}
