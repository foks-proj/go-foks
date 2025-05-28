package shared

import (
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func GetServerConfig(
	m MetaContext,
) (
	*proto.RegServerConfig,
	error,
) {
	ssoCfg, err := LoadSSOConfig(m, nil)
	if err != nil {
		return nil, err
	}
	var ret proto.RegServerConfig
	ret.Sso = ssoCfg
	cfg, err := m.G().HostIDMap().Config(m, m.ShortHostID())
	if err != nil {
		return nil, err
	}
	ret.Typ = cfg.Typ
	ret.View = cfg.Viewership
	return &ret, nil
}
