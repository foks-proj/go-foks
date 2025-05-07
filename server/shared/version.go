package shared

import (
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func ClientVersionInfo(
	m MetaContext,
	_ proto.ClientVersionExt,
) (
	*proto.ServerClientVersionInfo,
	error,
) {
	cfg := m.G().Config()
	ccfg, err := cfg.ClientConfig(m.Ctx())
	if err != nil {
		return nil, err
	}
	if ccfg == nil {
		return nil, nil
	}
	vcfg := ccfg.ClientVersion()
	if vcfg == nil {
		return nil, nil
	}
	ret := proto.ServerClientVersionInfo{
		Min:    vcfg.MinVersion(),
		Newest: vcfg.NewestVersion(),
		Msg:    vcfg.Message(),
	}
	return &ret, nil
}
