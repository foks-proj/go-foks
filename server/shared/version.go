package shared

import (
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

func ClientVersionInfo(
	m MetaContext,
	_ proto.ClientVersionExt,
) (
	*rem.ClientVersionInfo,
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
	ret := rem.ClientVersionInfo{
		Min:    vcfg.MinVersion(),
		Newest: vcfg.NewestVersion(),
		Msg:    vcfg.Message(),
	}
	return &ret, nil
}
