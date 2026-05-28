package librt

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type Minder struct {
	au *libclient.UserContext
}

func NewMinder(au *libclient.UserContext) *Minder {
	return &Minder{
		au: au,
	}
}

func (d *Minder) MakeChannel(
	m MetaContext,
	nm proto.RTChannelName,
	desc proto.RTChannelDesc,
	roles proto.RolePairOpt,
) (
	*proto.RTChannelID,
	error,
) {
	return nil, core.NotImplementedError{}
}
