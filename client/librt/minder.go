package librt

import (
	"sync"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type RTParty struct {
	sync.RWMutex
	plcn *libclient.PLCNode
}

func (k *RTParty) SetPLCNode(n *libclient.PLCNode) {
	k.plcn = n
}

var _ libclient.BaseMinderNoder = (*RTParty)(nil)

type Minder struct {
	sync.Mutex
	base *libclient.BaseMinder[RTParty, *RTParty]
	au   *libclient.UserContext
}

func NewMinder(au *libclient.UserContext) *Minder {
	ret := &Minder{au: au}
	ret.base = libclient.NewBaseMinder(
		au,
		func(n *RTParty) {},
	)
	return ret
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
