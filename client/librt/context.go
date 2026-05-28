package librt

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
)

type MetaContext struct {
	libclient.MetaContext
	au *libclient.UserContext
}

func (m MetaContext) Base() libclient.MetaContext {
	return m.MetaContext
}

func NewMetaContext(m libclient.MetaContext) MetaContext {
	return MetaContext{
		MetaContext: m,
	}
}

func (m MetaContext) SetActiveUser(u *libclient.UserContext) MetaContext {
	m.au = u
	return m
}

func (m MetaContext) ActiveUser() (*libclient.UserContext, error) {
	if m.au != nil {
		return m.au, nil
	}
	ret := m.G().ActiveUser()
	if ret != nil {
		return ret, nil
	}
	return nil, core.NoActiveUserError{}
}
