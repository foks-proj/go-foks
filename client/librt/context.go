package librt

import (
	"github.com/foks-proj/go-foks/client/libclient"
)

type MetaContext struct {
	libclient.MetaContext
}

func (m MetaContext) Base() libclient.MetaContext {
	return m.MetaContext
}

func NewMetaContext(m libclient.MetaContext) MetaContext {
	return MetaContext{
		MetaContext: m,
	}
}
