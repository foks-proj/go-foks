package librt

import (
	"sync"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
)

var AppID = libclient.AppID("rt")

type App struct {
	sync.Mutex
	parent *libclient.UserContext
}

func NewApp(u *libclient.UserContext) *App {
	return &App{
		parent: u,
	}
}
func (k *App) Cleanup(m libclient.MetaContext) error { return nil }
func (k *App) ID() libclient.AppID                   { return AppID }

func GetApp(u *libclient.UserContext) (*App, error) {
	ret := libclient.GetApp(u, AppID, NewApp)
	if ret == nil {
		return nil, core.InternalError("failed to get realtime App")
	}
	return ret, nil
}
