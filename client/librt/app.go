package librt

import (
	"sync"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

var AppID = libclient.AppID("rt")

type App struct {
	sync.Mutex
	parent *libclient.UserContext
	teams  map[proto.FQTeam]*Minder
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

func (a *App) Minder(m MetaContext, actingAs *proto.FQTeamParsed) (*Minder, error) {
	if actingAs == nil {
		return nil, core.InternalError("nil actingAs in librt.App.Minder")
	}
	fqp, err := a.parent.TeamMinder().ResolveAndReindex(m.MetaContext, *actingAs, nil)
	if err != nil {
		return nil, err
	}
	a.Lock()
	defer a.Unlock()
	var ret *Minder
	if ret = a.teams[*fqp]; ret == nil {
		ret = NewMinder(a.parent)
		a.teams[*fqp] = ret
	}
	return ret, nil
}

func appFromMeta(m MetaContext) (*App, error) {
	au, err := m.ActiveConnectedUser(&libclient.ACUOpts{AssertUnlocked: true})
	if err != nil {
		return nil, err
	}
	if au == nil {
		return nil, core.NoActiveUserError{}
	}
	app, err := GetApp(au)
	if err != nil {
		return nil, err
	}
	return app, nil
}

func InitReq(
	m MetaContext,
	tm *proto.FQTeamParsed,
) (
	*Minder,
	error,
) {
	app, err := appFromMeta(m)
	if err != nil {
		return nil, err
	}
	ret, err := app.Minder(m, tm)
	if err != nil {
		return nil, err
	}
	return ret, nil
}
