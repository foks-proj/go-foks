package librt

import (
	"sync"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

var AppID = libclient.AppID("rt")

type App struct {
	sync.Mutex
	parent *libclient.UserContext
	teams  map[proto.FQTeam]*Minder
	user   *Minder // team-independent flows (e.g. the inbox); lazily made

	// One lock per appID serializes inbox syncs for this user (the App is a
	// per-UserContext singleton), so concurrent syncs can't interleave their
	// page applies -- even across Minders.
	inboxSyncLocks map[proto.RTAppID]*sync.Mutex
}

func NewApp(u *libclient.UserContext) *App {
	return &App{
		parent:         u,
		teams:          make(map[proto.FQTeam]*Minder),
		inboxSyncLocks: make(map[proto.RTAppID]*sync.Mutex),
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

func (a *App) Minder(m MetaContext, actingAs lcl.ConfigTeam) (*Minder, error) {
	typ, err := actingAs.GetT()
	if err != nil {
		return nil, err
	}
	if typ == lcl.ConfigTeamType_None {
		return nil, core.InternalError("no actingAs team in librt.App.Minder")
	}
	fqp, err := a.parent.TeamMinder().ResolveAndReindex(m.MetaContext, actingAs, nil)
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

// UserMinder returns the user-scoped Minder, for flows that aren't tied to any
// one team -- like the inbox, which spans all of the user's teams. Per-team
// parties are still loaded lazily through its BaseMinder as needed.
func (a *App) UserMinder() *Minder {
	a.Lock()
	defer a.Unlock()
	if a.user == nil {
		a.user = NewMinder(a.parent)
	}
	return a.user
}

func (a *App) inboxSyncLock(appID proto.RTAppID) *sync.Mutex {
	a.Lock()
	defer a.Unlock()
	lk := a.inboxSyncLocks[appID]
	if lk == nil {
		lk = &sync.Mutex{}
		a.inboxSyncLocks[appID] = lk
	}
	return lk
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
	tm lcl.ConfigTeam,
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

// InitUserReq is InitReq for user-scoped requests that don't act as any one
// team, like inbox sync and render.
func InitUserReq(
	m MetaContext,
) (
	*Minder,
	error,
) {
	app, err := appFromMeta(m)
	if err != nil {
		return nil, err
	}
	return app.UserMinder(), nil
}
