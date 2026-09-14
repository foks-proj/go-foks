// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libgit

import (
	"context"
	"fmt"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/client/libkv"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	remhelp "github.com/foks-proj/go-git-remhelp"
)

type Agent struct {
	argv            []string
	lcd             remhelp.LocalCheckoutDir
	remoteNameFixed remhelp.RemoteName
	remoteNameMut   remhelp.RemoteName
	rawURL          remhelp.RemoteURL
	url             *proto.GitURL
	storage         *Storage
	psr             *PackSyncRemote
	tl              remhelp.TermLogger

	blio   *RpcBatchedLineIO
	doneCh chan struct{}
}

func NewAgent(
	argv []string,
	lcd remhelp.LocalCheckoutDir,
	tl remhelp.TermLogger,
) *Agent {
	return &Agent{argv: argv, lcd: lcd, tl: tl}
}

func (a *Agent) PumpInRPC(
	ctx context.Context,
	line string,
) (
	[]string,
	error,
) {
	return a.blio.PumpInRPC(ctx, line)
}

func (a *Agent) argvToGitURL() error {
	if len(a.argv) == 0 {
		return core.GitGenericError("no URL")
	}
	if len(a.argv) > 0 {
		// Can change later on `git remote rename`, so not very useful
		a.remoteNameMut = remhelp.RemoteName(a.argv[0])
	}
	lst := proto.GitURLString(core.Last(a.argv))
	ret, err := lst.Parse()
	if err != nil {
		return err
	}
	if ret.Proto != proto.GitProtoType_Foks {
		return core.GitGenericError("unsupported protocol")
	}
	a.rawURL = remhelp.RemoteURL(lst)
	a.url = ret
	return nil
}

func encodeRemoteRepoID(
	remoteRepoID proto.GitRemoteRepoID,
) remhelp.RemoteName {
	ret := fmt.Sprintf("%s-%s",
		core.B36Encode(remoteRepoID.Host[:]),
		core.B36Encode(remoteRepoID.Dir[:]),
	)
	return remhelp.RemoteName(ret)
}

func (a *Agent) initFixedName(
	mctx libclient.MetaContext,
) error {
	nm, err := a.storage.adptr.remoteRepoID(mctx.Ctx())
	if err != nil {
		return err
	}
	a.remoteNameFixed = encodeRemoteRepoID(*nm)
	mctx.Infow("git Agent.initFixedName", "remoteNameFixed", a.remoteNameFixed)
	return nil
}

func (a *Agent) initStorage(
	mctx libclient.MetaContext,
) error {
	if a.url.Fqp.Host == nil {
		return core.InternalError("no host in parsed Git URL")
	}
	var auOverride *libclient.UserContext
	var au *libclient.UserContext
	// Whichever user we pick, go through the connect-and-unlock path rather
	// than using the UserContext as is. If the agent started while its home
	// server was unreachable (e.g., at boot, before the network came up),
	// the user's keys haven't been unlocked yet, and every git operation
	// would fail with "key not found" until the agent restarted.
	acuOpts := &libclient.ACUOpts{AssertUnlocked: true}

	user, team, err := a.url.Fqp.Select()
	switch {
	case err != nil:
		return err
	case user != nil:
		uc, err := mctx.G().FindUser(*user)
		if err != nil {
			return err
		}
		if uc == nil {
			return core.InternalError("expected user!=nil if err==nil from FindUser")
		}
		uc, err = mctx.ConnectUser(uc, acuOpts)
		if err != nil {
			return err
		}
		auOverride = uc
		au = uc
	case team != nil:
		au, err = mctx.ActiveConnectedUser(acuOpts)
		if err != nil {
			return err
		}
	default:
		return core.InternalError("no user or team in parsed Git URL")
	}

	kv, err := libkv.GetApp(au)
	if err != nil {
		return err
	}

	mctxKv := libkv.NewMetaContext(mctx)
	if auOverride != nil {
		mctxKv = mctxKv.SetActiveUser(auOverride)
	}

	minder, err := kv.Minder(mctxKv, team)
	if err != nil {
		return err
	}

	storage := NewStorage(
		mctx.G(),
		minder,
		auOverride,
		team,
		a.url.Repo,
		StorageOpts{},
	)
	a.storage = storage

	a.psr = storage.NewPackSyncRemote()

	return nil
}

func (a *Agent) runIO(mctx libclient.MetaContext) error {
	a.doneCh = make(chan struct{})
	a.blio = NewRpcBatchedLineIO(a.doneCh)
	return nil
}

func (a *Agent) newHelper(
	mctx libclient.MetaContext,
) (
	*remhelp.RemoteHelper, error,
) {
	var ps *remhelp.PackSync
	var err error
	lcd := a.lcd

	if a.psr != nil {
		ps, err = remhelp.NewPackSyncFromPath(
			a.remoteNameFixed,
			a.psr,
			lcd,
			a.tl,
		)
		if err != nil {
			return nil, err
		}
	}

	sw, err := remhelp.NewStorageWrapper(
		a.storage,
		a.remoteNameFixed,
		a.rawURL,
		ps,
		lcd,
	)
	if err != nil {
		return nil, err
	}

	thresh := mctx.G().Cfg().GitRepackThreshhold()
	helper, err := remhelp.NewRemoteHelper(
		a.blio,
		sw,
		remhelp.RemoteHelperOptions{
			DbgLog:           NewDbgLogger(mctx),
			RepackThreshhold: int(thresh),
			TermLog:          a.tl,
		},
	)
	if err != nil {
		return nil, err
	}
	return helper, nil
}

func (a *Agent) run(mctx libclient.MetaContext) error {
	helper, err := a.newHelper(mctx)
	if err != nil {
		return err
	}
	dur, err := mctx.G().Cfg().GitTimeoutDuration()
	if err != nil {
		return err
	}
	mctx.Infow("git Agent.run", "timeout", dur.String())

	go func() {
		// Don't let the Git session run for longer than 10 minutes
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		err := helper.Run(ctx)
		if err != nil {
			mctx.Errorw("git helper.Run", "err", err)
		}
		close(a.doneCh)
	}()

	return nil
}

func (a *Agent) Init(mctx libclient.MetaContext) (err error) {
	a.tl.Log(mctx.Ctx(), remhelp.TermLogNoNewline.ToMsg("🦊 Initializing FOKS ... "))

	defer func() {
		msg := core.Sel(err == nil,
			"✅ done",
			fmt.Sprintf("❌ failed: %v", err),
		)
		a.tl.Log(mctx.Ctx(), remhelp.TermLogStd.ToMsg(msg))
	}()

	err = a.argvToGitURL()
	if err != nil {
		return err
	}
	err = a.initStorage(mctx)
	if err != nil {
		return err
	}
	err = a.initFixedName(mctx)
	if err != nil {
		return err
	}
	err = a.runIO(mctx)
	if err != nil {
		return err
	}
	err = a.run(mctx)
	if err != nil {
		return err
	}
	return nil
}
