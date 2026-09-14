// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"time"

	"github.com/foks-proj/go-foks/lib/core"
)

type BgUserRefresh struct {
	cfg BgTiming
}

func NewBgUserRefresh(c BgTiming) *BgUserRefresh {
	return &BgUserRefresh{
		cfg: c,
	}
}

func (b *BgUserRefresh) Priority() BgPriority {
	return 1
}

func (b *BgUserRefresh) Reschedule() time.Duration {
	return b.cfg.Sleep()
}

func (b *BgUserRefresh) refresh(m MetaContext, uc *UserContext) error {

	m = m.WithLogTag("bgop")

	fqus, _ := uc.FQU().StringErr()

	// If the agent started while offline, this user's keys were never
	// unlocked; Reconnect does that once the home server is reachable again.
	err := uc.Reconnect(m)
	if err != nil {
		m.Warnw("BgUserRefresh.refresh", "stage", "reconnect", "fqu", fqus, "err", err)
		return err
	}

	uw, err := LoadMe(m, uc)
	if err != nil {
		m.Warnw("BgUserRefresh.refresh", "stage", "loadme", "fqu", fqus, "err", err)
	}

	// We'll get an AuthError if we're unauthorized to log in. This can happen
	// after revocation, in which case, we'll have to load the user as a guest.
	if core.IsAuthError(err) {
		err = nil
	}

	if err != nil {
		return err
	}

	revoked, err := ClearOnRevoke(m, uc, uw)
	if err != nil {
		return err
	}
	if revoked {
		return nil
	}

	rotated, err := RotateStalePUKs(m, uc, uw)
	if err != nil {
		return err
	}

	// If we did rotate, then roload the userWrapper object,
	// since we'll have new PUKs
	if rotated {
		uw, err = LoadMe(m, uc)
		if err != nil {
			return err
		}
	}

	err = BgRefreshPassphraseEncryption(m, uc, uw)
	if err != nil {
		return err
	}

	err = BgRotateYubiManagementKey(m, uc, uw)
	if err != nil {
		return err
	}

	return nil
}

func (b *BgUserRefresh) Perform(m MetaContext) error {
	users := m.G().AllUsers()
	var ret error
	for i, u := range users {
		err := b.refresh(m, u)
		if err != nil {
			m.Warnw("BgUserRefresh.Perform", "stage", "perform", "err", err)
			ret = err
		}
		d := b.cfg.Pause()
		m.Infow("BgUserRefresh.Perform", "stage", "wait", "waiting", d, "iter", i)
		select {
		case <-m.Ctx().Done():
			err := m.Ctx().Err()
			m.Warnw("BgUserRefresh.Perform", "stage", "wait", "err", err)
			if ret == nil {
				ret = err
			}
		case <-time.After(d):
		}
	}
	return ret
}

func (b *BgUserRefresh) Type() BgJobType {
	return BgJobTypeUserRefresh
}

func (b *BgUserRefresh) Name() string {
	return "userRefresh"
}

var _ BgJobber = (*BgUserRefresh)(nil)
