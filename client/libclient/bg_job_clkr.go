// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"context"
	"time"
)

type BgCLKR struct {
	cfg BgTiming
}

func NewBgCLKR(c BgTiming) *BgCLKR {
	return &BgCLKR{
		cfg: c,
	}
}

func (b *BgCLKR) Type() BgJobType           { return BgJobTypeCLKR }
func (b *BgCLKR) Name() string              { return "CLKR" }
func (b *BgCLKR) Priority() BgPriority      { return 2 }
func (b *BgCLKR) Reschedule() time.Duration { return b.cfg.Sleep() }

func (b *BgCLKR) Perform(m MetaContext) error {
	// Reconnect (and unlock keys) if the agent started while offline;
	// otherwise the rotation below fails with "key not found" until restart.
	_, err := m.ActiveConnectedUser(nil)
	if err != nil {
		return err
	}
	tm, err := m.G().TeamMinder()
	if err != nil {
		return err
	}
	clkr := NewCLKR(tm, CLKROpts{
		WaitFn: func(ctx context.Context) error {
			tm := b.cfg.Pause()
			time.Sleep(tm)
			return nil
		},
	},
	)
	err = clkr.Run(m)
	if err != nil {
		return err
	}
	return nil
}

var _ BgJobber = (*BgCLKR)(nil)
