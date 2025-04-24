// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"errors"
	"testing"
	"time"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/keybase/clockwork"
	"github.com/stretchr/testify/require"
)

func TestAutocertSwitchboardSimple(t *testing.T) {
	cl := clockwork.NewFakeClock()
	brd := NewAutocertSwitchboard().WithClock(cl)

	good := AutocertHost{
		Hostname: proto.Hostname("good.com"),
		Stype:    proto.ServerType_Probe,
	}
	bad := AutocertHost{
		Hostname: proto.Hostname("bad.evil"),
		Stype:    proto.ServerType_Probe,
	}
	ctx := context.Background()

	err := brd.Broadcast(ctx, good, nil)
	require.NoError(t, err)

	err = brd.Wait(ctx, good, time.Hour)
	require.NoError(t, err)
	baderr := errors.New("my error")

	err = brd.Broadcast(ctx, bad, baderr)
	require.NoError(t, err)

	err = brd.Wait(ctx, bad, time.Hour)
	require.Error(t, err)
	require.Equal(t, baderr, err)

	multiTest := func(hn proto.Hostname, res error) {

		doneCh := make(chan struct{})
		n := 4
		key := AutocertHost{
			Hostname: hn,
			Stype:    proto.ServerType_Probe,
		}
		for i := 0; i < n; i++ {
			go func() {
				err := brd.Wait(ctx, key, time.Hour)
				require.Equal(t, res, err)
				doneCh <- struct{}{}
			}()
		}

		err = brd.Broadcast(ctx, key, res)
		require.NoError(t, err)
		for i := 0; i < n; i++ {
			<-doneCh
		}
	}

	multiTest(proto.Hostname("yet.to.com"), nil)
	multiTest(proto.Hostname("beenz.com"), errors.New("not enough beenz"))
}
