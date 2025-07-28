package core

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBotToken(t *testing.T) {
	var bt BotToken
	seed, err := GenerateBotTokenSeed()
	require.NoError(t, err)
	err = bt.FromSeed(*seed)
	require.NoError(t, err)
	bts, err := bt.Export()
	require.NoError(t, err)
	fmt.Printf("bot token: %s\n", bts)
	var bt2 BotToken
	err = bt2.Import(bts)
	require.NoError(t, err)
	require.Equal(t, bt.name, bt2.name)
	require.Equal(t, bt.key, bt2.key)
	require.Equal(t, bt.seed, bt2.seed)
}
