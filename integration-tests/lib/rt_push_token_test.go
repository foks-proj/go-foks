// rtSetPushToken registers/refreshes the authenticated user's device
// push token, and
// enabled=false is the opt-out. Rows are scoped to the authenticated uid
// regardless of the caller-supplied device-key namespacing hint.
package lib

import (
	"testing"

	"github.com/foks-proj/go-foks/client/librt"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func TestRTSetPushToken(t *testing.T) {
	tew := testEnvBeta(t)
	bluey := tew.NewTestUser(t)
	tew.DirectDoubleMerklePokeInTest(t)

	mb := librt.NewMetaContext(tew.NewClientMetaContextWithEracer(t, bluey))
	minder := librt.NewMinder(mb.G().ActiveUser())

	token := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	require.NoError(t, minder.SetPushToken(mb, "apns", token, true))

	m := tew.MetaContext()
	rtdb, err := m.Db(shared.DbTypeRealTime)
	require.NoError(t, err)
	defer rtdb.Release()

	var enabled bool
	var stored []byte
	row := rtdb.QueryRow(m.Ctx(),
		`SELECT enabled, token FROM push_tokens WHERE uid=$1`,
		mb.G().ActiveUser().UID().ExportToDB())
	require.NoError(t, row.Scan(&enabled, &stored))
	require.True(t, enabled)
	require.Equal(t, token, stored)

	// Refresh with a new token value (same device → same row).
	token2 := []byte{0x11, 0x22}
	require.NoError(t, minder.SetPushToken(mb, "apns", token2, true))
	// Opt out.
	require.NoError(t, minder.SetPushToken(mb, "apns", token2, false))

	var count int
	require.NoError(t, rtdb.QueryRow(m.Ctx(),
		`SELECT count(*) FROM push_tokens WHERE uid=$1`,
		mb.G().ActiveUser().UID().ExportToDB()).Scan(&count))
	require.Equal(t, 1, count)

	row = rtdb.QueryRow(m.Ctx(),
		`SELECT enabled, token FROM push_tokens WHERE uid=$1`,
		mb.G().ActiveUser().UID().ExportToDB())
	require.NoError(t, row.Scan(&enabled, &stored))
	require.False(t, enabled)
	require.Equal(t, token2, stored)

	// Bad platform is rejected.
	require.Error(t, minder.SetPushToken(mb, "carrier-pigeon", token, true))
}
