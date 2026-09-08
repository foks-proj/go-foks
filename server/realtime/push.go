package realtime

// Device push-token registration: store or refresh a token for the
// authenticated user, so a push server can find the devices to wake.

import (
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
)

const (
	maxPushTokenLen = 256 // APNs tokens are 32 bytes; FCM ~140 chars
)

// SetPushToken upserts the caller's push token. The row is keyed by the
// AUTHENTICATED uid + the caller-supplied device verify-key EntityID (a
// namespacing hint, never trusted for anything beyond splitting a user's
// own rows -- but it must at least parse as a device key). enabled=false
// is the opt-out: the relay only targets enabled tokens.
func SetPushToken(m shared.MetaContext, arg rem.RtSetPushTokenArg) error {
	platform, err := arg.Platform.ExportToDB()
	if err != nil {
		return core.BadArgsError("bad platform")
	}
	if len(arg.Token) == 0 || len(arg.Token) > maxPushTokenLen {
		return core.BadArgsError("bad token length")
	}
	// The EntityID's leading byte and length must say "device verify key";
	// anything else is a malformed registration, not a namespacing hint.
	if _, err := arg.DeviceKey.ToDeviceID(); err != nil {
		return core.BadArgsError("deviceKey must be a device verify-key EntityID")
	}
	rtdb, err := m.Db(shared.DbTypeRealTime)
	if err != nil {
		return err
	}
	defer rtdb.Release()
	_, err = rtdb.Exec(
		m.Ctx(),
		`INSERT INTO push_tokens
		   (short_host_id, uid, device_verify_key, platform, token, enabled, ctime, mtime)
		 VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		 ON CONFLICT (short_host_id, uid, device_verify_key)
		 DO UPDATE SET platform=$4, token=$5, enabled=$6, mtime=NOW()`,
		m.ShortHostID(),
		m.UID().ExportToDB(),
		arg.DeviceKey.ExportToDB(),
		platform,
		[]byte(arg.Token),
		arg.Enabled,
	)
	return err
}
