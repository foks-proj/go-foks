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
	maxDeviceKeyLen = 64
)

// SetPushToken upserts the caller's push token. The row is keyed by the
// AUTHENTICATED uid + the caller-supplied device verify-key id (a
// namespacing hint, never trusted for anything beyond splitting a user's
// own rows). enabled=false is the opt-out: the relay only targets
// enabled tokens.
func SetPushToken(m shared.MetaContext, arg rem.RtSetPushTokenArg) error {
	if arg.Platform != "apns" && arg.Platform != "fcm" {
		return core.BadArgsError("platform must be apns or fcm")
	}
	if len(arg.Token) == 0 || len(arg.Token) > maxPushTokenLen {
		return core.BadArgsError("bad token length")
	}
	if len(arg.DeviceKey) == 0 || len(arg.DeviceKey) > maxDeviceKeyLen {
		return core.BadArgsError("bad deviceKey length")
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
		arg.DeviceKey,
		string(arg.Platform),
		[]byte(arg.Token),
		arg.Enabled,
	)
	return err
}
