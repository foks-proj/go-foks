package cli

import (
	"testing"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/integration-tests/common"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

func TestKeyRemove(t *testing.T) {
	defer common.DebugEntryAndExit()()
	stopper := runMerkleActivePoker(t)
	defer stopper()

	x := newTestAgent(t)
	x.runAgent(t)
	defer x.stop(t)
	name := proto.DeviceName("device A.1")
	vh := vHost(t, 1)
	signupUi := newMockSignupUI().withDeviceName(name).withServer(vh.Addr)
	x.runCmdWithUIs(t, libclient.UIs{Signup: signupUi}, "--simple-ui", "signup")
	var klres lcl.KeyListRes
	x.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 1, len(klres.AllUsers))
	require.Equal(t, 1, len(klres.CurrUserAllKeys))
	yubiKeyID := klres.CurrUserAllKeys[0].Di.Key.Member.Id.Entity
	yubiKeyIDStr, err := yubiKeyID.StringErr()
	require.NoError(t, err)
	fqu := klres.AllUsers[0].Info.Fqu
	fqus, err := fqu.StringErr()
	require.NoError(t, err)

	x.runCmd(t, nil, "key", "dev", "perm", "--name", "device B.2")

	x.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 2, len(klres.AllUsers))
	require.Equal(t, 2, len(klres.CurrUserAllKeys))

	x.runCmd(t, nil, "key", "remove", "--user", fqus, "--key-id", yubiKeyIDStr)

	x.runCmdToJSON(t, &klres, "key", "list")
	require.Equal(t, 1, len(klres.AllUsers))
	require.Equal(t, 2, len(klres.CurrUserAllKeys))
	devKeyID := klres.AllUsers[0].Info.Key
	devKeyIDStr, err := devKeyID.StringErr()
	require.NoError(t, err)

	require.NotEqual(t, yubiKeyIDStr, devKeyIDStr)
	err = x.runCmdErr(nil, "key", "remove", "--user", fqus, "--key-id", devKeyIDStr)
	require.Error(t, err)
	require.Equal(t, core.BadArgsError("cannot remove device key"), err)
}
