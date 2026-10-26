package realtime

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/stretchr/testify/require"
)

// Every message type wakes a phone except Edit and Delete. Iterating the
// generated map means a type added to the enum later lands on the waking
// side, and fails here only if someone decides it should not.
func TestTypeWakesPhone(t *testing.T) {
	silent := map[proto.RTMsgType]bool{
		proto.RTMsgType_Edit:   true,
		proto.RTMsgType_Delete: true,
	}
	require.NotEmpty(t, proto.RTMsgTypeRevMap)
	for typ, name := range proto.RTMsgTypeRevMap {
		require.Equal(t, !silent[typ], typeWakesPhone(typ), name)
	}
}
