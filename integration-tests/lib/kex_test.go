// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"context"
	"testing"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func newKexClient(ctx context.Context) (*rem.KexClient, func(), error) {
	m := shared.NewMetaContext(ctx, G)
	gcli, fn, err := newGenericClient(m, globalTestEnv.RegSrv(), nil, nil)
	if err != nil {
		return nil, fn, err
	}
	cli := rem.KexClient{Cli: gcli, ErrorUnwrapper: core.StatusToError}
	return &cli, fn, err
}

func randomDeviceID(t *testing.T) proto.DeviceID {
	b := make([]byte, 32)
	err := core.RandomFill(b)
	require.NoError(t, err)
	eid, err := proto.EntityType_Device.MakeEntityID(b)
	require.NoError(t, err)
	return proto.DeviceID(eid)
}

func TestKexSendAndReceive(t *testing.T) {
	ctx := context.Background()
	cli, closeFn, err := newKexClient(ctx)
	require.NoError(t, err)
	defer closeFn()

	epriv, err := core.NewEntityPrivateEd25519(proto.EntityType_Device)
	require.NoError(t, err)
	epub, err := epriv.EntityPublic()
	require.NoError(t, err)

	var secret proto.HMACKey
	err = core.RandomFill(secret[:])
	require.NoError(t, err)
	deriv := lcl.NewKexKeyDerivationDefault(lcl.KexDerivationType_SessionID)
	sessionIdRaw, err := core.Hmac(&deriv, &secret)
	require.NoError(t, err)
	sessionId := proto.KexSessionID(*sessionIdRaw)
	nbox := proto.NaclSecretBox{}
	err = core.RandomFill(nbox.Nonce[:])
	require.NoError(t, err)
	nbox.Ciphertext = proto.NaclCiphertext([]byte{0x1, 0x2, 0x3, 0x4})
	sbox := proto.NewSecretBoxWithNacl(nbox)
	wmsg := rem.KexWrapperMsg{
		SessionID: sessionId,
		Sender:    epub.GetEntityID(),
		Seq:       proto.KexSeqNo(0),
		Payload:   sbox,
	}

	sig, err := epriv.Sign(&wmsg)
	require.NoError(t, err)

	sendArg := rem.SendArg{
		Msg:   wmsg,
		Sig:   *sig,
		Actor: rem.KexActorType_Provisionee,
	}

	err = cli.Send(ctx, sendArg)
	require.NoError(t, err)

	receiver := randomDeviceID(t)

	rarg := rem.ReceiveArg{
		SessionID: sessionId,
		Receiver:  proto.EntityID(receiver),
		Seq:       proto.KexSeqNo(0),
		PollWait:  10 * 1000,
		Actor:     rem.KexActorType_Provisioner,
	}
	receivedMsg, err := cli.Receive(ctx, rarg)
	require.NoError(t, err)
	require.Equal(t, wmsg, receivedMsg)

	rarg.Seq++
	ch := make(chan rem.KexWrapperMsg)
	go func() {
		msg, err := cli.Receive(ctx, rarg)
		require.NoError(t, err)
		ch <- msg
	}()

	wmsg.Seq++
	sig, err = epriv.Sign(&wmsg)
	require.NoError(t, err)

	sendArg = rem.SendArg{
		Msg:   wmsg,
		Sig:   *sig,
		Actor: rem.KexActorType_Provisionee,
	}

	err = cli.Send(ctx, sendArg)
	require.NoError(t, err)

	receivedMsg = <-ch
	require.Equal(t, wmsg, receivedMsg)
}
