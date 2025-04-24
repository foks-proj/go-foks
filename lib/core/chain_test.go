// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"testing"

	proto "github.com/foks-proj/go-foks/proto/lib"
	rem "github.com/foks-proj/go-foks/proto/rem"
	"github.com/stretchr/testify/require"
)

func TestEldest(t *testing.T) {
	ss := RandomSecretSeed32()
	ownerRole := proto.NewRoleDefault(proto.RoleType_OWNER)
	host := RandomHostID()
	device, err := NewPrivateSuite25519(proto.EntityType_Device, ownerRole, ss, host)
	require.NoError(t, err)
	pukSs := RandomSecretSeed32()
	puk, err := NewSharedPrivateSuite25519(
		proto.EntityType_User,
		ownerRole,
		pukSs,
		proto.Generation(1),
		host,
	)
	require.NoError(t, err)
	root := proto.TreeRoot{
		Epno: 1000,
		Hash: RandomMerkleRootHash(),
	}
	deviceLabel := proto.DeviceLabel{
		DeviceType: proto.DeviceType_Computer,
		Name:       "macbook",
		Serial:     proto.FirstDeviceSerial,
	}
	un, err := RandomUsername(8)
	require.NoError(t, err)
	mel, err := MakeEldestLink(
		host,
		rem.NameCommitment{
			Name: proto.Name(un).Normalize(),
			Seq:  proto.FirstNameSeqno,
		},
		device,
		puk,
		deviceLabel,
		root,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, mel)

	hepks, err := ImportHEPKSet(mel.HEPKSet)
	require.NoError(t, err)

	link := mel.Link
	res, err := OpenEldestLink(link, hepks, host)
	require.NoError(t, err)
	require.NotNil(t, res)
	uid := res.Uid

	lv, err := link.GetV()
	require.NoError(t, err)
	require.Equal(t, proto.LinkVersion_V1, lv)
	lov1 := link.V1()
	lov1.Signatures[0], lov1.Signatures[1] = lov1.Signatures[1], lov1.Signatures[0]
	link2 := proto.NewLinkOuterWithV1(lov1)

	res2, err := OpenEldestLink(&link2, hepks, host)
	require.Error(t, err)
	require.IsType(t, VerifyError(""), err)
	require.Equal(t, VerifyError("signature verification failed"), err)
	require.Nil(t, res2)

	lov1.Signatures = lov1.Signatures[0:1]
	link2 = proto.NewLinkOuterWithV1(lov1)
	res2, err = OpenEldestLink(&link2, hepks, host)
	require.Error(t, err)
	require.IsType(t, VerifyError(""), err)
	require.Equal(t, VerifyError("wrong number of keys"), err)
	require.Nil(t, res2)

	mel, err = MakeEldestLink(
		host,
		rem.NameCommitment{
			Name: proto.Name(un).Normalize(),
			Seq:  proto.FirstNameSeqno,
		},
		device,
		puk,
		deviceLabel,
		root,
		nil,
	)
	require.NoError(t, err)

	// DeviceChange should be able to open up an eldest link.
	_, err = OpenDeviceChange(mel.Link, hepks, &uid, host)
	require.NoError(t, err)
}
