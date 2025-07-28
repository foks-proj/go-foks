package core

import (
	"fmt"
	"strings"

	lcl "github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

const botTokenNameBytes = 3

type BotToken struct {
	name string
	key  string
	seed proto.BotTokenSeed
}

func (b *BotToken) FromSeed(s proto.BotTokenSeed) error {
	copy(b.seed[:], s[:])
	return b.fillStrings()
}

func (b *BotToken) fillStrings() error {
	n := botTokenNameBytes
	b.name = B36Encode(b.seed[0:n])
	b.key = B62Encode(b.seed[n:])
	return nil
}

func GenerateBotTokenSeed() (*proto.BotTokenSeed, error) {
	var ret proto.BotTokenSeed
	err := RandomFill(ret[:])
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func NewBotToken() (*BotToken, error) {
	seed, err := GenerateBotTokenSeed()
	if err != nil {
		return nil, err
	}
	ret := &BotToken{seed: *seed}
	err = ret.fillStrings()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (b *BotToken) SeedBytes() int { return 23 }

func (b *BotToken) Import(s lcl.BotTokenString) error {
	parts := strings.Split(string(s), ".")
	if len(parts) != 2 {
		return BotTokenError("expected 'name.key' formatting")
	}
	name, err := B36Decode(parts[0])
	if err != nil {
		return BotTokenError("invalid name part: " + err.Error())
	}
	if len(name) != botTokenNameBytes {
		return BotTokenError("name part must be exactly 3 bytes long")
	}
	key, err := B62Decode(parts[1])
	if err != nil {
		return BotTokenError("invalid key part: " + err.Error())
	}
	keyLen := len(b.seed) - botTokenNameBytes
	if len(key) != keyLen {
		return BotTokenError(fmt.Sprintf("key part must be exactly %d bytes long", keyLen))
	}
	copy(b.seed[0:botTokenNameBytes], name)
	copy(b.seed[botTokenNameBytes:], key)
	b.name = parts[0]
	b.key = parts[1]

	return nil
}

func (b *BotToken) Name() proto.DeviceName {
	return proto.DeviceName(b.name)
}

func (b *BotToken) SecretSeed32(out *proto.SecretSeed32) error {
	return PrefixedHashInto(&b.seed, (*out)[:])
}

func (k *BotToken) Export() (lcl.BotTokenString, error) {
	err := k.fillStrings()
	if err != nil {
		return "", err
	}
	return lcl.BotTokenString(fmt.Sprintf("%s.%s", k.name, k.key)), nil
}

func (k *BotToken) KeySuite(
	role proto.Role,
	hid proto.HostID,
) (
	*PrivateSuite25519,
	error,
) {
	var ss proto.SecretSeed32
	err := k.SecretSeed32(&ss)
	if err != nil {
		return nil, err
	}
	return NewPrivateSuite25519(proto.EntityType_BotTokenKey, role, ss, hid)
}

func (k *BotToken) DeviceLabelAndName() (
	*proto.DeviceLabelAndName,
	error,
) {
	if len(k.name) == 0 {
		return nil, InternalError("name for BotToken is empty")
	}
	nm := k.Name()
	nnm, err := NormalizeDeviceName(nm)
	if err != nil {
		return nil, err
	}
	return &proto.DeviceLabelAndName{
		Label: proto.DeviceLabel{
			DeviceType: proto.DeviceType_BotToken,
			Name:       nnm,
			Serial:     proto.FirstDeviceSerial,
		},
		Nv:   proto.NormalizationVersion_V0,
		Name: nm,
	}, nil
}

func ValidateBotTokenString(s lcl.BotTokenString) error {
	var tmp BotToken
	return tmp.Import(s)
}
