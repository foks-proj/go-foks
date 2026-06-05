package librt

import (
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type KeyMgr struct {
	seed  proto.SecretSeed32
	appID proto.RTAppID
	gen   proto.Generation
	role  proto.Role
}

func (k *KeyMgr) deriveKeyForType(typ proto.RTKeyType) (*proto.SecretBoxKey, error) {
	deriv := proto.RTKeyDerivation{
		App: k.appID,
		Var: proto.NewRTKeyVarDefault(typ),
	}
	ss, err := core.GenericDeriveKey32(k.seed, &deriv)
	if err != nil {
		return nil, err
	}
	var ret proto.SecretBoxKey
	copy(ret[:], ss[:])
	return &ret, nil
}

func NewKeyMgr(
	s core.SharedPrivateSuiter,
	appID proto.RTAppID,
) (
	*KeyMgr,
	error,
) {
	k := s.AppKey()
	deriv := proto.NewAppKeyDerivationWithEnum(proto.AppKeyEnum_Realtime)
	ss32, err := core.GenericDeriveKey32(k, &deriv)
	if err != nil {
		return nil, err
	}
	return &KeyMgr{
		seed:  *ss32,
		appID: appID,
		gen:   s.Metadata().Gen,
		role:  s.GetRole(),
	}, nil
}

func (k *KeyMgr) KeyForType(typ proto.RTKeyType) (*proto.SecretBoxKey, error) {
	return k.deriveKeyForType(typ)
}

func (k *KeyMgr) ChannelNameKey() (*proto.SecretBoxKey, error) {
	return k.deriveKeyForType(proto.RTKeyType_ChannelName)
}

func (k *KeyMgr) ChannelDescKey() (*proto.SecretBoxKey, error) {
	return k.deriveKeyForType(proto.RTKeyType_ChannelDesc)
}

func (k *KeyMgr) DataKey() (*proto.SecretBoxKey, error) {
	return k.deriveKeyForType(proto.RTKeyType_Data)
}

func (k *KeyMgr) SealIntoSecretBox(
	typ proto.RTKeyType,
	dat core.CryptoPayloader,
) (
	*proto.RTBoxRG,
	error,
) {
	key, err := k.KeyForType(typ)
	if err != nil {
		return nil, err
	}
	box, err := core.SealIntoSecretBox(dat, key)
	if err != nil {
		return nil, err
	}
	var ret proto.RTBoxRG
	ret.Rg.Role = k.role
	ret.Rg.Gen = k.gen
	ret.Box = *box
	return &ret, nil
}

func (k *KeyMgr) OpenBox(
	out core.CryptoPayloader,
	box proto.SecretBox,
	typ proto.RTKeyType,
) error {
	key, err := k.KeyForType(typ)
	if err != nil {
		return err
	}
	err = core.OpenSecretBoxInto(out, box, key)
	if err != nil {
		return err
	}
	return nil
}
