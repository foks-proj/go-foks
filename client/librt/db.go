package librt

import (
	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

func dbPutMsgs(
	m MetaContext,
	au *libclient.UserContext,
	v []proto.RTMsgCachedWithSeq,
) error {
	if au == nil {
		return core.NoActiveUserError{}
	}
	scope := au.FQParty()

	args := make([]libclient.PutArg, 0, 2*len(v))
	for _, x := range v {
		idx := int64(x.Seq)
		args = append(args,
			libclient.PutArg{
				Scope: &scope,
				Typ:   lcl.DataType_RTThreadMetadata,
				Key:   x.Cm.Md.Chid,
				Val:   &x.Cm.Md,
				Idx:   &idx,
			},
			libclient.PutArg{
				Scope: &scope,
				Typ:   lcl.DataType_RTThreadMsgData,
				Key:   x.Cm.Md.Chid,
				Val:   &x.Cm.Mw,
				Idx:   &idx,
			},
		)
	}

	err := m.DbPutTx(
		libclient.DbTypeSoft,
		args,
	)
	if err != nil {
		return err
	}
	return nil
}

func dbPutMsgToOutbox(
	m MetaContext,
	au *libclient.UserContext,
	row proto.RTMsgCached,
) error {
	if au == nil {
		return core.NoActiveUserError{}
	}
	scope := au.FQParty()
	sentAt := row.Md.Md.SendTime.ToInt64()
	err := m.DbPut(
		libclient.DbTypeSoft,
		libclient.PutArg{
			Scope: &scope,
			Typ:   lcl.DataType_RTOutboxMsg,
			Key:   row.Md.Chid,
			Val:   &row,
			Idx:   &sentAt,
		},
	)
	if err != nil {
		return err
	}
	return nil
}

func dbGetMsgs(
	m MetaContext,
	au *libclient.UserContext,
	chid proto.RTChannelID,
	lo proto.RTMsgSeq,
	hi proto.RTMsgSeq,
	lim uint,
	direction proto.RTThreadDir,
) (
	[]proto.RTMsgCachedWithSeq,
	error,
) {
	db, err := m.G().Db(m.Ctx(), libclient.DbTypeSoft)
	if err != nil {
		return nil, err
	}
	scope := au.FQParty()
	rng, err := libclient.NewDBRange[proto.RTMsgCached, *proto.RTMsgCached](
		m.Base(),
		db,
		&scope,
		lcl.DataType_RTThreadMetadata,
		chid,
	)
	if err != nil {
		return nil, err
	}
	msgs, idx, err := rng.Get(
		m.Base(),
		int64(lo),
		int64(hi),
		int64(lim),
		direction.IsAscending(),
	)
	if err != nil {
		return nil, err
	}

	// Now zip the indices back into the results, as they were returned
	// in a parallel list.
	ret := make([]proto.RTMsgCachedWithSeq, len(msgs))
	for i, msg := range msgs {
		ret[i] = proto.RTMsgCachedWithSeq{
			Cm:  msg,
			Seq: proto.RTMsgSeq(idx[i]),
		}
	}

	return ret, nil
}
