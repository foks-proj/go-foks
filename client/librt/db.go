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

	args := make([]libclient.PutArg, 0, len(v))
	for _, x := range v {
		idx := int64(x.Seq)
		// Store the whole RTMsgCached (noncer + wrapper + server-insert-time)
		// under one key; dbGetMsgs decodes RTThreadMsgData back into RTMsgCached.
		args = append(args,
			libclient.PutArg{
				Scope: &scope,
				Typ:   lcl.DataType_RTThreadMsgData,
				Key:   x.Cm.Md.Chid,
				Val:   &x.Cm,
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

func dbGetMsgsHelper(
	m MetaContext,
	au *libclient.UserContext,
	chid proto.RTChannelID,
	f func(rng *libclient.DBRange[proto.RTMsgCached, *proto.RTMsgCached]) (
		[]proto.RTMsgCached,
		[]int64,
		error,
	),
) (
	[]proto.RTMsgCachedWithSeq,
	error,
) {
	db, err := m.G().Db(m.Ctx(), libclient.DbTypeSoft)
	if err != nil {
		return nil, err
	}
	scope := au.FQParty()
	rng, err := libclient.NewDBRange[proto.RTMsgCached](
		m.Base(),
		db,
		&scope,
		lcl.DataType_RTThreadMsgData,
		chid,
	)
	if err != nil {
		return nil, err
	}
	msgs, idx, err := f(rng)
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

func dbGetMsgs(
	m MetaContext,
	au *libclient.UserContext,
	chid proto.RTChannelID,
	start proto.RTMsgSeq,
	end proto.RTMsgSeq,
) (
	[]proto.RTMsgCachedWithSeq,
	error,
) {
	return dbGetMsgsHelper(m, au, chid,
		func(rng *libclient.DBRange[proto.RTMsgCached, *proto.RTMsgCached]) (
			[]proto.RTMsgCached,
			[]int64,
			error,
		) {
			return rng.Get(
				m.Base(),
				start.Int64(),
				end.Int64(),
			)
		},
	)
}

func dbGetLastMsg(
	m MetaContext,
	au *libclient.UserContext,
	chid proto.RTChannelID,
) (
	*proto.RTMsgCachedWithSeq,
	error,
) {
	tmp, err := dbGetRecentMsgs(m, au, chid, 1)
	if err != nil {
		return nil, err
	}
	if len(tmp) < 1 {
		return nil, nil
	}
	return &tmp[0], nil

}

func dbGetRecentMsgs(
	m MetaContext,
	au *libclient.UserContext,
	chid proto.RTChannelID,
	num uint,
) (
	[]proto.RTMsgCachedWithSeq,
	error,
) {
	return dbGetMsgsHelper(m, au, chid,
		func(rng *libclient.DBRange[proto.RTMsgCached, *proto.RTMsgCached]) (
			[]proto.RTMsgCached,
			[]int64,
			error,
		) {
			return rng.GetNMax(
				m.Base(),
				int64(num),
			)

		},
	)
}
