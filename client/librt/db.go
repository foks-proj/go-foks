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
