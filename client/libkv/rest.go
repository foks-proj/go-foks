package libkv

import (
	"io"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
)

type Rester interface {
	Put(m MetaContext, path proto.KVPath, rdr io.Reader) error
	Get(m MetaContext, path proto.KVPath) (io.ReadCloser, error)
	Delete(m MetaContext, path proto.KVPath) error
}

type RestServer struct {
}

func (r *RestServer) Start(
	m libclient.MetaContext,
	arg lcl.ClientKVRestStartArg,
) error {
	return core.NotImplementedError{}
}
