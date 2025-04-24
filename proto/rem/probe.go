// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/rem/probe.snowp

package rem

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type ProbeRes struct {
	MerkleRoot lib.SignedMerkleRoot
	Zone       lib.SignedPublicZone
	Hostchain  []lib.HostchainLinkOuter
}

type ProbeResInternal__ struct {
	_struct    struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	MerkleRoot *lib.SignedMerkleRootInternal__
	Zone       *lib.SignedPublicZoneInternal__
	Hostchain  *[](*lib.HostchainLinkOuterInternal__)
}

func (p ProbeResInternal__) Import() ProbeRes {
	return ProbeRes{
		MerkleRoot: (func(x *lib.SignedMerkleRootInternal__) (ret lib.SignedMerkleRoot) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.MerkleRoot),
		Zone: (func(x *lib.SignedPublicZoneInternal__) (ret lib.SignedPublicZone) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Zone),
		Hostchain: (func(x *[](*lib.HostchainLinkOuterInternal__)) (ret []lib.HostchainLinkOuter) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]lib.HostchainLinkOuter, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *lib.HostchainLinkOuterInternal__) (ret lib.HostchainLinkOuter) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(p.Hostchain),
	}
}

func (p ProbeRes) Export() *ProbeResInternal__ {
	return &ProbeResInternal__{
		MerkleRoot: p.MerkleRoot.Export(),
		Zone:       p.Zone.Export(),
		Hostchain: (func(x []lib.HostchainLinkOuter) *[](*lib.HostchainLinkOuterInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*lib.HostchainLinkOuterInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(p.Hostchain),
	}
}

func (p *ProbeRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ProbeRes) Decode(dec rpc.Decoder) error {
	var tmp ProbeResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

var ProbeResTypeUniqueID = rpc.TypeUniqueID(0xe5d58d6f85e92a64)

func (p *ProbeRes) GetTypeUniqueID() rpc.TypeUniqueID {
	return ProbeResTypeUniqueID
}

func (p *ProbeRes) Bytes() []byte { return nil }

var ProbeProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xc5884ff6)

type ProbeArg struct {
	Hostname           lib.Hostname
	HostchainLastSeqno lib.Seqno
	HostID             *lib.HostID
}

type ProbeArgInternal__ struct {
	_struct            struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Hostname           *lib.HostnameInternal__
	HostchainLastSeqno *lib.SeqnoInternal__
	HostID             *lib.HostIDInternal__
}

func (p ProbeArgInternal__) Import() ProbeArg {
	return ProbeArg{
		Hostname: (func(x *lib.HostnameInternal__) (ret lib.Hostname) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.Hostname),
		HostchainLastSeqno: (func(x *lib.SeqnoInternal__) (ret lib.Seqno) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(p.HostchainLastSeqno),
		HostID: (func(x *lib.HostIDInternal__) *lib.HostID {
			if x == nil {
				return nil
			}
			tmp := (func(x *lib.HostIDInternal__) (ret lib.HostID) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(x)
			return &tmp
		})(p.HostID),
	}
}

func (p ProbeArg) Export() *ProbeArgInternal__ {
	return &ProbeArgInternal__{
		Hostname:           p.Hostname.Export(),
		HostchainLastSeqno: p.HostchainLastSeqno.Export(),
		HostID: (func(x *lib.HostID) *lib.HostIDInternal__ {
			if x == nil {
				return nil
			}
			return (*x).Export()
		})(p.HostID),
	}
}

func (p *ProbeArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(p.Export())
}

func (p *ProbeArg) Decode(dec rpc.Decoder) error {
	var tmp ProbeArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*p = tmp.Import()
	return nil
}

func (p *ProbeArg) Bytes() []byte { return nil }

type ProbeInterface interface {
	Probe(context.Context, ProbeArg) (ProbeRes, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h lib.Header) error

	MakeResHeader() lib.Header
}

func ProbeMakeGenericErrorWrapper(f ProbeErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type ProbeErrorUnwrapper func(lib.Status) error
type ProbeErrorWrapper func(error) lib.Status

type probeErrorUnwrapperAdapter struct {
	h ProbeErrorUnwrapper
}

func (p probeErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (p probeErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return p.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = probeErrorUnwrapperAdapter{}

type ProbeClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper ProbeErrorUnwrapper
	MakeArgHeader  func() lib.Header
	CheckResHeader func(context.Context, lib.Header) error
}

func (c ProbeClient) Probe(ctx context.Context, arg ProbeArg) (res ProbeRes, err error) {
	warg := &rpc.DataWrap[lib.Header, *ProbeArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[lib.Header, ProbeResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(ProbeProtocolID, 1, "Probe.probe"), warg, &tmp, 0*time.Millisecond, probeErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = tmp.Data.Import()
	return
}

func ProbeProtocol(i ProbeInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Probe",
		ID:   ProbeProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[lib.Header, *ProbeArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[lib.Header, *ProbeArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[lib.Header, *ProbeArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.Probe(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[lib.Header, *ProbeResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "probe",
			},
		},
		WrapError: ProbeMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(ProbeResTypeUniqueID)
	rpc.AddUnique(ProbeProtocolID)
}
