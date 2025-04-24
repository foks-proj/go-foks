// Auto-generated to Go types and interfaces using @foks-proj/snowpack-compiler 1.0.8 (git+https://github.com/foks-proj/node-snowpack-compiler.git)
//  Input file: ../../proto-src/lcl/git.snowp

package lcl

import (
	"context"
	"errors"
	"github.com/foks-proj/go-snowpack-rpc/rpc"
	"time"
)

import lib "github.com/foks-proj/go-foks/proto/lib"

type GitOpRes struct {
	Lines []string
}

type GitOpResInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Lines   *[](string)
}

func (g GitOpResInternal__) Import() GitOpRes {
	return GitOpRes{
		Lines: (func(x *[](string)) (ret []string) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]string, len(*x))
			for k, v := range *x {
				ret[k] = (func(x *string) (ret string) {
					if x == nil {
						return ret
					}
					return *x
				})(&v)
			}
			return ret
		})(g.Lines),
	}
}

func (g GitOpRes) Export() *GitOpResInternal__ {
	return &GitOpResInternal__{
		Lines: (func(x []string) *[](string) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](string), len(x))
			copy(ret, x)
			return &ret
		})(g.Lines),
	}
}

func (g *GitOpRes) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitOpRes) Decode(dec rpc.Decoder) error {
	var tmp GitOpResInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitOpRes) Bytes() []byte { return nil }

var GitHelperProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x80c74702)

type GitInitArg struct {
	Argv   []string
	Wd     lib.LocalFSPath
	GitDir lib.LocalFSPath
}

type GitInitArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Argv    *[](string)
	Wd      *lib.LocalFSPathInternal__
	GitDir  *lib.LocalFSPathInternal__
}

func (g GitInitArgInternal__) Import() GitInitArg {
	return GitInitArg{
		Argv: (func(x *[](string)) (ret []string) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]string, len(*x))
			for k, v := range *x {
				ret[k] = (func(x *string) (ret string) {
					if x == nil {
						return ret
					}
					return *x
				})(&v)
			}
			return ret
		})(g.Argv),
		Wd: (func(x *lib.LocalFSPathInternal__) (ret lib.LocalFSPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Wd),
		GitDir: (func(x *lib.LocalFSPathInternal__) (ret lib.LocalFSPath) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.GitDir),
	}
}

func (g GitInitArg) Export() *GitInitArgInternal__ {
	return &GitInitArgInternal__{
		Argv: (func(x []string) *[](string) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](string), len(x))
			copy(ret, x)
			return &ret
		})(g.Argv),
		Wd:     g.Wd.Export(),
		GitDir: g.GitDir.Export(),
	}
}

func (g *GitInitArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitInitArg) Decode(dec rpc.Decoder) error {
	var tmp GitInitArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitInitArg) Bytes() []byte { return nil }

type GitOpArg struct {
	Line string
}

type GitOpArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Line    *string
}

func (g GitOpArgInternal__) Import() GitOpArg {
	return GitOpArg{
		Line: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(g.Line),
	}
}

func (g GitOpArg) Export() *GitOpArgInternal__ {
	return &GitOpArgInternal__{
		Line: &g.Line,
	}
}

func (g *GitOpArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitOpArg) Decode(dec rpc.Decoder) error {
	var tmp GitOpArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitOpArg) Bytes() []byte { return nil }

type GitHelperInterface interface {
	GitInit(context.Context, GitInitArg) error
	GitOp(context.Context, string) (GitOpRes, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error

	MakeResHeader() Header
}

func GitHelperMakeGenericErrorWrapper(f GitHelperErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type GitHelperErrorUnwrapper func(lib.Status) error
type GitHelperErrorWrapper func(error) lib.Status

type gitHelperErrorUnwrapperAdapter struct {
	h GitHelperErrorUnwrapper
}

func (g gitHelperErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (g gitHelperErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return g.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = gitHelperErrorUnwrapperAdapter{}

type GitHelperClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper GitHelperErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c GitHelperClient) GitInit(ctx context.Context, arg GitInitArg) (err error) {
	warg := &rpc.DataWrap[Header, *GitInitArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, interface{}]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GitHelperProtocolID, 0, "GitHelper.gitInit"), warg, &tmp, 0*time.Millisecond, gitHelperErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	return
}

func (c GitHelperClient) GitOp(ctx context.Context, line string) (res GitOpRes, err error) {
	arg := GitOpArg{
		Line: line,
	}
	warg := &rpc.DataWrap[Header, *GitOpArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, GitOpResInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GitHelperProtocolID, 1, "GitHelper.gitOp"), warg, &tmp, 0*time.Millisecond, gitHelperErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func GitHelperProtocol(i GitHelperInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "GitHelper",
		ID:   GitHelperProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GitInitArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GitInitArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GitInitArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						err := i.GitInit(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, interface{}]{
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "gitInit",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GitOpArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GitOpArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GitOpArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GitOp(ctx, (typedArg.Import()).Line)
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *GitOpResInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "gitOp",
			},
		},
		WrapError: GitHelperMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

var GitProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0xe40a37b2)

type GitCreateArg struct {
	Cfg KVConfig
	Nm  lib.GitRepo
}

type GitCreateArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
	Nm      *lib.GitRepoInternal__
}

func (g GitCreateArgInternal__) Import() GitCreateArg {
	return GitCreateArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Cfg),
		Nm: (func(x *lib.GitRepoInternal__) (ret lib.GitRepo) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Nm),
	}
}

func (g GitCreateArg) Export() *GitCreateArgInternal__ {
	return &GitCreateArgInternal__{
		Cfg: g.Cfg.Export(),
		Nm:  g.Nm.Export(),
	}
}

func (g *GitCreateArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitCreateArg) Decode(dec rpc.Decoder) error {
	var tmp GitCreateArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitCreateArg) Bytes() []byte { return nil }

type GitLsArg struct {
	Cfg KVConfig
}

type GitLsArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Cfg     *KVConfigInternal__
}

func (g GitLsArgInternal__) Import() GitLsArg {
	return GitLsArg{
		Cfg: (func(x *KVConfigInternal__) (ret KVConfig) {
			if x == nil {
				return ret
			}
			return x.Import()
		})(g.Cfg),
	}
}

func (g GitLsArg) Export() *GitLsArgInternal__ {
	return &GitLsArgInternal__{
		Cfg: g.Cfg.Export(),
	}
}

func (g *GitLsArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitLsArg) Decode(dec rpc.Decoder) error {
	var tmp GitLsArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitLsArg) Bytes() []byte { return nil }

type GitInterface interface {
	GitCreate(context.Context, GitCreateArg) (lib.GitURL, error)
	GitLs(context.Context, KVConfig) ([]lib.GitURL, error)
	ErrorWrapper() func(error) lib.Status
	CheckArgHeader(ctx context.Context, h Header) error

	MakeResHeader() Header
}

func GitMakeGenericErrorWrapper(f GitErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type GitErrorUnwrapper func(lib.Status) error
type GitErrorWrapper func(error) lib.Status

type gitErrorUnwrapperAdapter struct {
	h GitErrorUnwrapper
}

func (g gitErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (g gitErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return g.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = gitErrorUnwrapperAdapter{}

type GitClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper GitErrorUnwrapper
	MakeArgHeader  func() Header
	CheckResHeader func(context.Context, Header) error
}

func (c GitClient) GitCreate(ctx context.Context, arg GitCreateArg) (res lib.GitURL, err error) {
	warg := &rpc.DataWrap[Header, *GitCreateArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, lib.GitURLInternal__]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GitProtocolID, 0, "Git.gitCreate"), warg, &tmp, 0*time.Millisecond, gitErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
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

func (c GitClient) GitLs(ctx context.Context, cfg KVConfig) (res []lib.GitURL, err error) {
	arg := GitLsArg{
		Cfg: cfg,
	}
	warg := &rpc.DataWrap[Header, *GitLsArgInternal__]{
		Data: arg.Export(),
	}
	if c.MakeArgHeader != nil {
		warg.Header = c.MakeArgHeader()
	}
	var tmp rpc.DataWrap[Header, [](*lib.GitURLInternal__)]
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GitProtocolID, 1, "Git.gitLs"), warg, &tmp, 0*time.Millisecond, gitErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	if c.CheckResHeader != nil {
		err = c.CheckResHeader(ctx, tmp.Header)
		if err != nil {
			return
		}
	}
	res = (func(x *[](*lib.GitURLInternal__)) (ret []lib.GitURL) {
		if x == nil || len(*x) == 0 {
			return nil
		}
		ret = make([]lib.GitURL, len(*x))
		for k, v := range *x {
			if v == nil {
				continue
			}
			ret[k] = (func(x *lib.GitURLInternal__) (ret lib.GitURL) {
				if x == nil {
					return ret
				}
				return x.Import()
			})(v)
		}
		return ret
	})(&tmp.Data)
	return
}

func GitProtocol(i GitInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "Git",
		ID:   GitProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GitCreateArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GitCreateArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GitCreateArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GitCreate(ctx, (typedArg.Import()))
						if err != nil {
							return nil, err
						}
						ret := rpc.DataWrap[Header, *lib.GitURLInternal__]{
							Data:   tmp.Export(),
							Header: i.MakeResHeader(),
						}
						return &ret, nil
					},
				},
				Name: "gitCreate",
			},
			1: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret rpc.DataWrap[Header, *GitLsArgInternal__]
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedWrappedArg, ok := args.(*rpc.DataWrap[Header, *GitLsArgInternal__])
						if !ok {
							err := rpc.NewTypeError((*rpc.DataWrap[Header, *GitLsArgInternal__])(nil), args)
							return nil, err
						}
						if err := i.CheckArgHeader(ctx, typedWrappedArg.Header); err != nil {
							return nil, err
						}
						typedArg := typedWrappedArg.Data
						tmp, err := i.GitLs(ctx, (typedArg.Import()).Cfg)
						if err != nil {
							return nil, err
						}
						lst := (func(x []lib.GitURL) *[](*lib.GitURLInternal__) {
							if len(x) == 0 {
								return nil
							}
							ret := make([](*lib.GitURLInternal__), len(x))
							for k, v := range x {
								ret[k] = v.Export()
							}
							return &ret
						})(tmp)
						ret := rpc.DataWrap[Header, [](*lib.GitURLInternal__)]{
							Header: i.MakeResHeader(),
						}
						if lst != nil {
							ret.Data = *lst
						}
						return &ret, nil
					},
				},
				Name: "gitLs",
			},
		},
		WrapError: GitMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

type LogLine struct {
	Msg            string
	Newline        bool
	CarriageReturn bool
}

type LogLineInternal__ struct {
	_struct        struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Msg            *string
	Newline        *bool
	CarriageReturn *bool
}

func (l LogLineInternal__) Import() LogLine {
	return LogLine{
		Msg: (func(x *string) (ret string) {
			if x == nil {
				return ret
			}
			return *x
		})(l.Msg),
		Newline: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(l.Newline),
		CarriageReturn: (func(x *bool) (ret bool) {
			if x == nil {
				return ret
			}
			return *x
		})(l.CarriageReturn),
	}
}

func (l LogLine) Export() *LogLineInternal__ {
	return &LogLineInternal__{
		Msg:            &l.Msg,
		Newline:        &l.Newline,
		CarriageReturn: &l.CarriageReturn,
	}
}

func (l *LogLine) Encode(enc rpc.Encoder) error {
	return enc.Encode(l.Export())
}

func (l *LogLine) Decode(dec rpc.Decoder) error {
	var tmp LogLineInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*l = tmp.Import()
	return nil
}

func (l *LogLine) Bytes() []byte { return nil }

var GitHelperLogProtocolID rpc.ProtocolUniqueID = rpc.ProtocolUniqueID(0x8e3b3b3b)

type GitLogArg struct {
	Lines []LogLine
}

type GitLogArgInternal__ struct {
	_struct struct{} `codec:",toarray"` //lint:ignore U1000 msgpack internal field
	Lines   *[](*LogLineInternal__)
}

func (g GitLogArgInternal__) Import() GitLogArg {
	return GitLogArg{
		Lines: (func(x *[](*LogLineInternal__)) (ret []LogLine) {
			if x == nil || len(*x) == 0 {
				return nil
			}
			ret = make([]LogLine, len(*x))
			for k, v := range *x {
				if v == nil {
					continue
				}
				ret[k] = (func(x *LogLineInternal__) (ret LogLine) {
					if x == nil {
						return ret
					}
					return x.Import()
				})(v)
			}
			return ret
		})(g.Lines),
	}
}

func (g GitLogArg) Export() *GitLogArgInternal__ {
	return &GitLogArgInternal__{
		Lines: (func(x []LogLine) *[](*LogLineInternal__) {
			if len(x) == 0 {
				return nil
			}
			ret := make([](*LogLineInternal__), len(x))
			for k, v := range x {
				ret[k] = v.Export()
			}
			return &ret
		})(g.Lines),
	}
}

func (g *GitLogArg) Encode(enc rpc.Encoder) error {
	return enc.Encode(g.Export())
}

func (g *GitLogArg) Decode(dec rpc.Decoder) error {
	var tmp GitLogArgInternal__
	err := dec.Decode(&tmp)
	if err != nil {
		return err
	}
	*g = tmp.Import()
	return nil
}

func (g *GitLogArg) Bytes() []byte { return nil }

type GitHelperLogInterface interface {
	GitLog(context.Context, []LogLine) error
	ErrorWrapper() func(error) lib.Status
}

func GitHelperLogMakeGenericErrorWrapper(f GitHelperLogErrorWrapper) rpc.WrapErrorFunc {
	return func(err error) interface{} {
		if err == nil {
			return err
		}
		return f(err).Export()
	}
}

type GitHelperLogErrorUnwrapper func(lib.Status) error
type GitHelperLogErrorWrapper func(error) lib.Status

type gitHelperLogErrorUnwrapperAdapter struct {
	h GitHelperLogErrorUnwrapper
}

func (g gitHelperLogErrorUnwrapperAdapter) MakeArg() interface{} {
	return &lib.StatusInternal__{}
}

func (g gitHelperLogErrorUnwrapperAdapter) UnwrapError(raw interface{}) (appError error, dispatchError error) {
	sTmp, ok := raw.(*lib.StatusInternal__)
	if !ok {
		return nil, errors.New("Error converting to internal type in UnwrapError")
	}
	if sTmp == nil {
		return nil, nil
	}
	return g.h(sTmp.Import()), nil
}

var _ rpc.ErrorUnwrapper = gitHelperLogErrorUnwrapperAdapter{}

type GitHelperLogClient struct {
	Cli            rpc.GenericClient
	ErrorUnwrapper GitHelperLogErrorUnwrapper
}

func (c GitHelperLogClient) GitLog(ctx context.Context, lines []LogLine) (err error) {
	arg := GitLogArg{
		Lines: lines,
	}
	warg := arg.Export()
	err = c.Cli.Call2(ctx, rpc.NewMethodV2(GitHelperLogProtocolID, 0, "GitHelperLog.gitLog"), warg, nil, 0*time.Millisecond, gitHelperLogErrorUnwrapperAdapter{h: c.ErrorUnwrapper})
	if err != nil {
		return
	}
	return
}

func GitHelperLogProtocol(i GitHelperLogInterface) rpc.ProtocolV2 {
	return rpc.ProtocolV2{
		Name: "GitHelperLog",
		ID:   GitHelperLogProtocolID,
		Methods: map[rpc.Position]rpc.ServeHandlerDescriptionV2{
			0: {
				ServeHandlerDescription: rpc.ServeHandlerDescription{
					MakeArg: func() interface{} {
						var ret GitLogArgInternal__
						return &ret
					},
					Handler: func(ctx context.Context, args interface{}) (interface{}, error) {
						typedArg, ok := args.(*GitLogArgInternal__)
						if !ok {
							err := rpc.NewTypeError((*GitLogArgInternal__)(nil), args)
							return nil, err
						}
						err := i.GitLog(ctx, (typedArg.Import()).Lines)
						if err != nil {
							return nil, err
						}
						return nil, nil
					},
				},
				Name: "gitLog",
			},
		},
		WrapError: GitHelperLogMakeGenericErrorWrapper(i.ErrorWrapper()),
	}
}

func init() {
	rpc.AddUnique(GitHelperProtocolID)
	rpc.AddUnique(GitProtocolID)
	rpc.AddUnique(GitHelperLogProtocolID)
}
