// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package tools

import (
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/spf13/cobra"
)

type b62cfg struct {
	encode   bool
	decode   bool
	typ      byte
	goOutput bool
}

func b62enc(m libclient.MetaContext, s string, typ byte) (string, error) {
	buf, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}
	if typ == 0 {
		return proto.B62Encode(buf), nil
	}
	return proto.PrefixedB62Encode(typ, buf)
}

func b62dec(
	m libclient.MetaContext,
	s string,
	goOutput bool,
) (string, error) {

	hex2str := func(buf []byte) string {
		if goOutput {
			return fmt.Sprintf("%#v", buf)
		}
		return hex.EncodeToString(buf)
	}

	if s[0] != '.' {
		buf, err := proto.B62Decode(s)
		if err != nil {
			return "", err
		}
		return hex2str(buf), nil
	}

	eid, id16, err := proto.ImportIDFromString(s)
	if err != nil {
		return "", err
	}
	var dat []byte
	var iType int
	var sType string
	var ok bool
	if eid != nil {
		dat = eid.Data()
		typ := eid.Type()
		iType = int(typ)
		sType, ok = proto.EntityTypeRevMap[typ]
	} else {
		dat = id16.Data()
		typ := id16.Type()
		iType = int(typ)
		sType, ok = proto.ID16TypeRevMap[typ]
	}
	if !ok {
		return "", core.BadArgsError("unknown entity or ID16 type")
	}
	sDat := hex2str(dat)
	ret := fmt.Sprintf(
		"%s<%d> %s",
		sType,
		iType,
		sDat,
	)
	return ret, nil
}

func b62(
	m libclient.MetaContext,
	parent *cobra.Command,
	cfg *b62cfg,
	args []string,
) error {
	type op int
	const (
		opNone op = iota
		opEnc  op = iota
		opDec  op = iota
	)
	b62Rxx := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	hexRxx := regexp.MustCompile(`^([0-9a-fA-F]{2})+$`)

	if len(args) != 1 {
		return core.BadArgsError("expected exactly one argument")
	}
	s := args[0]
	switch {
	case cfg.encode && cfg.decode:
		return core.BadArgsError("cannot both encode and decode")
	case cfg.typ != 0 && cfg.decode:
		return core.BadArgsError("type only applies to encoding")
	case len(s) < 2:
		return core.BadArgsError("input too short")
	}

	inferredOp := opNone
	isB62 := b62Rxx.MatchString(s)
	isHex := hexRxx.MatchString(s)

	switch {
	case s[0] == '.':
		inferredOp = opDec
	case !isB62 && !isHex:
		return core.BadArgsError("input is not base62 or hex")
	case isB62 && !isHex:
		inferredOp = opDec
	}

	switch {
	case inferredOp == opNone && !cfg.encode && !cfg.decode:
		return core.BadArgsError("cannot infer operation")
	case inferredOp == opNone && cfg.encode:
		inferredOp = opEnc
	case inferredOp == opNone && cfg.decode:
		inferredOp = opDec
	case inferredOp == opEnc && cfg.decode:
		return core.BadArgsError("cannot decode since we guessed we had to encode")
	case inferredOp == opDec && cfg.encode:
		return core.BadArgsError("cannot encode since we didn't get hex")
	}

	switch {
	case inferredOp != opDec && cfg.goOutput:
		return core.BadArgsError("go output only applies to decoding")
	}

	var out string
	var err error
	switch inferredOp {
	case opEnc:
		out, err = b62enc(m, s, cfg.typ)
	case opDec:
		out, err = b62dec(m, s, cfg.goOutput)
	default:
		err = core.BadArgsError("no possible operation")
	}
	if err != nil {
		return err
	}
	m.G().UIs().Terminal.Printf("%s\n", out)
	return nil
}

func B62Cmd(m libclient.MetaContext, parent *cobra.Command) {
	var cfg b62cfg
	cmd := &cobra.Command{
		Use:          "b62",
		Short:        "base62 encode/decode",
		Long:         "encode/decode base62 strings",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, arg []string) error {
			return b62(m, cmd, &cfg, arg)
		},
	}
	cmd.Flags().BoolVarP(&cfg.encode, "encode", "e", false, "encode")
	cmd.Flags().BoolVarP(&cfg.decode, "decode", "d", false, "decode")
	cmd.Flags().BoolVarP(&cfg.goOutput, "go-output", "g", false, "output in go format")
	cmd.Flags().Uint8VarP(&cfg.typ, "type", "t", 0, "type of encoding (for encoding)")
	parent.AddCommand(cmd)
}
