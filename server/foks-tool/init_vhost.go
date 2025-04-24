// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type InitVhost struct {
	CLIAppBase
	vhost  string
	code   string
	typRaw string
	cfg    proto.HostConfig
}

func (i *InitVhost) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "init-vhost",
		Short: "Initial host configuration for one or most virtual hosts (vhosts)",
	}
	ret.Flags().StringVarP(&i.vhost, "vhost", "", "", "Comma-separated hostnames")
	ret.Flags().StringVarP(&i.code, "code", "", "", "Invite code")
	ret.Flags().StringVarP(&i.typRaw, "host-type", "", "big-top", "Host type (one of: big-top, vhost-management, vhost)")
	return ret
}

func (i *InitVhost) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}

	for _, s := range []struct {
		key string
		val string
	}{
		{key: "vhost", val: i.vhost},
		{key: "code", val: i.code},
	} {
		if len(s.val) == 0 {
			return fmt.Errorf("missing required --%s parameter", s.key)
		}
	}

	var typ proto.HostType
	switch i.typRaw {
	case "big-top":
		typ = proto.HostType_BigTop
	case "vhost-management":
		typ = proto.HostType_VHostManagement
	case "vhost":
		typ = proto.HostType_VHost
	default:
		return fmt.Errorf("invalid host type: %s", i.typRaw)
	}

	i.cfg = shared.MakeHostConfig(typ)
	return nil
}

func (i *InitVhost) Run(m shared.MetaContext) error {

	err := shared.InitHostID(m)
	if err != nil {
		return err
	}

	vhm := shared.BaseVHostMinder{
		Hostname:   proto.Hostname(i.vhost),
		InviteCode: rem.MultiUseInviteCode(i.code),
		Type:       i.cfg.Typ,
	}
	err = vhm.Run(m)
	if err != nil {
		return err
	}
	hid := vhm.HostID()
	if hid == nil {
		return core.InternalError("no host ID")
	}
	s, err := hid.Id.StringErr()
	if err != nil {
		return err
	}
	fmt.Printf("Success: %s => %s\n", i.vhost, s)
	return nil
}

func (i *InitVhost) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*InitVhost)(nil)

func init() {
	AddCmd(&InitVhost{})
}
