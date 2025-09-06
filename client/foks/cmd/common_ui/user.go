// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package common_ui

import (
	"fmt"
	"strings"

	proto "github.com/foks-proj/go-foks/proto/lib"
)

type FormatUserInfoOpts struct {
	Avatar       bool
	Active       bool
	Role         bool
	NewKeyWiz    bool
	NoDeviceName bool
}

func FormatUserInfoAsPromptItem(u proto.UserInfo, opts *FormatUserInfoOpts) (string, error) {
	var parts []string
	if opts == nil || opts.Avatar {
		parts = append(parts, "👤")
	}

	if opts != nil && opts.Role {
		typ, err := u.Role.GetT()
		if err != nil {
			return "", err
		}
		// Most users are owners, so don't bother to show unless not an owner
		if typ != proto.RoleType_OWNER {
			rs, err := u.Role.ShortStringErr()
			if err != nil {
				return "", err
			}
			parts = append(parts, "("+rs+")")
		}
	}

	if !u.Username.NameUtf8.IsZero() {
		parts = append(parts, string(u.Username.NameUtf8))
	} else {
		s, err := u.Fqu.Uid.StringErr()
		if err != nil {
			return "", err
		}
		parts = append(parts, "["+s+"]")
	}
	parts = append(parts, "@")
	hn := u.HostAddr.Hostname()
	if !hn.IsZero() {
		parts = append(parts, string(hn))
	} else {
		s, err := u.Fqu.HostID.StringErr()
		if err != nil {
			return "", err
		}
		parts = append(parts, "["+s+"]")
	}

	if opts == nil || !opts.NoDeviceName {
		info := string(u.Devname)
		if info == "" {
			info, _ = u.Key.StringErr()
		}
		var sgen string
		switch u.KeyGenus {
		case proto.KeyGenus_Device:
			sgen = "📱 device"
		case proto.KeyGenus_Backup:
			sgen = "💾 backup key"
		case proto.KeyGenus_BotToken:
			sgen = "🤖 bot token"
		case proto.KeyGenus_Yubi:
			sgen = "🔑 YubiKey"
			if u.YubiInfo != nil {
				sgen = "🔑 " + string(u.YubiInfo.Card.Name)
				info = fmt.Sprintf("serial=%d / slot=%d",
					u.YubiInfo.Card.Serial,
					u.YubiInfo.Key.Slot,
				)
			}
		}
		part := fmt.Sprintf("<%s: %s>", sgen, info)
		parts = append(parts, part)
	}

	if u.Active && (opts == nil || opts.Active) {
		parts = append(parts, "[ACTIVE]")
	}

	return strings.Join(parts, " "), nil
}
