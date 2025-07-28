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

	if u.YubiInfo != nil && (opts == nil || !opts.NoDeviceName) {
		s := fmt.Sprintf("<🔑 %s / serial=%d / slot=%d>", u.YubiInfo.Card.Name, u.YubiInfo.Card.Serial, u.YubiInfo.Key.Slot)
		parts = append(parts, s)
	}

	if u.KeyGenus == proto.KeyGenus_Backup && (opts == nil || !opts.NoDeviceName) {
		nm := string(u.Devname)
		if nm == "" {
			nm, _ = u.Key.StringErr()
		}
		s := fmt.Sprintf("<💾 backup key: %s>", nm)
		parts = append(parts, s)
	}

	if u.Active && (opts == nil || opts.Active) {
		parts = append(parts, "[ACTIVE]")
	}

	return strings.Join(parts, " "), nil
}
