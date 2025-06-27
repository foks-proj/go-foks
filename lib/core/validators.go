// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"errors"
	"net"
	"net/mail"
	"regexp"
	"strconv"
	"strings"

	lcl "github.com/foks-proj/go-foks/proto/lcl"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
)

type ValidatorError string

func (v ValidatorError) Error() string {
	return string(v)
}

func ValidateEmail(e proto.Email) error {
	ret, err := mail.ParseAddress(string(e))
	if err != nil {
		return ValidatorError("malformed email address")
	}
	if ret.Name != "" {
		return ValidatorError("cannot allow Foo <bar@zam.com> style name")
	}

	host := ret.Address[strings.LastIndex(ret.Address, "@")+1:]
	if host == "" {
		return ValidatorError("no host in email address")
	}

	parts := strings.Split(host, ".")
	// make sure the address contains a domain
	if len(parts) < 2 {
		return ValidatorError("domain doesn't have a TLD")
	}

	// make sure it's not an IP address, so that the TLD is
	// only letters
	tld := parts[len(parts)-1]

	_, err = strconv.Atoi(tld)
	if err == nil {
		return ValidatorError("hostname cannot be an IP address")
	}

	tldRe := regexp.MustCompile(`^[a-zA-Z]{2,}$`)
	if !tldRe.MatchString(tld) {
		return ValidatorError("bad TLD for email hostname")
	}

	return nil
}

func ValidateTCPAddr(a proto.TCPAddr) error {
	s := string(a)
	if len(s) < 4 {
		return errors.New("hostname too short")
	}
	var host string
	if strings.Contains(s, ":") {
		var err error
		var port string
		host, port, err = net.SplitHostPort(s)
		if err != nil {
			return errors.New("hostname could not be split into a host and port")
		}
		iPort, err := strconv.Atoi(port)
		if err != nil {
			return errors.New("port is not a number")
		}
		if iPort < 4 || iPort > 65535 {
			return errors.New("port is out of range")
		}
	} else {
		host = s
	}
	if host == "localhost" {
		return nil
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	var parts = strings.Split(host, ".")
	if len(parts) < 2 {
		return errors.New("hostname does not contain a top level domain")
	}
	if len(parts[len(parts)-1]) < 2 {
		return errors.New("top level domain is too short")
	}
	return nil
}

var multiUseInviteCodeRxx = regexp.MustCompile(`^[0-9a-zA-Z._+-]{5,}$`)

func ValidateMultiUseInviteCode(s rem.MultiUseInviteCode) error {
	ok := len(s) >= 5 && multiUseInviteCodeRxx.MatchString(s.String())
	if !ok {
		return BadInviteCodeError{}
	}
	return nil
}

func ValidateStandardInviteCode(b []byte) error {
	if len(b) < InviteCodeBytes {
		return BadInviteCodeError{}
	}
	return nil
}

func ValidateInviteCode(c rem.InviteCode) error {
	typ, err := c.GetT()
	if err != nil {
		return err
	}
	switch typ {
	case rem.InviteCodeType_Empty:
		return nil
	case rem.InviteCodeType_Standard:
		return ValidateStandardInviteCode(c.Standard())
	case rem.InviteCodeType_MultiUse:
		return ValidateMultiUseInviteCode(c.Multiuse())
	default:
		return BadInviteCodeError{}
	}
}

func ValidateInviteCodeString(s lcl.InviteCodeString, icr proto.InviteCodeRegime) error {
	code, err := ImportInviteCode(string(s), icr)
	if err != nil {
		return err
	}
	return ValidateInviteCode(code)
}
