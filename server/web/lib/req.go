// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package lib

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/proto/rem"
	"github.com/go-chi/chi/v5"
)

func NewBadParamError(id string) error {
	return core.NewHttp422Error(fmt.Errorf("bad parameter '%s'", id), "")
}

func NewMissingParamError(id string) error {
	return core.NewHttp422Error(fmt.Errorf("missing parameter '%s'", id), "")
}

type ParamSource int

const (
	ParamSourceURL   ParamSource = 1
	ParamSourceForm  ParamSource = 2
	ParamSourceQuery ParamSource = 3
)

type Args struct {
	r *http.Request
}

func NewArgs(r *http.Request) *Args {
	return &Args{r: r}
}

func (a *Args) raw(src ParamSource, name string) string {
	switch src {
	case ParamSourceURL:
		return chi.URLParam(a.r, name)
	case ParamSourceForm:
		return a.r.FormValue(name)
	case ParamSourceQuery:
		return a.r.URL.Query().Get(name)
	default:
		return ""
	}
}

func (a *Args) TeamID(src ParamSource, id string) (*proto.TeamID, error) {
	raw := a.raw(src, id)
	eid, err := proto.ImportEntityIDFromString(raw)
	if err != nil {
		return nil, a.mkerr(err, id)
	}
	tid, err := eid.ToTeamID()
	if err != nil {
		return nil, a.mkerr(err, id)
	}
	return &tid, nil
}

func (a *Args) makeDesc(id string) string {
	return "Param '" + id + "'"
}

func (a *Args) mkerr(err error, id string) error {
	return core.NewHttp422Error(err, a.makeDesc(id))
}

func (a *Args) id16(src ParamSource, id string) (*proto.ID16, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return nil, NewMissingParamError(id)
	}
	id16, err := proto.ID16String(raw).Parse()
	if err != nil {
		return nil, a.mkerr(err, id)
	}
	return id16, nil
}

func (a *Args) VHostID(src ParamSource, id string) (*proto.VHostID, error) {
	id16, err := a.id16(src, id)
	if err != nil {
		return nil, err
	}
	vid, err := id16.ToVHostID()
	if err != nil {
		return nil, a.mkerr(err, id)
	}
	return vid, nil
}

func (a *Args) PlanID(src ParamSource, id string) (*proto.PlanID, error) {
	id16, err := a.id16(src, id)
	if err != nil {
		return nil, err
	}
	pid, err := id16.ToPlanID()
	if err != nil {
		return nil, a.mkerr(err, id)
	}
	return pid, nil
}

func (a *Args) Time(src ParamSource, id string) (*proto.Time, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return nil, NewMissingParamError(id)
	}
	val, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil, a.mkerr(err, id)
	}
	t := proto.Time(val)
	return &t, nil
}

func (a *Args) StripePriceID(src ParamSource, id string) (*infra.StripePriceID, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return nil, NewMissingParamError(id)
	}
	ret := infra.StripePriceID(raw)
	return &ret, nil
}

func (a *Args) PriceID(src ParamSource, id string) (*proto.PriceID, error) {
	id16, err := a.id16(src, id)
	if err != nil {
		return nil, err
	}
	pid, err := id16.ToPriceID()
	if err != nil {
		return nil, a.mkerr(err, id)
	}
	return pid, nil
}

func (a *Args) StdTargetHostID() (*proto.HostID, error) {
	paramId := "hostId"
	raw := a.raw(ParamSourceURL, paramId)
	if raw == "" {
		return nil, NewMissingParamError(paramId)
	}
	eid, err := proto.ImportEntityIDFromString(raw)
	if err != nil {
		return nil, NewBadParamError(paramId)
	}
	hid, err := eid.ToHostID()
	if err != nil {
		return nil, a.mkerr(err, paramId)
	}
	return &hid, nil
}

func (a *Args) StripeSessionID(src ParamSource, id string) (infra.StripeSessionID, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return "", NewMissingParamError(id)
	}
	if len(raw) < 5 {
		return "", NewBadParamError(id)
	}
	ret := infra.StripeSessionID(raw)
	return ret, nil
}

func (a *Args) MultiUseInviteCode(src ParamSource, id string) (*rem.MultiUseInviteCode, error) {
	raw := a.raw(src, id)
	if len(raw) < 5 {
		return nil, NewMissingParamError(id)
	}
	ret := rem.MultiUseInviteCode(raw)
	return &ret, nil
}

func (a *Args) StripeSubscriptionID(src ParamSource, id string) (infra.StripeSubscriptionID, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return "", NewMissingParamError(id)
	}
	if len(raw) < 5 {
		return "", NewBadParamError(id)
	}
	ret := infra.StripeSubscriptionID(raw)
	return ret, nil
}

func (a *Args) IsChecked(src ParamSource, id string) (bool, error) {
	raw := a.raw(src, id)
	if strings.ToLower(raw) == "checked" {
		return true, nil
	}
	return false, nil
}

type ActionType int

const (
	ActionTypeApprove ActionType = 1
	ActionTypeCancel  ActionType = 2
)

func (a *Args) ActionType(src ParamSource, id string) (ActionType, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return ActionTypeApprove, nil
	}
	if strings.ToLower(raw) == "approve" {
		return ActionTypeApprove, nil
	}
	return ActionTypeCancel, nil
}

var goodRe = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
var badRe = regexp.MustCompile(`^-|-$|--`)

func (a *Args) validateHostnamePart(arg string, id string) (string, error) {
	errOut := func(s string) (string, error) {
		return "", a.mkerr(core.BadArgsError(s), id)
	}

	arg = strings.ToLower(arg)

	if !goodRe.MatchString(arg) {
		return errOut("invalid hostname part")
	}
	if badRe.MatchString(arg) {
		return errOut("invalid hostname part")
	}

	return arg, nil
}

func (a *Args) validateHostname(v string, id string, canBeApex bool) (string, error) {

	errOut := func(s string) (string, error) {
		return "", a.mkerr(core.BadArgsError(s), id)
	}

	s := strings.ToLower(v)
	if len(s) < 3 {
		return errOut("hostname too short")
	}
	args := strings.Split(s, ".")
	if len(args) < 2 {
		return errOut("host lacks a TLD")
	}
	if len(args) < 3 && !canBeApex {
		return errOut("hostname cannot be an apex domain")
	}
	if len(args) > 6 {
		return errOut("too many hostname parts")
	}
	tldRe := regexp.MustCompile(`^[a-z]{2,}$`)
	tld := args[len(args)-1]
	args = args[:len(args)-1]

	if !tldRe.MatchString(tld) {
		return errOut("invalid TLD")
	}

	for _, arg := range args {
		_, err := a.validateHostnamePart(arg, id)
		if err != nil {
			return "", err
		}
	}

	return s, nil
}

func (a *Args) Hostname(src ParamSource, id string) (proto.Hostname, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return "", NewMissingParamError(id)
	}
	ret, err := a.validateHostname(raw, id, true)
	if err != nil {
		return "", err
	}
	return proto.Hostname(ret), nil
}

func (a *Args) NonApexHostname(src ParamSource, id string) (proto.Hostname, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return "", NewMissingParamError(id)
	}
	ret, err := a.validateHostname(raw, id, false)
	if err != nil {
		return "", err
	}
	return proto.Hostname(ret), nil
}

func (a *Args) HostnamePart(src ParamSource, id string) (proto.Hostname, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return "", NewMissingParamError(id)
	}
	ret, err := a.validateHostnamePart(raw, id)
	if err != nil {
		return "", err
	}
	return proto.Hostname(ret), nil
}

func (a *Args) OAuth2SessionID(src ParamSource, id string) (*proto.OAuth2SessionID, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return nil, NewMissingParamError(id)
	}
	s := proto.OAuth2SessionIDString(raw)
	ret, err := s.Parse()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func (a *Args) ViewershipMode(src ParamSource, id string) (proto.ViewershipMode, error) {
	ret := proto.ViewershipMode_Closed
	raw := a.raw(src, id)
	if raw == "" {
		return ret, NewMissingParamError(id)
	}
	err := ret.ImportFromDB(raw)
	if err != nil {
		return ret, a.mkerr(err, id)
	}
	return ret, nil
}

func (a *Args) String(src ParamSource, id string) (string, error) {
	raw := a.raw(src, id)
	if raw == "" {
		return "", NewMissingParamError(id)
	}
	return raw, nil
}

func (a *Args) url(
	src ParamSource,
	param string,
) (
	proto.URLString,
	error,
) {
	raw := a.raw(src, param)
	if raw == "" {
		return "", NewMissingParamError(param)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", a.mkerr(err, param)
	}
	if u.Host == "" {
		return "", a.mkerr(core.BadArgsError("URL is missing host"), param)
	}
	if u.Scheme == "" {
		return "", a.mkerr(core.BadArgsError("URL is missing scheme"), param)
	}
	if u.Path == "" {
		return "", a.mkerr(core.BadArgsError("URL is missing path"), param)
	}
	ret := proto.URLString(u.String())
	return ret, nil
}

func (a *Args) SSOConfig(
	src ParamSource,
	providerParam string,
	urlParam string,
	idParam string,
	secretParam string,
	disableParam string,
) (*proto.SSOConfig, error) {
	dis := a.raw(src, disableParam)
	enabled := (dis == "")
	if !enabled {
		return &proto.SSOConfig{
			Active: proto.SSOProtocolType_None,
		}, nil
	}

	provider := a.raw(src, providerParam)

	var configURL proto.URLString
	switch provider {
	case "google":
		configURL = proto.URLString(GoogleOIDCConfigURL)
	default:
		u, err := a.url(src, urlParam)
		if err != nil {
			return nil, err
		}
		configURL = u
	}

	id := a.raw(src, idParam)
	if id == "" {
		return nil, NewMissingParamError(idParam)
	}
	sec := a.raw(src, secretParam)
	if provider == "google" && sec == "" {
		return nil, NewMissingParamError(secretParam)
	}
	return &proto.SSOConfig{
		Active: proto.SSOProtocolType_Oauth2,
		Oauth2: &proto.OAuth2Config{
			ConfigURI:    configURL,
			ClientID:     proto.OAuth2ClientID(id),
			ClientSecret: proto.OAuth2ClientSecret(sec),
		},
	}, nil
}
