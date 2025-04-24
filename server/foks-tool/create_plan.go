// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/proto/infra"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type CreatePlan struct {
	CLIAppBase
	details     []string
	prices      []string
	name        string
	displayName string
	maxSeats    int
	maxVhosts   int
	quotaRaw    string
	quota       proto.Size
	promoted    bool
	vhostScope  bool
	sso         bool

	plan infra.Plan
}

func parsePrice(s string) (*infra.PlanPrice, error) {

	pattern := `^(?P<count>\d+)?(?P<interval>[dym]):(?P<cents>\d+)$`
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(s)
	if match == nil {
		return nil, core.BadArgsError("bad price, need something like '1m:995'")
	}

	result := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}
	count := 1
	if result["count"] != "" {
		var err error
		count, err = strconv.Atoi(result["count"])
		if err != nil {
			return nil, core.BadArgsError(fmt.Sprintf("bad count: %s\n", err.Error()))
		}
	}
	interval := result["interval"]
	cents, err := strconv.Atoi(result["cents"])
	if err != nil {
		return nil, core.BadArgsError(fmt.Sprintf("bad price: %s\n", err.Error()))
	}

	var intervalCode infra.Interval
	switch strings.ToLower(interval) {
	case "d":
		intervalCode = infra.Interval_Day
	case "m":
		intervalCode = infra.Interval_Month
	case "y":
		intervalCode = infra.Interval_Year
	default:
		return nil, core.BadArgsError("bad interval, can only support months and years")
	}
	return &infra.PlanPrice{
		Cents: infra.Cents(cents),
		Pi: infra.PaymentInterval{
			Interval: intervalCode,
			Count:    uint64(count),
		},
		Promoted: true,
		Pri:      int64(cents),
	}, nil
}

func (c *CreatePlan) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "create-plan",
		Short: "create a new usage plan",
	}
	ret.Flags().IntVar(&c.maxSeats, "max-seats", -1, "max number of teams (or users in vhosts-mode) who can share quota")
	ret.Flags().BoolVar(&c.vhostScope, "vhost-scope", false, "use vhost scope")
	ret.Flags().BoolVar(&c.sso, "sso", false, "use SSO (only works with vhost-scope)")
	ret.Flags().IntVar(&c.maxVhosts, "max-vhosts", -1, "max number of vhosts allowed to be created")
	ret.Flags().StringVar(&c.quotaRaw, "quota", "", "allowable quota for plan")
	ret.Flags().StringVar(&c.name, "name", "", "unique name for the plan")
	ret.Flags().StringVar(&c.displayName, "display-name", "", "the displayed name of the plan (need not be unique)")
	ret.Flags().StringSliceVar(&c.details, "details", nil, "Bullet points to list in the display")
	ret.Flags().BoolVar(&c.promoted, "promoted", false, "promote the plan in the UI")
	ret.Flags().StringSliceVar(&c.prices, "prices", nil, "price details, in a form like '1m:995'")
	return ret
}

func (c *CreatePlan) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if c.name == "" {
		return core.BadArgsError("no --name paramenter specified")
	}
	if c.maxSeats <= 0 {
		return core.BadArgsError("must specify positive --max-teams option")
	}
	if c.quotaRaw == "" {
		return core.BadArgsError("must specify positive --quota option")
	}
	err := c.quota.Parse(c.quotaRaw)
	if err != nil {
		return core.BadArgsError(fmt.Sprintf("bad quota specified: %s", err.Error()))
	}
	if len(c.details) == 0 {
		return core.BadArgsError("must specify one of more --details options")
	}
	if len(c.prices) == 0 {
		return core.BadArgsError("must specify one or more --price options")
	}
	if c.displayName == "" {
		return core.BadArgsError("must specify --display-name option")
	}
	if c.vhostScope && c.maxVhosts <= 0 {
		return core.BadArgsError("must specify positive --max-vhosts option when using --vhost-scope")
	}
	if !c.vhostScope && c.maxVhosts > 0 {
		return core.BadArgsError("cannot specify --max-vhosts without --vhost-scope")
	}
	if c.sso && !c.vhostScope {
		return core.BadArgsError("cannot specify --sso without --vhost-scope")
	}

	var vhosts uint64
	if c.maxVhosts > 0 {
		vhosts = uint64(c.maxVhosts)
	}

	plan := infra.Plan{
		Name:        c.name,
		DisplayName: c.displayName,
		MaxSeats:    uint64(c.maxSeats),
		MaxVhosts:   vhosts,
		Quota:       c.quota,
		Points:      c.details,
		Promoted:    c.promoted,
		Scope:       core.Sel(c.vhostScope, infra.QuotaScope_VHost, infra.QuotaScope_Teams),
		Sso:         c.sso,
	}

	for _, raw := range c.prices {
		price, err := parsePrice(raw)
		if err != nil {
			return err
		}
		plan.Prices = append(plan.Prices, *price)
	}
	c.plan = plan
	return nil
}

func (c *CreatePlan) Run(m shared.MetaContext) error {
	pm := shared.NewPlanMaker(&c.plan, infra.MakePlanOpts{})
	err := pm.Run(m)
	if err != nil {
		return err
	}
	out, err := c.plan.Id.StringErr()
	if err != nil {
		return err
	}
	fmt.Printf("New plan created w/ id: %s\n", out)
	return nil
}

func (c *CreatePlan) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*CreatePlan)(nil)

func init() {
	AddCmd(&CreatePlan{})
}
