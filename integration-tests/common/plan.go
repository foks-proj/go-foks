// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package common

import (
	"testing"

	"github.com/foks-proj/go-foks/proto/infra"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/stretchr/testify/require"
)

func MakeRandomPlan(
	t *testing.T,
	m shared.MetaContext,
	dn string,
	template infra.Plan,
) *infra.Plan {
	nm := RandomPlanName(t)

	plan := &infra.Plan{
		Name:        nm,
		DisplayName: dn + " " + nm,
		MaxSeats:    template.MaxSeats,
		MaxVhosts:   template.MaxVhosts,
		Quota:       template.Quota,
		Promoted:    true,
		Scope:       template.Scope,
		Points: []string{
			"10 Beeblebroxes per Zaphod",
			"512MB in SlartiBartfast per Trillian",
		},
	}
	plan.Prices = append(plan.Prices, infra.PlanPrice{
		Cents: 995,
		Pi: infra.PaymentInterval{
			Count:    1,
			Interval: infra.Interval_Month,
		},
		Promoted: true,
		Pri:      995,
	})
	plan.Prices = append(plan.Prices, infra.PlanPrice{
		Cents: 1995,
		Pi: infra.PaymentInterval{
			Count:    1,
			Interval: infra.Interval_Year,
		},
		Promoted: true,
		Pri:      1995,
	})
	pm := shared.NewPlanMaker(plan, infra.MakePlanOpts{})
	err := pm.Run(m)
	require.NoError(t, err)
	_, err = plan.Id.StringErr()
	require.NoError(t, err)
	return plan
}
