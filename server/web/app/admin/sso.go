// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package admin

import (
	"net/http"

	"github.com/foks-proj/go-foks/server/shared"
	"github.com/foks-proj/go-foks/server/web/lib"
	"github.com/foks-proj/go-foks/server/web/templates"
)

func VHostSetSSOHandler(g *shared.GlobalContext) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		newBaseHandler(g).ServeWithVHostDetails(w, r,
			func(m shared.MetaContext, pd *lib.AdminPageData, vhr *lib.VHostRow) error {
				args := lib.NewArgs(r)
				sso, err := args.SSOConfig(
					lib.ParamSourceForm,
					"sso-provider",
					"sso-oauth2-config-url",
					"sso-oauth2-client-id",
					"sso-oauth2-client-secret",
					"sso-disable",
				)
				if err != nil {
					return err
				}
				err = shared.SetVHostSSOConfig(m, sso)
				if err != nil {
					return err
				}
				err = vhr.LoadDetails(m)
				if err != nil {
					return err
				}
				return templates.VHostSSO(pd, vhr).Render(m.Ctx(), w)
			},
		)
	}
}
