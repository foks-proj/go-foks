// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"fmt"
	"strings"

	"github.com/foks-proj/go-foks/lib/core"
)

func ClientifyErrorMessage(e error) string {

	switch te := e.(type) {
	case core.YubiLockedError:
		var b strings.Builder
		fmt.Fprintf(&b, "Credentials are locked with your YubiKey (%s, Slot %d); ",
			string(te.Info.Card.Name), te.Info.Key.Slot)
		fmt.Fprintf(&b, "Use %s to unlock", italicStyle.Render("foks yubi unlock"))
		return b.String()
	case core.YubiDefaultPINError:
		var b strings.Builder
		fmt.Fprintf(&b, "Default YubiKey PINs are not allowed; use %s to set one",
			HappyStyle.Render(
				italicStyle.Render("foks yubi set-pin"),
			),
		)
		return b.String()
	}
	return e.Error()
}

func RenderError(e error) string {
	return ClientifyErrorMessage(e)
}
