// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
)

func drawTextInput(ti textinput.Model, prompt string, validator func(string) error) string {
	var err error
	s := ti.Value()
	styl := HappyStyle
	var emsg string
	if len(s) > 0 {
		err = validator(s)
		if err != nil {
			styl = ErrorStyle
			emsg = styl.Render(textInputStyle.Render(err.Error())) + "\n\n"
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\n\n%s\n\n%s",
		textInputStyle.Render(prompt),
		styl.Render(textInputStyle.Render(ti.View())),
		emsg,
	)
	return b.String()
}
