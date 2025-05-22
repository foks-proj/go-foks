// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"errors"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
)

func ErrToStringCLI(e error) string {

	switch {
	case e == nil:
		return ""
	case core.IsSSOAuthError(e):
		return "your IdP has logged you out; please log in again via `foks sso login`"
	case errors.Is(e, core.YubiDefaultPINError{}):
		return "default YubiKey PIN is not allowed; set one via `foks yubi set-pin`"
	case errors.Is(e, core.YubiPINRequredError{}):
		return "PIN needed to unlock YubiKey; supply PIN via `foks yubi unlock --prompt-pin`"
	default:

		switch te := e.(type) {
		case core.AgentConnectError:
			return fmt.Sprintf(
				"could not connect to the FOKS agent; start it via `foks ctl start` (socket file: %s)",
				te.Path.String(),
			)

		case core.KVAbsPathError:
			if IsGitBashEnv() && IsWindowsDrivePath(te.Path) {
				return "Need an absolute path unix-style path (e.g. /a/b/c) but got \"" +
					te.Path.String() + "\"; note that Git Bash translates unix-style paths " +
					"to absolute Windows-style paths, but you can use " +
					"a leading double-slash (e.g., //path/to/my/key) to avoid this behavior"
			}
		}

		return e.Error()
	}
}
