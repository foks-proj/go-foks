package libclient

import (
	"os"
	"runtime"
	"strings"

	proto "github.com/foks-proj/go-foks/proto/lib"
)

func IsGitBashEnv() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	msys := map[string]bool{
		"MSYS":    true,
		"MINGW32": true,
		"MINGW64": true,
	}
	return msys[os.Getenv("MSYSTEM")]
}

func IsWindowsDrivePath(path proto.KVPath) bool {
	if len(path) < 3 {
		return false
	}
	if !(path[0] >= 'a' && path[0] <= 'z' || path[0] >= 'A' && path[0] <= 'Z') {
		return false
	}
	if path[1] != ':' {
		return false
	}
	if path[2] != '/' {
		return false
	}
	return true
}

// GitBashAbsPathInvert tries to undo what git bash does to paths. If conditions
// are not met, it returns the original path.
func GitBashAbsPathInvert(path proto.KVPath) proto.KVPath {
	if !IsGitBashEnv() {
		return path
	}
	if !IsWindowsDrivePath(path) {
		return path
	}

	// Will be of the form "C:\\Program Files\Git"
	exePrfx :=
		strings.ReplaceAll(
			strings.ToLower(
				os.Getenv("EXEPATH"),
			),
			"\\",
			"/",
		)
	pathLower := strings.ToLower(string(path))

	if strings.HasPrefix(pathLower, strings.ToLower(exePrfx)) {
		return proto.KVPath(path.String()[len(exePrfx):])
	}

	// Do not attempt to convert paths of the form "a:/b/c" to back to "/a/b/c"
	// since we are not certain the above check will always work. In this case,
	// we'll likely get an error further downstream, but with documentation on
	// how to change it.

	return path
}
