package libterm

import (
	"os"

	"golang.org/x/term"
)

// TermDims holds the dimensions of the terminal.
type TermDims struct {
	Width  int
	Height int
}

func GetTermDims() (*TermDims, error) {
	fd := int(os.Stdout.Fd())
	if !term.IsTerminal(fd) {
		return nil, NotATerminalError{}
	}

	width, height, err := term.GetSize(fd)
	if err != nil {
		return nil, err
	}
	return &TermDims{
		Width:  width,
		Height: height,
	}, nil
}

func TerminalWidthWithDefault() int {
	dims, err := GetTermDims()
	if err != nil {
		return 72 // very conservative default
	}
	ret := dims.Width
	if ret <= 5 {
		return 40
	}
	ret -= 4            // leave room for right margin
	maxTextWidth := 100 // above this width, text doesn't look good
	if ret >= maxTextWidth {
		ret = maxTextWidth // don't go wider than this
	}
	return ret
}
