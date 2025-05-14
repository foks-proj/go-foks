// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package core

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// RewrapPad reads UTF‑8 text from r, wraps it, and writes it to w.
// Each line is indented by pad spaces; the total line length
// (padding + text) never exceeds width.
//
// Paragraphs are separated by blank lines in the input and are preserved.
//
// Example:
//
//	err := RewrapPad(os.Stdin, os.Stdout, 80, 4) // 4‑space indent
func RewrapPad(r io.Reader, w io.Writer, width, pad int) error {
	if width <= pad+1 {
		return fmt.Errorf("width (%d) must be > pad (%d)+1", width, pad)
	}
	inner := width - pad               // usable columns for text
	prefix := strings.Repeat(" ", pad) // left padding

	sc := bufio.NewScanner(r)
	var buf strings.Builder
	col := 0

	flush := func() {
		if buf.Len() > 0 {
			fmt.Fprintln(w, prefix+buf.String())
			buf.Reset()
			col = 0
		}
	}

	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r\n")

		// blank line = paragraph break
		if strings.TrimSpace(line) == "" {
			flush()
			fmt.Fprintln(w) // preserve blank line
			continue
		}

		for _, word := range strings.Fields(line) {
			wlen := utf8.RuneCountInString(word)

			switch {
			case col == 0: // first word on new line
				buf.WriteString(word)
				col = wlen
			case col+1+wlen > inner: // wrap
				flush()
				buf.WriteString(word)
				col = wlen
			default: // append to current line
				buf.WriteByte(' ')
				buf.WriteString(word)
				col += 1 + wlen
			}
		}
	}
	flush()
	return sc.Err()
}

func Rewrap(s string, cols, pad int) (string, error) {
	var buf strings.Builder
	if err := RewrapPad(strings.NewReader(s), &buf, cols, pad); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func MustRewrap(s string, cols int, pad int) string {
	s, err := Rewrap(s, cols, pad)
	if err != nil {
		panic(err)
	}
	return s
}

func Blockquote(s string, cols int) string {
	lines := strings.Split(s, "\n")
	spcs := func(n int) string {
		if n < 0 {
			return ""
		}
		var b strings.Builder
		for range n {
			b.WriteByte(' ')
		}
		return b.String()
	}

	pad := spcs(cols)

	for i, line := range lines {
		if len(line) > 0 {
			lines[i] = pad + line
		}
	}
	return strings.Join(lines, "\n")
}
