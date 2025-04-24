// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
	goj "gitlab.com/c0b/go-ordered-json"
	"go.uber.org/zap/zapcore"
)

type LogView struct {
	input  io.Reader
	output io.Writer
	level  zapcore.Level
}

func flatten(v [][]byte) string {
	var tmp []string
	for _, x := range v {
		tmp = append(tmp, string(x))
	}
	return strings.Join(tmp, "")
}

func (l *LogView) processLine(ctx context.Context, s string) error {

	om := goj.NewOrderedMap()

	err := om.UnmarshalJSON([]byte(s))
	if err != nil {
		return err
	}

	// Filter out all levels less than what we're at.
	if ilev, ok := om.GetValue("level"); ok {
		if slev, ok := ilev.(string); ok {
			nlev, err := zapcore.ParseLevel(slev)
			if err != nil {
				return err
			}
			if nlev < l.level {
				return nil
			}
		}
	}

	// Now set the timestamp to something human-readable
	if its, ok := om.GetValue("ts"); ok {
		if nts, ok := its.(json.Number); ok {
			if fts, err := nts.Float64(); err == nil {
				tm := time.Unix(int64(fts), int64((fts-float64(int64(fts)))*1e9))
				om.Set("ts", tm.Format(time.RFC3339))
			}
		}
	}

	out, err := om.MarshalJSON()
	if err != nil {
		return err
	}
	out = append(out, '\n')
	_, err = l.output.Write(out)
	if err != nil {
		return err
	}
	return nil
}

func (l *LogView) Run(ctx context.Context) error {

	rdr := bufio.NewReader(l.input)
	var c int

	var linebuf [][]byte
	for {
		c++
		line, isPrefix, err := rdr.ReadLine()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		linebuf = append(linebuf, line)
		if isPrefix {
			continue
		}
		s := flatten(linebuf)
		linebuf = nil

		err = l.processLine(ctx, s)
		if err != nil {
			// Ignore error and return value
			_, _ = fmt.Fprintf(l.output, "Error on line %d: %s\n", c, err)
		}
	}
}

func FilterLog(ctx context.Context, input io.Reader, output io.Writer, level zapcore.Level) error {
	lv := LogView{
		input:  input,
		output: output,
		level:  level,
	}
	return lv.Run(ctx)
}

type FilterLogOpts struct {
	Level string
}

func RunFilterLog(cmd *cobra.Command, args []string, opts *FilterLogOpts) error {
	lev := zapcore.DebugLevel
	if opts.Level != "" {
		var err error
		lev, err = zapcore.ParseLevel(opts.Level)
		if err != nil {
			return err
		}
	}
	return FilterLog(context.Background(), cmd.InOrStdin(), cmd.OutOrStdout(), lev)
}

func FilterLogCommand(name string) *cobra.Command {
	var opts FilterLogOpts
	ret := &cobra.Command{
		Use:   name,
		Short: "Filter log output",
		Long:  "Filter log output according to level (and maybe eventually tags); also convert time to human-readable",
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunFilterLog(cmd, args, &opts)
		},
	}
	ret.Flags().StringVarP(&opts.Level, "level", "l", "info", "Minimum log level to show")
	return ret
}
