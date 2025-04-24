// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package agent

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/foks-proj/go-foks/client/libclient"
)

// InitDevTools initializes dev tools like the profiler, etc.
func InitDevTools(
	m libclient.MetaContext,
) error {

	err := initDevToolsProfiler(m)
	if err != nil {
		return err
	}

	return nil
}

func initDevToolsProfiler(
	m libclient.MetaContext,
) error {

	port := m.G().Cfg().ProfilerPort()
	if port == 0 {
		return nil
	}

	go func() {
		bind := fmt.Sprintf("localhost:%d", port)
		m.Infow("profiler", "bind", bind)
		err := http.ListenAndServe(bind, nil)
		if err != nil {
			m.Warnw("profiler", "stage", "http.ListenAndServe", "bind", bind, "err", err)
		}
	}()
	return nil
}
