// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libgit

import (
	"bytes"
	"context"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/go-git/go-git/v5/config"
)

type ConfigStorage struct {
	adptr *adapter
}

const configFilename = "config"

func (c *ConfigStorage) Config() (*config.Config, error) {
	var buf bytes.Buffer
	err := c.adptr.getDataFromPath(context.Background(), configFilename, &buf)
	if core.IsKVNoentError(err) {
		return config.NewConfig(), nil
	}
	if err != nil {
		return nil, err
	}
	ret, err := config.ReadConfig(&buf)
	if err != nil {
		return nil, err
	}

	// Turn off delta compression
	ret.Pack.Window = 0
	return ret, nil
}

func (c *ConfigStorage) SetConfig(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	b, err := cfg.Marshal()
	if err != nil {
		return err
	}
	buf := bytes.NewReader(b)
	return c.adptr.putDataToPath(context.Background(), configFilename, buf)
}

var _ config.ConfigStorer = (*ConfigStorage)(nil)
