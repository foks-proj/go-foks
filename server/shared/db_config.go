// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package shared

import (
	"context"
	"fmt"
	"strings"

	"github.com/foks-proj/go-foks/lib/core"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DbConfigJSON struct {
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Name     string `json:"name"`
	CA       string `json:"CA"`
	NoTLS    bool   `json:"no-tls"`
}

// It's slightly preposterous that we need to build a string just so the library can parse it
// but this does seem to be the safest approach.
func (d DbConfigJSON) ToString() string {
	var pairs []string
	if d.Host != "" {
		pairs = append(pairs, "host="+d.Host)
	}
	if d.Port != 0 {
		pairs = append(pairs, fmt.Sprintf("%s=%d", "port", d.Port))
	}
	if d.User != "" {
		pairs = append(pairs, "user="+d.User)
	}
	if d.Password != "" {
		pairs = append(pairs, "password="+d.Password)
	}
	if d.Name != "" {
		pairs = append(pairs, "dbname="+d.Name)
	}
	if !d.NoTLS {
		pairs = append(pairs, "sslmode=verify-full")
	}
	// Tune this way down to expose leaks and recurives db acquires
	pairs = append(pairs, "pool_max_conns=100")
	ret := strings.Join(pairs, " ")
	return ret
}

type KVShardConfigJSON struct {
	DbConfigJSON
	ShardID proto.KVShardID `json:"id"`
	Active  bool            `json:"active"`
}

type kvShardsConfig struct {
	shards map[proto.KVShardID]*KVShardConfigJSON
	active []*KVShardConfigJSON
}

func newKvShardsConfig(shards []KVShardConfigJSON) *kvShardsConfig {
	ret := &kvShardsConfig{
		shards: make(map[proto.KVShardID]*KVShardConfigJSON),
	}
	for _, s := range shards {
		ret.shards[s.ShardID] = &s
		if s.Active {
			ret.active = append(ret.active, &s)
		}
	}
	return ret
}

func (c *kvShardsConfig) isValid() bool {
	return c.active != nil && len(c.shards) > 0
}

func (c *kvShardsConfig) Active() []KVShardConfig {
	return core.Map(c.active, func(s *KVShardConfigJSON) KVShardConfig { return s })
}

func (c *kvShardsConfig) Get(id proto.KVShardID) KVShardConfig {
	ret := c.shards[id]
	if ret == nil {
		return nil
	}
	return ret
}

func (c *kvShardsConfig) All() []KVShardConfig {
	ret := make([]KVShardConfig, 0, len(c.shards))
	for _, s := range c.shards {
		ret = append(ret, s)
	}
	return ret
}

func (d *DbConfigJSON) AddRootCAs(ctx context.Context, cfg *pgxpool.Config) error {
	if d.CA == "" {
		return nil
	}
	pool, err := core.ExpandCertPool(ctx, d.CA)
	if err != nil {
		return err
	}
	cfg.ConnConfig.TLSConfig.RootCAs = pool
	return nil
}

func (c *KVShardConfigJSON) DbConfig(ctx context.Context) (*pgxpool.Config, error) {
	opts, err := pgxpool.ParseConfig(c.DbConfigJSON.ToString())
	if err != nil {
		return nil, err
	}
	err = c.DbConfigJSON.AddRootCAs(ctx, opts)
	if err != nil {
		return nil, err
	}
	return opts, nil
}

func (c *KVShardConfigJSON) Name() string {
	return c.DbConfigJSON.Name
}

func (c *KVShardConfigJSON) Id() proto.KVShardID {
	return c.ShardID
}

func (c *KVShardConfigJSON) IsActive() bool {
	return c.Active
}

func MakeShardDescriptor(s KVShardConfig) KVShardDescriptor {
	return KVShardDescriptor{Index: s.Id(), Active: s.IsActive(), Name: s.Name()}
}

var _ KVShardConfig = (*KVShardConfigJSON)(nil)
var _ KVShardsConfig = (*kvShardsConfig)(nil)
