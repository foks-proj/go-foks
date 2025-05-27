// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package main

import (
	"errors"
	"strings"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

type InitDB struct {
	CLIAppBase

	// config params
	all    bool
	db     string
	drop   bool
	shards []int

	eng *shared.InitDB
}

func (i *InitDB) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "init-db",
		Short: "Initialize all FOKS databases",
	}
	ret.Flags().BoolVarP(&i.all, "all", "", false, "init ALL databases")
	ret.Flags().StringVarP(&i.db, "db", "", "", "operate on one DB")
	ret.Flags().BoolVarP(&i.drop, "drop", "", false, "drop the current database")
	ret.Flags().IntSliceVar(&i.shards, "shard", nil, "shard(s) to operate on")
	return ret
}

func (i *InitDB) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if i.all && (i.db != "" || len(i.shards) > 0) {
		return errors.New("cannot use -all and -db arguments in concert; pick one or the other")
	}
	if !i.all && i.db == "" && len(i.shards) == 0 {
		return errors.New("supply either -all or -db or --shard")
	}

	var cfg shared.ManageDBsConfig

	if i.db != "" {
		db, err := shared.ParseDbType(i.db)
		if err != nil {
			return err
		}
		cfg.Dbs = []shared.DbType{db}
	}

	if i.all && len(i.shards) > 0 {
		return errors.New("cannot use -all and -shard arguments in concert; pick one or the other")
	}

	if i.all {
		cfg.Dbs = shared.AllDBs
	}

	i.eng = &shared.InitDB{
		Dbs: cfg,
	}

	return nil
}

func (i *InitDB) runDrop(m shared.MetaContext) error {

	names := strings.Join(i.eng.DatabaseNames(), ",")
	prompt := promptui.Select{
		Label: "Confirm destruction of data (tables: " + names + ")",
		Items: []string{"NO", "Yes, I'm sure"},
	}

	sel, _, err := prompt.Run()

	if err != nil {
		return err
	}

	if sel != 1 {
		return errors.New("data destruction not confirmed")
	}
	err = i.eng.DropAll(m)
	if err != nil {
		return err
	}
	return nil
}

func allShards(m shared.MetaContext) ([]shared.KVShardDescriptor, error) {
	return shared.AllShards(m)
}

func someShards(m shared.MetaContext, indices []int) ([]shared.KVShardDescriptor, error) {
	return shared.SomeShards(m, indices)
}

func (i *InitDB) Run(m shared.MetaContext) error {

	if len(i.shards) > 0 {
		shard, err := someShards(m, i.shards)
		if err != nil {
			return err
		}
		i.eng.Dbs.KVShards = shard
	}

	// Pick up all of the shards if that is what was requested.
	if i.all {
		shards, err := allShards(m)
		if err != nil {
			return err
		}
		i.eng.Dbs.KVShards = shards
	}

	var err error
	if i.drop {
		err = i.runDrop(m)
		if err != nil {
			return err
		}

	}
	err = i.eng.CreateAll(m)
	if err != nil {
		return err
	}

	err = i.eng.RunMakeTablesAll(m)
	if err != nil {
		return err
	}

	return nil
}

func (i *InitDB) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*InitDB)(nil)

func init() {
	AddCmd(&InitDB{})
}
