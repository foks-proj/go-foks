package main

import (
	"errors"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

type DbType struct {
	shared.DbType
}

func (d *DbType) Set(s string) error {
	tmp, err := shared.ParseDbType(s)
	if err != nil {
		return err
	}
	d.DbType = tmp
	return nil
}

func (d *DbType) String() string {
	return d.ToString()
}

func (d *DbType) Type() string {
	return "DbType"
}

type PatchDB struct {
	CLIAppBase
	db     DbType
	eng    *shared.PatchDBEng
	shards []int
}

func (p *PatchDB) CobraConfig() *cobra.Command {
	ret := &cobra.Command{
		Use:   "patch-db",
		Short: "Apply patches to the FOKS database",
	}
	ret.Flags().Var(&p.db, "db", "database to patch")
	ret.Flags().IntSliceVar(&p.shards, "shard", nil, "shard(s) to patch")
	return ret
}

func (p *PatchDB) CheckArgs(args []string) error {
	if len(args) != 0 {
		return core.BadArgsError("no args allowed")
	}
	if p.db.DbType == shared.DbTypeNone {
		return core.BadArgsError("must specify a database to patch with --db")
	}
	if len(p.shards) > 0 && p.db.DbType != shared.DbTypeKVStore {
		return core.BadArgsError("shards can only be specified for KV shards")
	}
	p.eng = &shared.PatchDBEng{
		Which:       p.db.DbType,
		Shards:      p.shards,
		ConfirmHook: p.Confirm,
	}
	return nil
}

func (p *PatchDB) Confirm(m shared.MetaContext, ps *shared.PatchSummary) error {
	fmt.Printf("Patches are ready to go:\n\n")

	for _, patch := range ps.Desc() {
		fmt.Printf(" - %s\n", patch)
	}
	fmt.Println("")
	prompt := promptui.Select{
		Label: "Confirm patch application",
		Items: []string{"NO", "Yes, I'm sure"},
	}

	sel, _, err := prompt.Run()

	if err != nil {
		return err
	}

	if sel != 1 {
		return errors.New("patch application aborted by user")
	}
	return nil
}

func (p *PatchDB) Run(m shared.MetaContext) error {
	return p.eng.Run(m)
}

func (p *PatchDB) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*PatchDB)(nil)

func init() {
	AddCmd(&PatchDB{})
}
