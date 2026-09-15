package main

import (
	"encoding/json"
	"fmt"

	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/libterm"
	proto "github.com/foks-proj/go-foks/proto/lib"
	"github.com/foks-proj/go-foks/server/shared"
	"github.com/spf13/cobra"
)

type LogSendCommand struct {
	CLIAppBase
	Id  proto.LogSendID
	Dir core.Path
}

func (l *LogSendCommand) CobraConfig() *cobra.Command {
	return &cobra.Command{
		Use:   "logsend <id> [<dir>]",
		Short: "Digest logs sent to FOKS server",
		Long: libterm.MustRewrapSense(`Access packaged logs sent to the 
FOKS server for debugging purposes. Supply a directory to dump the new logs to.
If none is supplied, the logs will be dumped to the current directory. In any case,
a subdirectory named after the logsend ID will be created.
`, 0),
	}
}

func (l *LogSendCommand) CheckArgs(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return core.BadArgsError("expected 1 or 2 arguments")
	}
	id, err := proto.LogSendIDString(args[0]).Parse()
	if err != nil {
		return err
	}
	l.Id = *id
	if len(args) == 2 {
		l.Dir = core.Path(args[1])
	} else {
		l.Dir = core.Path(".")
	}
	return nil
}

func (l *LogSendCommand) Run(m shared.MetaContext) error {

	set, err := shared.LogSendReassemble(m, l.Id)
	if err != nil {
		return err
	}

	// These are another user's logs, extracted onto an operator's machine;
	// keep them to the operator.
	dir := l.Dir.Join(core.Path(fmt.Sprintf("logsend-%s", l.Id.String())))
	if err := dir.Mkdir(0o700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := dir.Chdir(); err != nil {
		return err
	}

	type Md struct {
		HostID proto.HostID    `json:"host_id"`
		ID     proto.LogSendID `json:"id"`
		UID    *proto.UID      `json:"uid,omitempty"`
	}

	metaData := Md{
		HostID: set.HostID,
		ID:     set.ID,
		UID:    set.UID,
	}
	out, err := json.MarshalIndent(metaData, "", "  ")
	if err != nil {
		return err
	}
	err = dir.Join(core.Path("metadata.json")).WriteFile(out, 0o600)
	if err != nil {
		return err
	}
	for _, file := range set.Files {
		fn := core.ImportPath(file.Name)

		// check the name for malicious content that would write outside the directory
		if fn.IsBadFilename() {
			return fmt.Errorf("invalid file name %q in logsend %s", file.Name, l.Id.String())
		}
		fpath := dir.Join(core.Path(file.Name))
		err = fpath.WriteFile(file.RawData, 0o600)
		if err != nil {
			return err
		}
		isGzip, basename := fn.StripSuffix(".gz")
		if len(file.ExpandedData) > 0 && isGzip {
			fpath = dir.Join(core.Path(basename))
			err = fpath.WriteFile(file.ExpandedData, 0o600)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *LogSendCommand) SetGlobalContext(g *shared.GlobalContext) {}

var _ shared.CLIApp = (*LogSendCommand)(nil)

func init() {
	AddCmd(&LogSendCommand{})
}
