package simple_ui

import (
	"fmt"

	"github.com/foks-proj/go-foks/client/libclient"
	"github.com/foks-proj/go-foks/lib/core"
	"github.com/foks-proj/go-foks/lib/libterm"
	"github.com/foks-proj/go-foks/proto/lcl"
	"github.com/manifoldco/promptui"
)

type LogSendUI struct {
	spinner *Spinner
}

func (s *LogSendUI) Outputf(f string, args ...interface{}) {
	fmt.Printf(f, args...)
}

func (s *LogSendUI) Output(msg string) {
	fmt.Print(msg)
}

func (l *LogSendUI) ApproveLogs(m libclient.MetaContext, logs lcl.LogSendSet) error {
	l.Output("🔍 Sending the following logs for analysis:\n\n")
	for _, log := range logs.Files {
		l.Outputf("    - %s\n", log)
	}
	l.Output("\n")
	l.Output(
		libterm.MustRewrapSense(
			`Feel free to examine your logs to be certain that you are comfortable
sharing their contents with the FOKS developers. We are careful to exclude sensitive data
from logs, but please check our work. If you notice any sensitive data in these logs, do not send and please file a GitHub issue.
Thank you for helping us to improve this software.`, 0),
	)
	l.Output("\n")

	prompt := promptui.Select{
		Label: "Go ahead and share logs with the developers?",
		Items: []string{
			"❌ No, forget it",
			"✅ Yes, send them",
		},
	}
	idx, _, err := prompt.Run()
	if err != nil {
		return err
	}
	if idx == 0 {
		return core.CanceledInputError{}
	}
	return nil
}

func (l *LogSendUI) ShowLogSendRes(m libclient.MetaContext, res lcl.LogSendRes) error {
	l.Outputf("✅ Logs sent successfully; please relay these details to the developer you are working with!\n")
	l.Outputf(" - Id: %s\n", res.Id.String())
	l.Outputf(" - Server: %s\n", res.Host.String())
	return nil
}

func (l *LogSendUI) ShowStartSend(m libclient.MetaContext) error {
	l.spinner = NewSpinner("Sending logs...")
	l.spinner.Start()
	return nil
}

func (l *LogSendUI) ShowCompleteSend(m libclient.MetaContext, err error) error {
	var msg string
	if err != nil {
		msg = fmt.Sprintf(" ❌ Log send failed: %v", err)
	} else {
		msg = " 🎉 success"
	}
	l.spinner.Stop(msg)
	return nil
}

var _ libclient.LogSendUIer = &LogSendUI{}
