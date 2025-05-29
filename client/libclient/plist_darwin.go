// Copyright (c) 2025 ne43, Inc.
// Licensed under the MIT License. See LICENSE in the project root for details.

package libclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"

	"github.com/foks-proj/go-foks/lib/core"
)

var LaunchCtl = "/bin/launchctl"

// Plist is used to manage MacOS/Darwin launching of the background agent process. This class is
// used to write a text file down on the file system, which is later sourced via shell out to
// the `launchctl` command.
type Plist struct {
	label  string
	home   string
	path   string
	logDir string
}

func (p *Plist) Template() string {
	return `<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\" >
<plist version='1.0'>
	<dict>
	  <key>Label</key><string>{{.Label}}</string>
	  <key>ProgramArguments</key>
	  <array>
	    <string>{{.Program}}</string>
		<string>--home</string>
		<string>{{.Home}}</string>
		<string>--config</string>
		<string>{{.Config}}</string>
		<string>agent</string>
	  </array>
	  <key>RunAtLoad</key><true/>
	  <key>KeepAlive</key><true/>
	  <key>StandardErrorPath</key>
	  <string>{{.LogDir}}/agent.err.log</string>
	  <key>StandardOutputPath</key>
	  <string>{{.LogDir}}/agent.out.log</string>
	</dict>
</plist>`
}

func NewPlist() *Plist {
	return &Plist{}
}

func (p *Plist) Path() string {
	return p.path
}

func (p *Plist) DomainAndLabel(m MetaContext) (string, error) {
	err := p.Configure(m)
	if err != nil {
		return "", err
	}
	domain, err := p.Domain(m)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s/%s", domain, p.label), nil
}

func (p *Plist) Domain(m MetaContext) (string, error) {
	uid := os.Getuid()
	if uid < 0 {
		return "", errors.New("getuid failed")
	}
	return fmt.Sprintf("gui/%d", uid), nil
}

func (p *Plist) launchctlRaw(m MetaContext, args []string) ([]byte, error) {
	cmd := exec.CommandContext(m.Ctx(),
		LaunchCtl,
		args...,
	)
	return cmd.CombinedOutput()
}

func (p *Plist) launchctl(m MetaContext, args []string) error {
	out, err := p.launchctlRaw(m, args)
	if err != nil {
		return err
	}
	if len(out) > 0 && strings.Contains(string(out), "failed") {
		return errors.New(string(out))
	}
	return nil
}

func (p *Plist) Load(m MetaContext) error {
	_, err := p.Status(m)
	if err == nil {
		return errors.New("already loaded")
	}
	err = p.Write(m)
	if err != nil {
		return err
	}
	d, err := p.Domain(m)
	if err != nil {
		return err
	}
	return p.launchctl(m, []string{"bootstrap", d, p.path})
}

type PlistStatus struct {
	Pid            int    `json:"pid"`
	State          string `json:"state"`
	Label          string `json:"label"`
	LabelAndDomain string `json:"label_and_domain"`
	MoreInfo       string `json:"more_info"`
	Path           string `json:"path"`
}

func (p *PlistStatus) String() string {
	buf := bytes.NewBuffer(nil)
	je := json.NewEncoder(buf)
	je.SetIndent("", "  ")
	err := je.Encode(p)
	if err != nil {
		return fmt.Sprintf("failed to encode plist status: %v", err)
	}
	return buf.String()
}

type PlistPrint struct {
	pid   int
	state string
	path  string
}

func parsePrint(p []byte) (*PlistPrint, error) {
	lines := strings.Split(string(p), "\n")
	var ret PlistPrint
	for _, l := range lines {
		parts := strings.Split(l, "=")
		if len(parts) != 2 {
			continue
		}
		p0 := strings.TrimSpace(parts[0])
		p1 := strings.TrimSpace(parts[1])
		switch p0 {
		case "pid":
			pid, err := strconv.Atoi(p1)
			if err != nil {
				return nil, err
			}
			ret.pid = pid
		case "state":
			ret.state = p1
		case "path":
			ret.path = p1
		}
	}
	return &ret, nil
}

func (p *Plist) Status(m MetaContext) (*PlistStatus, error) {
	l, err := p.DomainAndLabel(m)
	if err != nil {
		return nil, err
	}
	out, err := p.launchctlRaw(m, []string{"print", l})
	if err != nil {
		return nil, err
	}
	pr, err := parsePrint(out)
	if err != nil {
		return nil, err
	}
	return &PlistStatus{
		Pid:            pr.pid,
		State:          pr.state,
		Label:          p.label,
		Path:           pr.path,
		LabelAndDomain: l,
		MoreInfo:       fmt.Sprintf("%s print %s", LaunchCtl, l),
	}, nil
}

func (p *Plist) Restart(m MetaContext) (int, string, error) {
	status, err := p.Status(m)
	if err != nil {
		return 0, "", err
	}
	err = p.launchctl(m, []string{"kickstart", "-k", status.LabelAndDomain})
	if err != nil {
		return 0, "", err
	}
	return status.Pid, status.LabelAndDomain, nil
}

func (p *Plist) Unload(m MetaContext) (string, string, error) {
	status, err := p.Status(m)
	if err != nil {
		return "", "", err
	}
	err = p.launchctl(m, []string{"bootout", status.LabelAndDomain})
	if err != nil {
		return "", "", err
	}
	err = os.Remove(status.Path)
	if err != nil {
		return "", "", err
	}
	return status.LabelAndDomain, status.Path, nil
}

func (p *Plist) Configure(m MetaContext) error {
	if len(p.label) > 0 {
		return nil
	}
	label, err := m.G().Cfg().AgentProcessLabel()
	if err != nil {
		return err
	}
	hf := m.G().Cfg().HomeFinder()
	home, err := hf.Home(false)
	if err != nil {
		return err
	}
	logDir, err := hf.LogDir()
	if err != nil {
		return err
	}
	data := struct {
		Label string
		Home  string
	}{
		Label: label,
		Home:  home,
	}
	plistPathTemplate, err := m.G().Cfg().PlistPathTeplate()
	if err != nil {
		return err
	}
	pathT, err := template.New("plistPath").Parse(plistPathTemplate)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	err = pathT.Execute(buf, data)
	if err != nil {
		return err
	}
	p.home = home
	p.logDir = logDir
	p.label = label
	p.path = buf.String()

	return nil
}

func (p *Plist) Write(m MetaContext) error {

	err := p.Configure(m)
	if err != nil {
		return err
	}

	prog, err := os.Executable()
	if err != nil {
		return err
	}
	cfg, err := m.G().Cfg().ConfigFile()
	if err != nil {
		return err
	}

	// Fix up relative paths by prefixing working directory, for writing into
	// the plist file.
	fix := func(p core.Path) core.Path {
		s := p.String()
		if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") {
			cwd, err := os.Getwd()
			if err == nil {
				return core.Path(cwd).Join(p)
			}
		}
		return p
	}
	home := fix(core.Path(p.home))
	cfg = fix(cfg)
	logDir := fix(core.Path(p.logDir))
	data := struct {
		Label   string
		Program string
		Home    core.Path
		Config  core.Path
		LogDir  core.Path
	}{
		Label:   p.label,
		Program: prog,
		Home:    home,
		Config:  cfg,
		LogDir:  logDir,
	}
	plistPath := core.Path(p.path)

	launchdT, err := template.New("launchdConfig").Parse(p.Template())
	if err != nil {
		return err
	}
	err = plistPath.MakeParentDirs()
	if err != nil {
		return err
	}
	f, err := plistPath.OpenFile(os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	err = launchdT.Execute(f, data)
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}

	return nil
}
