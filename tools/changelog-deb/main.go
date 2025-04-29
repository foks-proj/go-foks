package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Project    string  `yaml:"project"`
	Maintainer string  `yaml:"maintaner"`
	Changelog  []Entry `yaml:"changelog"`
}

type Entry struct {
	Version string    `yaml:"version"`
	Urgency string    `yaml:"urgency"`
	Stable  bool      `yaml:"stable"`
	Date    LocalTime `yaml:"date"`
	Changes []Change  `yaml:"changes"`
}

type Change struct {
	Desc   string `yaml:"desc"`
	Closes []any  `yaml:"closes"`
}

// LocalTime wraps time.Time to parse custom date format.
type LocalTime struct {
	time.Time
}

func (lt *LocalTime) UnmarshalYAML(value *yaml.Node) error {
	// Expect format "2006-01-02 15:04:05 +0400"
	parsed, err := time.Parse("2006-01-02 15:04:05 -0700", value.Value)
	if err != nil {
		return err
	}
	lt.Time = parsed.Local()
	return nil
}

func stable(stable bool) string {
	if stable {
		return "stable"
	}
	return "unstable"
}

func doChangelog() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	for _, entry := range cfg.Changelog {
		fmt.Printf("%s (%s) %s; urgency=%s\n\n",
			cfg.Project,
			entry.Version,
			stable(entry.Stable),
			entry.Urgency,
		)

		for _, change := range entry.Changes {
			fmt.Printf("  * %s\n", change.Desc)
			if len(change.Closes) > 0 {
				var closes []string
				for _, c := range change.Closes {
					switch v := c.(type) {
					case string:
						closes = append(closes, v)
					case int:
						closes = append(closes, fmt.Sprintf("#%d", v))
					}
				}
				closesStr := strings.Join(closes, ", ")
				fmt.Printf("   Closes: %s\n", closesStr)
			}
		}
		fmt.Printf("\n -- %s  %s\n\n", cfg.Maintainer, entry.Date.Format(time.RFC1123Z))
	}
	return nil
}

func main() {
	err := doChangelog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
