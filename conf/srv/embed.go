package srv

import (
	_ "embed"
)

//go:embed foks.jsonnet
var FoksConfig string

//go:embed foks-docker-compose.jsonnet
var FoksDockerComposeConfig string
