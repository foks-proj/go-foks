#!/bin/bash

set -euo pipefail

key=$(foks kv get --team build.win /keys/choco-api -)
sversion=$(git describe --tags --abbrev=0)
numversion=$(echo $sversion | sed 's/^v//')

choco apikey --key ${key} --source https://push.chocolatey.org/
choco push pkg/choco/foks.${numversion}.nupkg --source https://push.chocolatey.org/
