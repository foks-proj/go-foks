#!/bin/bash

set -euo pipefail

usage() {
    echo "Usage: $0 <dir>"
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi
dir="$1"

if [ ! -d "$dir" ]; then
    echo "Directory $dir does not exist."
    exit 1
fi

vers=$(git describe --tags --abbrev=0 | sed 's/^v//')

parent_dir=$dir/manifests/n/ne43/foks/$vers
mkdir -p "$parent_dir"

url_64="https://github.com/foks-proj/go-foks/releases/download/v${vers}/foks-v${vers}-win-winget-amd64.zip"
url_32="https://github.com/foks-proj/go-foks/releases/download/v${vers}/foks-v${vers}-win-winget-x86.zip"

get_sum() {
    local url="$1"
    curl -sSL "$url" | sha256sum | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]'
}

sha_64=$(get_sum "$url_64")
sha_32=$(get_sum "$url_32")
date=$(date -u +"%Y-%m-%d")

cat <<EOF >"$parent_dir/ne43.foks.installer.yaml"
# Created using go-foks/scripts/winget-gen.bash
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.installer.1.10.0.schema.json

PackageIdentifier: ne43.foks
PackageVersion: ${vers}
InstallerType: zip
NestedInstallerType: portable
NestedInstallerFiles:
- RelativeFilePath: foks.exe
  PortableCommandAlias: foks
- RelativeFilePath: git-remote-foks.exe
  PortableCommandAlias: git-remote-foks
Installers:
- Architecture: x64
  InstallerUrl: ${url_64}
  InstallerSha256: ${sha_64}
- Architecture: x86
  InstallerUrl: ${url_32}
  InstallerSha256: ${sha_32}
ManifestType: installer
ManifestVersion: 1.10.0
ReleaseDate: ${date}
EOF

cat <<EOF >"$parent_dir/ne43.foks.locale.en-US.yaml"
# Created using go-foks/scripts/winget-gen.bash
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.defaultLocale.1.10.0.schema.json

PackageIdentifier: ne43.foks
PackageVersion: ${vers}
PackageLocale: en-US
Publisher: ne43
PackageName: foks
License: MIT License
ShortDescription: command-line interface to FOKS, the federated open key service
ManifestType: defaultLocale
ManifestVersion: 1.10.0
EOF

cat <<EOF >"$parent_dir/ne43.foks.yaml"
# Created using go-foks/scripts/winget-gen.bash
# yaml-language-server: \$schema=https://aka.ms/winget-manifest.1.10.0.schema.json

PackageIdentifier: ne43.foks
PackageVersion: ${vers}
ManifestType: installer
ManifestVersion: 1.10.0
DefaultLocale: en-US
EOF



