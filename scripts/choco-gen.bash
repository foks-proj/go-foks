#!/bin/bash

set -euo pipefail

if [ ! -f ".top" ]; then
	echo "Must be run from top dir"
	exit 1
fi

# take one optional argument: --version <version>
if [ $# -gt 2 ]; then
  echo "Usage: $0 [--version <version>]"
  exit 1
fi

if [ $# -eq 1 ] && [ "$1" != "--version" ]; then
  echo "Unknown argument: $1"
  echo "Usage: $0 [--version <version>]"
  exit 1
fi
if [ $# -eq 2 ]; then
  sversion="$2"
else
  # Get the latest tag from git
  sversion=$(git describe --tags --abbrev=0)
fi
if [ -z "$sversion" ]; then
  echo "No git tags found. Please create a tag to proceed."
  exit 1
fi
if [[ ! "$sversion" =~ ^v[0-9]+ ]]; then
  echo "Invalid version format: $sversion. Expected format: v<major>.<minor>.<patch>"
  exit 1
fi


numversion=$(echo $sversion | cut -d'v' -f2)

url32="https://github.com/foks-proj/go-foks/releases/download/${sversion}/foks-${sversion}-win-choco-x86.zip"
pkg32sha=$(curl -sSL $url32 | sha256sum | cut -d' ' -f1)
url64="https://github.com/foks-proj/go-foks/releases/download/${sversion}/foks-${sversion}-win-choco-amd64.zip"
pkg64sha=$(curl -sSL $url64 | sha256sum | cut -d' ' -f1)

mkdir -p pkg/choco/tools

cat <<EOF >pkg/choco/foks.nuspec
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>foks</id>
    <version>${numversion}</version>
    <packageSourceUrl>https://github.com/foks-proj/go-foks</packageSourceUrl>
    <owners>Maxwell Krohn</owners>
    <title>foks (Install)</title>
    <authors>Maxwell Krohn</authors>
    <projectUrl>https://foks.pub</projectUrl>
    <iconUrl>https://foks.pub/img/foks.png</iconUrl>
    <copyright>2025 ne43, Inc.</copyright>
    <licenseUrl>https://github.com/foks-proj/go-foks/blob/main/LICENSE</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <projectSourceUrl>https://github.com/foks-proj/go-foks</projectSourceUrl>
    <bugTrackerUrl>https://github.com/foks-proj/go-foks/issues</bugTrackerUrl>
    <tags>foks git e2ee pq key-management cli tools encryption</tags>
    <summary>command-line interface to FOKS, the Federated Open Key Service</summary>
    <description>
FOKS is a federated protocol that allows for online public key advertisement,
sharing, and rotation. It works for a user and their many devices, for many users who want
to form a group, for groups of groups etc. The core primitive is that several
private key holders can conveniently share a private key; and that private key
can simply correspond to another public/private key pair, which can be members
of a group one level up. This pattern can continue recursively forming a tree.

Crucially, if any private key is removed from a key share, all shares rooted at
that key must rotate. FOKS implements that rotation.

Like email or the Web, the world consists of multiple FOKS servers, administrated
independently and speaking the same protocol. Groups can span multiple federated
services.

Many applications can be built on top of this primitive but best suited are those
that share end-to-end encrypted, persistent information across groups of users with multiple
devices. For instance, files and git hosting.
    </description>
    <releaseNotes>https://github.com/foks-proj/go-foks/releases</releaseNotes>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
EOF

cat <<EOF >pkg/choco/tools/chocolateyinstall.ps1
\$toolsDir    = "\$(Split-Path -Parent \$MyInvocation.MyCommand.Definition)"

$packageArgs = @{
  packageName    = 'foks'
  fileType       = 'zip'
  url            = '${url32}'
  url64          = '${url64}'
  checksum64     = '${pkg64sha}'
  checksum       = '${pkg32sha}'
  checksumType   = 'sha256'
  checksumType64 = 'sha256'
  unzipLocation  = '\$toolsDir'
}

Install-ChocolateyZipPackage @packageArgs

# Need to copy the item over since we need to know the equivalent of os.Args[0]
# inside the executable, and we lose that via the shimming process.
Copy-Item "\$toolsDir\foks.exe" "\$toolsDir\git-remote-foks.exe" -Force

Install-BinFile \`
  -Name 'foks' \`
  -Path "\$toolsDir\foks.exe"

Install-BinFile \`
  -Name 'git-remote-foks' \`
  -Path "\$toolsDir\git-remote-foks.exe"
EOF

if [ $(which choco) ]; then
    (cd pkg/choco && \
	  choco pack && \
	  foks kv put --team build.win --force -p -f /rel/foks.${numversion}.nupkg foks.${numversion}.nupkg )
fi
