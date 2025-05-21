#!/bin/bash

set -euo pipefail

version=$(git describe --tags --always)

usage() {
    echo "Usage: $0 -p {arm64|amd64} [-scl]"
    exit 1
}

strip=0
choco=0
lcl=0
plat="arm64"
packaging="darwin-zip"

# take two arguments: -p which can be arm64 or amd64, and also
# -s, which is a boolean flag that means to strip the binary
# use getopt to parse the arguments::
while getopts ":p:scl" opt; do
    case $opt in
        p)
            plat=$OPTARG
            ;;
        s)
            strip=1
            ;;
        c) 
            choco=1
            packaging="choco"
            ;;
        l)
            lcl=1
            packaging="local"
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            usage
            ;;
    esac
done
shift $((OPTIND -1))

if [ $# -ne 0 ]; then
   usage
fi

if [ "$plat" != "arm64" ] && [ "$plat" != "amd64" ]; then
    usage
fi

echo "Building darwin version $version"
echo "  - platform: $plat"
echo "  - stripping: $strip"
echo "  - choco: $choco"
echo "  - local: $lcl"

targ="build/win-${plat}/foks"
mkdir -p $(dirname ${targ})

src="./client/foks"
linkerVersion="-X github.com/foks-proj/go-foks/client/libclient.LinkerVersion=${version}"
linkerPackaging="-X github.com/foks-proj/go-foks/client/libclient.LinkerPackaging=${packaging}"
strip_w_flag=""
trimppath_flag=""

if [ "$strip" -eq 1 ]; then
    strip_w_flag="-w"
    trimppath_flag="-trimpath"
fi

set -x

export CGO_ENABLED=1
export GOOS=windows
export GOARCH=${plat} 

build_mode="build -o ${targ}"
if [ "$lcl" -eq 1 ]; then
    build_mode="install"
fi

go ${build_mode} \
    ${trimppath_flag} \
    -ldflags "${strip_w_flag} ${linkerVersion} ${linkerPackaging}" \
    ${src}

if [ "$lcl" -eq 1 ]; then
    echo "Build complete -> $(./scripts/gowhere.sh)/foks"
    exit 0
fi
echo "Build complete -> ${targ}"