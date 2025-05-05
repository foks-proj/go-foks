#!/bin/bash

set -euo pipefail

version=$(git describe --tags --always)

usage() {
    echo "Usage: $0 -p {arm64|amd64} [-s]"
    exit 1
}

strip=0

# take two arguments: -p which can be linux-arm64 or linux-amd64, and also
# -s, which is a boolean flag that means to strip the binary
# use getopt to parse the arguments::
while getopts ":p:s" opt; do
    case $opt in
        p)
            plat=$OPTARG
            ;;
        s)
            strip=1
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

targ="build/darwin-${plat}/foks"
mkdir -p $(dirname ${targ})

src="./client/foks"
linkerVersion="-X github.com/foks-proj/go-foks/client/foks/cmd.LinkedVersion=${version}"
strip_w_flag=""
trimppath_flag=""

if [ "$strip" -eq 1 ]; then
    strip_w_flag="-w"
    trimppath_flag="-trimpath"
fi

set -x

export CGO_ENABLED=1
export GOOS=darwin
export GOARCH=${plat} 

go build -o ${targ} \
    ${trimppath_flag} \
    -ldflags "${strip_w_flag} ${linkerVersion}" \
    ${src}

echo "Build complete -> ${targ}"
