#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.

set -e -u

usage() {
    echo "Usage: $0 -p {linux-arm64|linux-amd64} [-s]"
    exit 1
}

plat=""
os=""

# take two arguments: -p which can be linux-arm64 or linux-amd64, and also
# -s, which is a boolean flag that means to strip the binary
# use getopt to parse the arguments::
while getopts ":p:o:" opt; do
    case $opt in
        p)
            plat=$OPTARG
            ;;
        o)
            os=$OPTARG
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

if [ "$plat" != "linux-arm64" ] && [ "$plat" != "linux-amd64" ]; then
    usage
fi

build() {
    mkdir -p build/
    splat=$(echo $plat | sed 's#linux-##')
    output=foks.${os}.${splat}
    name=foks-linux-${os}-build-${splat}
    tmp=temp-${name}
    docker_plat=$(echo $plat | sed 's#-#/#')

    docker build \
        -f dockerfiles/compile-deb-bin.dev \
        --platform=${docker_plat} \
        -t ${name} \
        --build-arg VERSION=$(git describe --tags --always) \
        --build-arg PACKAGING=${os} \
        . 
    docker create --platform=${docker_plat} --name=${tmp} ${name}
    docker cp ${tmp}:/foks/foks build/${output}
    docker rm ${tmp}

    echo "Build for ${os} ${plat} is complete: build/${output}"
}

build 
