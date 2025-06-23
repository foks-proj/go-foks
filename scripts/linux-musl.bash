#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.

set -euo pipefail

version=$(git describe --tags --always)
short_version=$(git describe --tags --abbrev=0 | sed 's/^v//')

usage() {
    echo "Usage: $0 -p {arm64|amd64}"
    exit 1
}

plat=''

# take two arguments: -p which can be linux-arm64 or linux-amd64, and also
# -s, which is a boolean flag that means to strip the binary
# use getopt to parse the arguments::
while getopts ":p:s" opt; do
    case $opt in
        p)
            plat=$OPTARG
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

docker_plat="linux/$plat"

build() {
    mkdir -p build/
    output=foks-${short_version}.musl.linux.${plat}
    outgz=${output}.gz
    name=foks-musl-linux-${plat}
    tmp=temp-foks-musl-linux-${plat}

    docker build \
        -f dockerfiles/linux-musl.dev \
        --platform=${docker_plat} \
        -t ${name} \
        --build-arg VERSION=${version} \
        . 
    docker create --platform=${docker_plat} --name=${tmp} ${name}
    docker cp ${tmp}:/foks build/${output}
    docker rm ${tmp}

    (cd build && rm -f $outgz && gzip -9 -q ${output})

    echo "Build for ${plat} is complete: build/${outgz}"
}

build 
