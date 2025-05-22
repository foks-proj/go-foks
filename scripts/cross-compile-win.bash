#!/bin/bash
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.

set -euo pipefail
set -x 

usage() {
    echo "Usage: $0 -p {win-arm64|win-amd64|win-x86} [-sc]"
    exit 1
}

strip=0
packaging="local"
pkgTag=""
outSffx="exe"
doZip=0

# take two arguments: -p which can be arm64 or amd64, and also
# -s, which is a boolean flag that means to strip the binary
# use getopt to parse the arguments::
while getopts ":p:sc" opt; do
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
            pkgTag="-choco"
            outSffx="zip"
            doZip=1
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

if [ -z ${plat+x} ]; then
    echo "Platform not specified. Use -p to specify the platform."
    usage
fi

version=$(git describe --tags --always)
sversion=$(git describe --tags --abbrev=0)


docker_plat=''
docker_file=''
goarch=''
cxx=''
filearch=''
cc=''
case $plat in
    win-arm64)
        echo "not yet supported!"
        exit 1
        docker_plat='linux/arm64'
        docker_file=dockerfiles/cross-compile-win-arm64.dev
        goarch=arm64
        filearch=amd64
        ;;
    win-amd64)
        docker_plat='linux/amd64'
        docker_file=dockerfiles/cross-compile-win-amd64.dev
        cc=x86_64-w64-mingw32-gcc
        cxx=x86_64-w64-mingw32-g++
        filearch=amd64
        ;;
    win-x86)
        docker_plat='linux/amd64'
        docker_file=dockerfiles/cross-compile-win-amd64.dev
        goarch=386
        cc=i686-w64-mingw32-gcc 
        cxx=i686-w64-mingw32-g++
        filearch=x86
        ;;
    *)
        echo "Invalid platform: $plat"
        usage
        ;;
esac

output=foks-${sversion}-win${pkgTag}-${filearch}.${outSffx}
target=build/${output}

tmpdir=""
if [ $doZip -eq 1 ]; then
    tmpdir=$(mktemp -d)
    outDir=${tmpdir}
    target=${outDir}/foks.exe
fi

build() {
    mkdir -p build/
    file_sffx=''
    if [ "$strip" -eq 1 ]; then
        file_sffx='.stripped'
    fi
    name=foks-${plat}-build
    tmp=temp-foks-${plat}

    docker build \
        -f ${docker_file} \
        --platform=${docker_plat} \
        -t ${name} \
        . 

    trimpath=''
    ldflags=" -X github.com/foks-proj/go-foks/client/libclient.LinkerVersion=${version} \
        -X github.com/foks-proj/go-foks/client/libclient.LinkerPackaging=${packaging} "

    if [ "$strip" -eq 1 ]; then
        trimpath='-trimpath'
        ldflags="${ldflags} -w -s"
    fi

    docker run --platform=${docker_plat} --name=${tmp} ${name} \
        "(cd /foks/go-foks/client/foks && \
        GOARCH=${goarch} CC=${cc} CXX=${cxx} \
        go build ${trimpath} -o foks.exe -ldflags '${ldflags}' .)"

    docker cp ${tmp}:/foks/go-foks/client/foks/foks.exe ${target}
    docker rm ${tmp}

    echo "Build for ${plat} is complete: ${target}"
}

pkgZip() {
    if [ $doZip -eq 1 ]; then
        final=build/${output}
        (cd ${tmpdir} && zip -r ${output} foks.exe)
        mv ${tmpdir}/${output} ${final}
        rm -rf ${tmpdir}
        echo "Zipped build for ${plat} is complete: ${final}"
    fi
}

build 
pkgZip


