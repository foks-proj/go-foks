#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.


usage() {
    echo "Usage: $0 -p {linux-arm64|linux-amd64} [-s]"
    exit 1
}

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

if [ "$plat" != "linux-arm64" ] && [ "$plat" != "linux-amd64" ]; then
    usage
fi

build() {
    mkdir -p build/
    file_sffx=''
    image_sffx=''
    if [ "$strip" -eq 1 ]; then
        file_sffx='.stripped'
        image_sffx='-stripped'
    fi
    output=foks.${plat}${file_sffx}
    name=foks-${plat}-build${image_sffx}
    tmp=temp-foks-${plat}
    docker_plat=$(echo $plat | sed 's#-#/#')

    docker build \
        -f dockerfiles/cross-compile.dev \
        --platform=${docker_plat} \
        -t ${name} \
        --build-arg STRIP=${strip} \
        . 
    docker create --platform=${docker_plat} --name=${tmp} ${name}
    docker cp ${tmp}:/foks/go-foks/client/foks/foks build/${output}
    docker rm ${tmp}

    echo "Build for ${plat} is complete: build/${output}"
}

build 
