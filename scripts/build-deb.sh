#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.

# This script builds a debian package for foks via docker, so should work on most platforms.


usage() {
    echo "Usage: $0 -p {arm64|amd64}"
    exit 1
}

while getopts ":p:" opt; do
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

if [ ! -f ".top" ]; then
    echo "This script must be run from the root of the foks repository."
    exit 1
fi

if [ "$plat" != "arm64" ] && [ "$plat" != "amd64" ]; then
    usage
fi

vversion=$(git describe --tags --abbrev=0)
version=$(echo $vversion | sed 's/^v//')

if [ -z "$version" ]; then
    echo "No version found. Please tag the commit with a version."
    exit 1
fi

echo "Building foks version $version for $plat"

make_control() {
    cat <<EOF > build/debian.control-${version}-${plat}
Package: foks
Version: ${version}
Section: utils
Priority: optional
Architecture: ${plat}
Maintainer: Maxwell Krohn <max@ne43.com>
Depends: libpcsclite-dev (>= 1.9.9), libc6 (>= 2.31)
Description: Access the Federated Open Key Service (FOKS)
 with this single CLI-application. Supplies signup, key management,
 team management, KV-store put-get and also git remote helper.
EOF
}

make_copyright() {
    cat <<EOF > build/debian.copyright
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: go-foks
Source: https://github.com/foks-proj/go-foks

Files: *
Copyright: 2025 Maxwell Krohn <max@ne43.com>
License: MIT

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

EOF
}

make_changelog() {
    cl_vers=$(grep -- '- version' changelog.yml  | head -n1 |  awk -F: ' { print $2 }' | xargs)
    if [ "$cl_vers" != "$version" ]; then
        echo "Version in changelog.yml ($cl_vers) does not match version ($version)"
        exit 1
    fi
    go run tools/changelog-deb/main.go < changelog.yml | gzip -n9c > build/changelog.debian-${version}.gz
}

build_deb() {
    name=foks-deb-${version}-${plat}
    tmp=tmp-${name}
    docker_plat=linux/${plat}
    docker build \
        -f dockerfiles/deb-pkg.dev \
        --platform=${docker_plat} \
        --build-arg VERSION=${version} \
        --build-arg PLAT=${plat} \
        -t ${name} \
        .
    docker create  \
        --platform=${docker_plat} \
        --name=${tmp} \
        ${name}
    docker cp ${tmp}:/pkg/foks_${version}_${plat}.deb build/
    docker rm ${tmp}

    echo "Debian package foks_${version}_${plat}.deb created in build/"
}

check_foks_version() {
    foks_vers=$(go run client/foks/main.go --version | awk '{print $3}')
    if [ "$foks_vers" != "$version" ]; then
        echo "Version in foks binary ($foks_vers) does not match version ($version)"
        exit 1
    fi
}

check_foks_version
make_copyright
make_control
make_changelog
build_deb