#!/bin/bash

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <dir>"
    exit 1
fi

if [ ! -f .top ]; then
    echo "Error: .top file not found. Please run this script from the top-level directory."
    exit 1
fi

dir=$1
plat=$(basename $dir)

cd ${dir}/..
targ=foks.zip

version=$(git tag --list | grep -E '^v[0-9]+\.' | sort -V | tail -1)

set -x
targ=foks-${version}-${plat}.zip
rm -f ${targ}
ditto -c -k --sequesterRsrc ${plat}/foks ${targ}
cd ${plat}
rm -f foks.zip
ln -s ../${targ} foks.zip
