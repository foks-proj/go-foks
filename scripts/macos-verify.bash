#!/bin/bash

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

targ=$(realpath $1)
tmp=$(mktemp -d)

set -x
cd ${tmp}
unzip ${targ}
codesign -dvv foks
spctl -a -vv --type install foks
cd ..
rm -rf ${tmp}
