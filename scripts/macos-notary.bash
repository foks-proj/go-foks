#!/bin/bash

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

targ=$(realpath $1)

set -x
xcrun notarytool submit ${targ} \
    --keychain-profile foks-notary-1 \
    --wait 