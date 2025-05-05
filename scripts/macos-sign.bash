#!/bin/bash

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

targ=$1

codesign \
    --force \
    --options runtime \
    --timestamp \
    --sign "Developer ID Application: NE43 INC (L2W77ZPF94)" \
    ${targ}
