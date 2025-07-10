#!/bin/bash

set -euo pipefail
top=".go-foks-src-top"

fail_in_src() {(
    for (( i=0; i<250; i++ )); do
        if [ -f "$top" ]; then
            echo "This script should not be run from the source directory."
            exit 1
        fi
        if [ $(pwd) = "/" ]; then
            return
        fi
        cd ..
    done
    echo "Stuck in a symlink loop; aborting."
    exit 1
)}

my_realpath() {
    # Resolve the absolute path of a file or directory
    local path="$1"
    realpath $path
}