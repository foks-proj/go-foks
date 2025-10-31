#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.

FOKS_BIN_PATH=$(which foks)
if [ -z "$FOKS_BIN_PATH" ]; then
    echo "foks binary not found in PATH, cannot create git-remote-foks link"
    exit 1
fi
(cd $(dirname $FOKS_BIN_PATH) && ln -sf foks git-remote-foks) 
