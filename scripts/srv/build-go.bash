#!/usr/bin/env bash
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.

set -euo pipefail

. ./env.sh

export GOBIN=$(realpath ${BINDIR})

fetch_tool() {
    latest=$(curl -fsSL  https://pkgs.foks.pub/stable/changelog.yml | grep -- "- version: " | head -1 | cut -d: -f2 | xargs)
    echo "Using latest version ${latest} of foks-tool and foks-server"

    # get if we are on arm64 or amd64
    plat=$(uname -m)
    case $plat in
        arm64|aarch64) plat="arm64" ;;
        x86_64|amd64) plat="amd64" ;;
        *)
            echo "Unsupported architecture: $plat"
            exit 1
            ;;
    esac
    fn="https://github.com/foks-proj/go-foks/releases/download/v${latest}/foks-tool.linux.${plat}.gz"
    echo "Downloading foks-tool from ${fn}"
    curl -fsSL ${fn} | gunzip > ${TOOL}
    chmod +x ${TOOL}
    ${TOOL} version
}

if [ "$RUN_REMOTE" -eq 1 ]; then
    echo "Running in remote mode, skipping build"
    exit 0
fi

if [ "$COMPILE_SERVER" -eq 1 ]; then
    (cd ${SRCDIR}/server/foks-tool && go install)
    if [ "$RUN_MODE" != "docker_compose" ]; then
        (cd ${SRCDIR}/server/foks-server && go install)
    fi
elif [ ! -f ${TOOL} ]; then
    fetch_tool
fi

if [ "$COMPILE_CLIENT" -eq 1 ]; then
    export GOBIN=$(realpath ${BINDIR_CLI})
    (cd ${SRCDIR}/client/foks && go install)
fi
