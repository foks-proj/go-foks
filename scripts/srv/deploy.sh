#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.


. ./env.sh

export GOOS=linux
export GOARCH=arm64
export GOFLAGS="-tags=noresinit"

(cd ${SRCDIR}/server/foks-tool && go build)
(cd ${SRCDIR}/server/foks-server && go build)

rev=$(cd ${SRCDIR} && git rev-parse --short HEAD)

scp ${SRCDIR}/server/foks-tool/foks-tool ${PROD_SSH}:${REMOTE_TOPDIR}/bin/foks-tool.${rev}
scp ${SRCDIR}/server/foks-server/foks-server ${PROD_SSH}:${REMOTE_TOPDIR}/bin/foks-server.${rev}

ssh ${PROD_SSH} "cd ${REMOTE_TOPDIR}/bin && \
    ln -sf foks-tool.${rev} foks-tool && \
    ln -sf foks-server.${rev} foks-server"

ssh ${ROOT_PROD_SSH} "cd ${REMOTE_TOPDIR}/bin && \
    sudo setcap cap_net_bind_service=+ep foks-server.${rev} && \
    sudo setcap cap_net_bind_service=+ep foks-tool.${rev}"

scp ${SRCDIR}/scripts/build.bash ${PROD_SSH}:${REMOTE_TOPDIR}/scripts/
