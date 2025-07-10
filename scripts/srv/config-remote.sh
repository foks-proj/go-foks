#!/bin/bash
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.

. ./env.sh

ssh ${PROD_SSH} "mkdir -p \
    ${REMOTE_TOPDIR}/bin \
    ${REMOTE_TOPDIR}/conf \
    ${REMOTE_TOPDIR}/sh \
    ${REMOTE_TOPDIR}/tmp \
    ${REMOTE_TOPDIR}/tls \
    ${REMOTE_TOPDIR}/system \
    ${REMOTE_TOPDIR}/scripts"

scp conf/* ${PROD_SSH}:${REMOTE_TOPDIR}/conf/

echo "#!/bin/bash" > env-remote.sh
echo "" >> env-remote.sh
echo "export REMOTE_TOPDIR=${REMOTE_TOPDIR}" >> env-remote.sh
echo 'export TOPDIR=${REMOTE_TOPDIR}' >> env-remote.sh
grep -v '^export TOPDIR=' env.sh >> env-remote.sh
scp env-remote.sh ${PROD_SSH}:${REMOTE_TOPDIR}/env.sh

ssh ${PROD_SSH} "cd ${REMOTE_TOPDIR}/scripts && \
    ln -sf ${REMOTE_TOPDIR}/env.sh env.sh"
