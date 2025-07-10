#!/bin/sh
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.


. ./env.sh

get_port() {
    jsonnet ${TOPDIR}/conf/foks.jsonnet | jq .listen.$1.port
}

proxy_pair() {
    port=$(get_port $1)
    echo "${port}:localhost:${port}"
}

key=""
if [ -n "${SSH_KEY}" ]; then
    key="-i ${SSH_KEY}"
fi

ssh -N ${key} \
    -R $(proxy_pair reg) \
    -R $(proxy_pair probe) \
    -R $(proxy_pair user) \
    -R $(proxy_pair merkle_query) \
    -R $(proxy_pair beacon) \
    -R $(proxy_pair kv_store) \
    -R 80:localhost:${HTTP_LOCAL_PORT} \
    -R 443:localhost:${HTTPS_LOCAL_PORT} \
    root@${SSH_PROXY_HOSTNAME}
