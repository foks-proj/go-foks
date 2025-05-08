#!/bin/bash
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.


set -e -o pipefail

. ./env.sh

is_env_bool_set() {
    local var_name=$1
    [[ -n "${!var_name}" && "${!var_name}" -eq 1 ]]
}

if (is_env_bool_set "TEST") || (is_env_bool_set "DEV"); then
    ./build-go.bash
fi

## constants
##
TLSDIR=${TOPDIR}/tls
##
##

##
## Setup data arrays
##
declare -a services=(
    "reg" "user" "merkle_builder" "internal_ca" "merkle_query" "queue" 
    "merkle_batcher" "merkle_signer" "kv_store" "quota" "autocert"
)

# New array to store modified service names
declare -a services_hyphenate=()

# Loop through each element in the original array
for service in "${services[@]}"; do
    # Replace underscores with hyphens
    tmp=${service//_/-}
    # Add the modified service name to the new array
    services_hyphenate+=("$tmp")
done

declare -a all_services_hyphenate=("${services_hyphenate[@]}")
all_services_hyphenate+=("probe" "beacon" "web")
##
## done setup
##

##
## helper functions
##
tool() {
    ${TOOL} --config-path ${CONF} "$@"
}

pm2() {
    (
        cd ${TOPDIR}
        if [ ! -f ./node_modules/.bin/pm2 ]; then
            npm i pm2
        fi
        ./node_modules/.bin/pm2 $@
    )
}

autocert() {
    tool autocert --port ${HTTP_LOCAL_PORT} $1
}
##
##

##
## work functions
##
setup_tools() {
    (cd ${SRCDIR} && make srv-setup)
}

make_web_assets() {
    (cd ${SRCDIR} && make srv-assets)
}

create_docker_db() {
    if is_env_bool_set "USE_RDS"; then
        return
    fi
    docker \
        run -d --name foks-postgresql \
        -v foks-db:/var/lib/postgresql/data \
        -p ${DBPORT}:5432 \
        -e POSTGRES_PASSWORD=${DBPW_ROOT} \
        arm64v8/postgres:17-alpine
}

create_foks_user() {
    PGPASSWORD=${DBPW_ROOT} psql \
        -h ${DBHOST} -p ${DBPORT} -U postgres \
        -c "CREATE USER foks WITH CREATEDB PASSWORD '${DBPW_FOKS}';"
}

init_db() {
    ${TOOL} --config-path ${CONF} init-db --all 
}

make_host_chain() {
    tool make-host-chain \
        --keys-dir ${TOPDIR}/keys \
        --hostname ${PRIMARY_HOSTNAME}
}

noop() {
    echo "No operation"
}

issue_backend_cert() {
    hosts=${HOSTS}
    if [ -z "${hosts}" ]; then 
        hosts=127.0.0.1,localhost,::1,${PRIMARY_HOSTNAME}
    fi
    tool issue-cert \
        --type backend-x509-cert \
        --hosts ${hosts}
}

issue_frontend_cert() {
    hosts=${HOSTS}
    if [ -z "${hosts}" ]; then
        if is_env_bool_set "TEST"; then
            hosts=127.0.0.1,localhost,::1,${PRIMARY_HOSTNAME}
        else 
            hosts=${PRIMARY_HOSTNAME}
        fi
    fi
    tool issue-cert \
        --type hostchain-frontend-x509-cert \
        --hosts ${hosts}
}

issue_probe_and_beacon_certs_test() {
    hosts=127.0.0.1,localhost,::1,${PRIMARY_HOSTNAME}

    tool lets-encrypt \
        --ca-cert ${TLSDIR}/probe_ca.rootca.cert \
        --ca-key ${TLSDIR}/probe_ca.rootca.key
}

issue_probe_cert_prod() {
    autocert probe
}

issue_beacon_cert_prod() {
    if [[ -n "${BEACON}" && "${BEACON}" -eq 1 ]]; then
        autocert beacon
    fi
}

start_ssh_proxy() {
    pm2 start ecosystem.config.js --only ssh-tun
}

write_public_zone() {
    tool write-public-zone \
        --key ${TOPDIR}/keys/metadata.host.key
}

init_merkle_tree() {
    tool init-merkle-tree 
}

make_invite_code() {
    PGPASSWORD=${DBPW_FOKS} psql \
        -h ${DBHOST} -p ${DBPORT} \
        -U foks foks_users \
        -c "INSERT INTO multiuse_invite_codes (short_host_id, code, num_uses, valid) VALUES (1, '${INVITECODE}', 0, TRUE);"
}

sleep2() {
    sleep 2
}

write_dbkeys() {
    tool write-db-keys
}

make_systemd_units() {
    for i in "${all_services_hyphenate[@]}"
    do
        cat <<EOF > ${TOPDIR}/system/foks-${i}.service
[Unit]
Description=FOKS ${i} service
After=network.target

[Service]
Type=simple
User=${USER}
Group=${USER}
WorkingDirectory=$(realpath ${TOPDIR}/tmp)
ExecStart=${SERVER} --config-path $(realpath ${CONF}) --refork ${i}
SyslogIdentifier=foks-${i}
EOF
        if [[ "${i}" == "web" || "${i}" == "autocert" ]]; then
            cat <<EOF >> ${TOPDIR}/system/foks-${i}.service
AmbientCapabilities=CAP_NET_BIND_SERVICE
EOF
        fi

        cat <<EOF >> ${TOPDIR}/system/foks-${i}.service

[Install]
WantedBy=multi-user.target
EOF

    done
}

install_systemd_units() {
    (
        cd ${TOPDIR}/system
        for i in "${all_services_hyphenate[@]}"
        do
            sudo ln -sf $(realpath foks-${i}.service) /etc/systemd/system/
        done
    )
}

start_systemd() {
    for i in "${all_services_hyphenate[@]}"
    do
        sudo service foks-${i} start
    done
}

start_pm2() {
    pm2 start
}

beacon_register() {
    tool beacon-register
}

init_mgmt_vhost() {
    tool init-vhost \
    --vhost ${MGMT_HOSTNAME} \
    --code ${VHOST_INVITECODE} \
    --host-type vhost-management
}

init_big_top_vhost() {
    tool init-vhost \
    --vhost ${BIG_TOP_HOSTNAME} \
    --code ${VHOST_INVITECODE} \
    --host-type big-top
}

init_plans() {

    # For testing webhooks and renewals, have a stupid option to refresh
    # once a day
    if (is_env_bool_set "TEST") || (is_env_bool_set "DEV"); then
        tool create-plan \
            --quota 100MB \
            --name "micro-1" \
            --display-name "Micro" \
            --prices 1d:129,1m:495 \
            --max-seats 10 \
            --details '1GB of storage' \
            --details 'Up to 10 teams can share this quota' \
            --promoted
    fi

     tool create-plan \
        --quota 1GB \
        --name "basic-1" \
        --display-name "Basic" \
        --prices 1m:495,1y:4950 \
        --max-seats 10 \
        --details '1GB of storage' \
        --details 'Up to 10 teams can share this quota' \
        --promoted

    tool create-plan \
        --quota 10GB \
        --name "pro-1" \
        --display-name "Pro" \
        --prices 1m:1495,1y:14950 \
        --max-seats 100 \
        --details '10GB of storage' \
        --details 'Up to 100 teams can share this quota' \
        --promoted

    tool create-plan \
        --quota 1TB \
        --name "xl-1" \
        --display-name "XL" \
        --prices 1m:7995,1y:79950 \
        --max-seats 1000 \
        --details '1TB of storage' \
        --details 'Up to 1000 teams can share this quota' \
        --promoted

    tool create-plan \
        --quota 1GB \
        --name "vhost-basic-1" \
        --display-name 'VHost Basic' \
        --prices 1m:1995,1y:19950 \
        --max-vhosts 2 \
        --max-seats 20 \
        --details '1GB of storage' \
        --details 'Up to 20 total users across 2 hosts' \
        --details 'Unlimited teams' \
        --vhost-scope \
        --promoted


    tool create-plan \
        --quota 10GB \
        --name "vhost-pro-1" \
        --display-name 'VHost Pro' \
        --prices 1m:4995,1y:49950 \
        --max-vhosts 10 \
        --max-seats 200 \
        --details '10GB of storage' \
        --details 'Up to 200 total users across 10 hosts' \
        --details 'Unlimited teams' \
        --details 'Ouath2 SSO' \
        --vhost-scope \
        --sso \
        --promoted

    tool create-plan \
        --quota 1TB \
        --name "vhost-enterprise-1" \
        --display-name 'VHost Enterprise' \
        --prices 1m:18995,1y:189950 \
        --max-vhosts 100 \
        --max-seats 2000 \
        --details '100GB of storage' \
        --details 'Up to 2000 total users across 100 hosts' \
        --details 'Unlimited teams' \
        --details 'Ouath2 SSO' \
        --vhost-scope \
        --sso \
        --promoted
}

##
## done work functions
##

declare -a sequence=(
    "td:setup_tools p:noop"
    "td:make_web_assets p:noop"
    "create_docker_db"
    "sleep2"
    "create_foks_user"
    "init_db"
    "t:gen_probe_ca pd:noop"
    "gen_cks_cas"
    "make_host_chain"
    "issue_frontend_cert"
    "issue_backend_cert"
    "d:start_ssh_proxy pt:noop"
    "t:issue_probe_and_beacon_certs_test pd:issue_probe_cert_prod"
    "t:noop pd:issue_beacon_cert_prod"
    "init_merkle_tree"
    "write_public_zone"
    "make_invite_code"
    "write_dbkeys"
    "p:make_systemd_units dt:noop"
    "p:install_systemd_units dt:noop"
    "p:start_systemd dt:start_pm2"
    "beacon_register"
    "init_mgmt_vhost"
    "init_big_top_vhost"
    "init_plans"
)

get_raw_op() {
    echo ${sequence[$1]}
}

bad_op() {
    echo "bad operation in list"
    exit 1
}

get_op() {
    raw=$(get_raw_op $1)

    if [ -z "$raw" ]; then
        echo ""
        return
    fi

    if [ $(echo ${raw} | wc -w ) = "1" ]; then
        echo ${raw}
        return
    fi

    if is_env_bool_set "TEST" ; then 
        echo ${raw} | perl -ne '{ print "$1\n" if /t[pd]*:(\S+)/ }'
        return
    fi

    if is_env_bool_set "PROD" ; then
        echo ${raw} | perl -ne '{ print "$1\n" if /p[dt]*:(\S+)/ }'
        return
    fi

    if is_env_bool_set "DEV" ; then
        echo ${raw} | perl -ne '{ print "$1\n" if /d[pt]*:(\S+)/ }'
        return
    fi

    echo "bad_op"
}

next() {
    next_op=0
    step=${TOPDIR}/build.step
    if [ -f ${step} ]; then
        last_op=$(cat ${step})
        next_op=$((last_op + 1))
    fi
    op=$(get_op $next_op)
    if [ -z "$op" ]; then
        echo eof
        return
    fi
    echo "Peforming operation ${next_op}: ${op}" >&2
    $op
    if [ "$?" -ne 0 ]; then
        echo "Operation failed: ${op}"
        exit 1
    fi
    echo $next_op > ${step}
    echo ok
}

list() {
    for i in $(seq 0 $((${#sequence[@]} - 1))); do
        echo "$i: $(get_op $i)"
    done
}

all() {
    while [ 1 ]; do
        ret=$(next)
        if [ "$ret" = "eof" ]; then
            break
        fi
    done
}

gen_cks_cas() {
    types=( "internal-client-ca" "external-client-ca" "backend-ca" )
    for i in "${types[@]}"
    do
        tool gen-ca --type ${i}
    done
}

gen_probe_ca() {
    tool gen-ca \
        --cert ${TOPDIR}/tls/probe_ca.rootca.cert \
        --key ${TOPDIR}/tls/probe_ca.rootca.key
}

single() {
    op=$(get_op $1)
    if [ -z "$op" ]; then
        echo "No operation at index $1"
        exit 1
    fi
    echo "Peforming operation $1: ${op}"
    $op
}

service() {
    for i in "${all_services_hyphenate[@]}"
    do
        sudo service foks-${i} $1
    done
}

usage() {
    echo "Usage: $0 <list|all|next|single <op-num>|service <start|stop|restart>>"
    exit 1
}

if [ $# -eq 0 ]; then
    usage
fi

case $1 in
    list)
        if [ $# -ne 1 ]; then
            usage
        fi
        list
        ;;
    all)
        if [ $# -ne 1 ]; then
            usage
        fi
        all
        ;;
    next)
        if [ $# -ne 1 ]; then
            usage
        fi
        res=$(next)
        if [ "$res" = "eof" ]; then
            echo "No more operations"
        fi
        ;;
    single)
        if [ $# -ne 2 ]; then
            usage
        fi
        single $2
        ;;
    service)
        if [ $# -ne 2 ]; then
            usage
        fi
        service $2
        ;;
    *)
        usage
        ;;
esac

