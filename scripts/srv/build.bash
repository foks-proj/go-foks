#!/bin/bash
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.

set -eou pipefail

. ./env.sh

# If we're running remotely, on a potentially different architecture, no need to build
# Should run `deploy.sh` instead
if [ "$RUN_REMOTE" -eq 0 ]; then
    ${SCRIPTDIR}/build-go.bash
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
all_services_hyphenate+=("probe")

if [ "$RUN_BEACON" -eq 1 ]; then
    all_servics_hyphenate+=("beacon")
fi
if [ "$SERVER_MODE" = "hosting_platform" ]; then
    all_services_hyphenate+=("web")
fi
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
    if [ "$RUN_REMOTE" -eq 1 ]; then
        echo "Skipping setup_tools since running remotely"
        return
    fi
    if [ "$SERVER_MODE" != "hosting_platform" ] ; then
        echo "Skipping setup_tools since standalone doesn't need a web portal"
        return
    fi
    (cd ${SRCDIR} && make srv-setup)
}

make_web_assets() {
    if [ "$RUN_REMOTE" -eq 1 ]; then
        echo "Skipping make_web_assets since running remotely"
        return
    fi
    if [ "$SERVER_MODE" != "hosting_platform" ] ; then
        (cd ${SRCDIR} && make srv-templ-build)
    else
        (cd ${SRCDIR} && make srv-assets)
    fi
}

docker_arch() {
    if [ "$(uname -m)" = "arm64" ]; then
        echo "arm64v8/"
    else
        echo ""
    fi
}

db_img() {
    echo "$(docker_arch)postgres:17-alpine"
}

create_docker_db() {
    if [ "$DB_BYO" -eq 1 ]; then
        echo "Skipping create_docker_db since using BYO DB"
        return
    fi
    docker \
        run -d --name foks-postgresql-${INSTANCE_ID} \
        -v foks-db-${INSTANCE_ID}:/var/lib/postgresql/data \
        -p ${DB_PORT}:5432 \
        -e POSTGRES_PASSWORD=${DB_PW_POSTGRES} \
        $(db_img)
    sleep2
}

create_foks_user() {
    PGPASSWORD=${DB_PW_POSTGRES} psql \
        -h ${DB_HOST} -p ${DB_PORT} -U postgres \
        -c "CREATE USER foks WITH CREATEDB PASSWORD '${DB_PW_FOKS}';"
}

init_db() {
    ${TOOL} --config-path ${CONF} init-db --all 
}

make_host_chain() {
    typ=''
    if [ "$SERVER_MODE" = "standalone" ]; then
        typ="--type standalone"
    fi
    tool make-host-chain \
        --keys-dir ${TOPDIR}/keys \
        --hostname ${BASE_HOSTNAME} \
        ${typ}
}

noop() {
    echo "No operation"
}

list_services() {
    local wanted_is_ext="$1"
    ret=""
    for svc in "${all_services_hyphenate[@]}"
    do
        unhyp="${svc//-/_}"
        is_ext=$(jsonnet ${TOPDIR}/conf/foks.jsonnet | jq -r ".listen.${unhyp}.is_ext")
        if [ "$is_ext" = "$wanted_is_ext" ]; then
                ret="${ret},${unhyp}"
        fi
    done
    echo "${ret}"
}

issue_backend_cert() {
    hosts="127.0.0.1,localhost,::1,${BASE_HOSTNAME}"

    # For docker-compose, the hostname is the name of the service, so has
    # to appear as an SNI in the TLS cert
    if [ "$RUN_MODE" = "docker_compose" ]; then
        others=$(list_services false)
        hosts="${hosts},${others}"
    fi
    tool issue-cert \
        --type backend-x509-cert \
        --hosts ${hosts}
}

issue_frontend_cert() {
    hosts=""
    if [ "$NETWORK_MODE" = "test" ]; then
        hosts=127.0.0.1,localhost,::1,${BASE_HOSTNAME}
    else 
        hosts=${BASE_HOSTNAME}
    fi
    if [ "$RUN_MODE" = "docker_compose" ]; then
        others=$(list_services true)
        hosts="${hosts},${others}"
    fi
    tool issue-cert \
        --type hostchain-frontend-x509-cert \
        --hosts ${hosts}
}

issue_probe_and_beacon_certs_test() {
    hosts=127.0.0.1,localhost,::1,${BASE_HOSTNAME}

    tool lets-encrypt \
        --ca-cert ${TLSDIR}/probe_ca.rootca.cert \
        --ca-key ${TLSDIR}/probe_ca.rootca.key
}

issue_probe_cert_prod() {
    autocert probe
}

issue_beacon_cert_prod() {
    if [ "$RUN_BEACON" -eq 1 ]; then
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
    PGPASSWORD=${DB_PW_FOKS} psql \
        -h ${DB_HOST} -p ${DB_PORT} \
        -U foks foks_users \
        -c "INSERT INTO multiuse_invite_codes (short_host_id, code, num_uses, valid) VALUES (1, '${INVITE_CODE}', 0, TRUE);"
}

sleep2() {
    sleep 2
}

write_dbkeys() {
    tool write-db-keys
}

make_docker_guest_conf() {
    # docker-compose needs a slightly different configuration system, since processes
    # are running as guests in the docker context
    mkdir -p ${TOPDIR}/conf-guest
    cp -f ${TOPDIR}/conf/* ${TOPDIR}/conf-guest/
    echo "true" > ${TOPDIR}/conf-guest/local.is_docker_guest.libsonnet
}

make_docker_compose_db() {
    local dcf="$1"
    echo "DB_PW_POSTGRES=${DB_PW_POSTGRES}" > ${TOPDIR}/.env
    cat <<EOF >> ${dcf}
  postgresql:
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: \${DB_PW_POSTGRES}
      POSTGRES_DB: postgres
    env_file: 
      - ${TOPDIR}/.env
    healthcheck:
      test:
        - CMD-SHELL
        - pg_isready -U postgres -d postgres
      timeout: 10s
      interval: 30s
      retries: 10
      start_period: 20s
    image: $(db_img)
    ports:
      - mode: host
        target: 5432
        published: ${DB_PORT}
        protocol: tcp
    restart: unless-stopped
    volumes:
      - type: volume
        source: foks-db-${INSTANCE_ID}
        target: /var/lib/postgresql/data
volumes:
  foks-db-${INSTANCE_ID}:
    name: foks-db-${INSTANCE_ID}
    external: true
EOF
}

make_docker_compose_service() {
    local dcf="$1"
    local service="$2"
    local unhyphenated_service="${service//-/_}"

    cat <<EOF >> ${dcf}
  ${unhyphenated_service}:
    command:
      - ${service}
      - --config-path 
      - /foks/conf/foks.jsonnet
    image: ${DOCKER_FOKS_SERVER}
    restart: unless-stopped
    volumes:
      - type: bind
        source: ${TOPDIR}/conf-guest
        target: /foks/conf
      - type: bind
        source: ${TOPDIR}/keys
        target: /foks/keys
EOF
    port=$(jsonnet ${TOPDIR}/conf/foks.jsonnet \
        | jq -r ".listen.${unhyphenated_service}.port")
    is_ext=$(jsonnet ${TOPDIR}/conf/foks.jsonnet \
        | jq -r ".listen.${unhyphenated_service}.is_ext")
    if [ "$is_ext" = "true" ]; then
        cat <<EOF >> ${dcf}
    ports:
      - mode: host
        target: ${port}
        published: "${port}"
        protocol: tcp
EOF
    fi
    if [ "$DB_BYO" -eq 0 ]; then
        cat <<EOF >> ${dcf}
    depends_on:
      postgresql:
        condition: service_healthy
        required: false
EOF
    fi
}

make_docker_compose_file() {

    make_docker_guest_conf
    dcf="${TOPDIR}/docker-compose.yml"

    cat <<EOF > ${dcf}
services:
EOF


    for i in "${all_services_hyphenate[@]}"
    do
        make_docker_compose_service ${dcf} ${i}
    done

    if [ "$DB_BYO" -eq 0 ]; then
        make_docker_compose_db ${dcf}
    fi

}

make_prod_runmode_files() {
    case "$RUN_MODE" in
        "docker_compose") make_docker_compose_file ;;
        "systemd") make_systemd_units ;;
        *)
            echo "Unknown run mode: $RUN_MODE"
            exit 1
            ;;
    esac
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
ExecStart=${SERVER} --config-path ${CONF} --refork ${i}
SyslogIdentifier=foks-${i}
EOF
        if [ "${i}" == "web" -o "${i}" == "autocert" ]; then
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

install_prod_runmode_files() {
    case "$RUN_MODE" in
        "docker_compose") ;;
        "systemd") install_systemd_units ;;
        *)
            echo "Unknown run mode: $RUN_MODE"
            exit 1
            ;;
    esac
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

start_docker_compose() {
    if [ "$DB_BYO" -eq 0 ] ; then
        docker stop foks-postgresql-${INSTANCE_ID}
        docker rm foks-postgresql-${INSTANCE_ID}

    fi
    (cd ${TOPDIR} && docker compose up -d)
}

start_prod_runmode() {
    case "$RUN_MODE" in
        "docker_compose") start_docker_compose ;;
        "systemd") start_systemd ;;
        *)
            echo "Unknown run mode: $RUN_MODE"
            exit 1
            ;;
    esac
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
    if [ "$SERVER_MODE" != "hosting_platform" ]; then
        echo "Skipping init_mgmt_vhost since not in hosting platform mode"
        return
    fi
    tool init-vhost \
        --vhost ${MGMT_HOSTNAME} \
        --code ${VHOST_INVITE_CODE} \
        --host-type vhost-management
}

init_big_top_vhost() {
    if [ "$SERVER_MODE" != "hosting_platform" ]; then
        echo "Skipping init_big_top_vhost since not in hosting platform mode"
        return
    fi
    tool init-vhost \
        --vhost ${BIG_TOP_HOSTNAME} \
        --code ${VHOST_INVITE_CODE} \
        --host-type big-top
}

init_plans() {
    if [ "$SERVER_MODE" != "hosting_platform" ]; then
        echo "Skipping init_plans since not in hosting platform mode"
        return
    fi

    # For testing webhooks and renewals, have a stupid option to refresh
    # once a day
    if [ "$NETWORK_MODE" = "test" -o "$NETWORK_MODE" = "dev" ]; then
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
        --details '1TB of storage' \
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
    "setup_tools"
    "make_web_assets"
    "create_docker_db"
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
    "p:make_prod_runmode_files dt:noop"
    "p:install_prod_runmode_files dt:noop"
    "p:start_prod_runmode dt:start_pm2"
    "beacon_register"
    "init_mgmt_vhost"
    "init_big_top_vhost"
    "init_plans"
    "eof"
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

    if [ "$raw" = "eof" ]; then
        echo "eof"
        return
    fi

    if [ $(echo ${raw} | wc -w ) = "1" ]; then
        echo ${raw}
        return
    fi

    case "$NETWORK_MODE" in
        "test")
            echo ${raw} | perl -ne '{ print "$1\n" if /t[pd]*:(\S+)/ }'
            ;;
        "prod")
            echo ${raw} | perl -ne '{ print "$1\n" if /p[dt]*:(\S+)/ }'
            ;;
        "dev")
            echo ${raw} | perl -ne '{ print "$1\n" if /d[pt]*:(\S+)/ }'
            ;;
        *)
            echo "bad_op"
            ;;
    esac

    true
}

next() {
    next_op=0
    step=${TOPDIR}/build.step
    if [ -f ${step} ]; then
        last_op=$(cat ${step})
        next_op=$((last_op + 1))
    fi
    op=$(get_op $next_op)
    if [ "$op" = "eof" ]; then
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

