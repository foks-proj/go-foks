#!/usr/bin/env bash

set -euo pipefail

# load in general-purpose library routines
. $(dirname $0)/lib.bash

fail_in_src

## configuration parameters that are set via CLI invocation:

server_mode=standalone   # can be 'standalone' or 'hosting_platform'
network_mode=prod        # can be 'prod', 'test', 'dev'
run_mode=systemd         # can be 'docker_compose' or 'systemd' in prod; must be pm2 otherwise
run_remote=0             # in network_mode=prod, can also be running the code on a remote server

base_hostname=""         # must be specified in all cases
big_top_hostname=""      # only needed in server_mode=hosting_platform
mgmt_hostname=""         # only needed in server_mode=hosting_platform

ssh_key=""               # in network_mode=dev, need this ssh key for ssh reverse proxy
ssh_proxy_hostname=""    # in network_mode=dev, hostname of ssh reverse proxy

run_beacon=0             # in test and dev; on by default; in prod, off by default
beacon_hostname=""       # in network_mode!=prod, can specify non-standard beacon hostname, like localhost, etc

db_byo=0                 # if we are bringing out own database, set to 1
db_no_tls=1              # if using local docker, no TLS
db_port=54320            # if docker, run on this port
db_port_std=5432         # standard port for postgres
db_hostname="localhost"  # if docker, run on localhost

# the following are needed if server_mode=hosting_platform:
stripe_pk=""             # Stripe public key for payments
stripe_sk=""             # Stripe secret key for payments
stripe_whsec=""          # Stripe webhook secret for payments
canned_domains=()        # list of canned domains for hosting platform, in "<domain>,<zone_id>" pairs
vanity_hosting_domain="" # a utility domain that user-supplied hostnames point to (in "<domain>,<zone_id>" form)

# the following are used if we want to BYO CA, rather than using Let's Encrypt:
probe_key=""            # path to the probe private key
probe_cert_chain=""     # path to the probe certificate chain, leaf-first, in PEM format
beacon_key=""           # path to the beacon private key
beacon_cert_chain=""    # path to the beacon certificate chain, leaf-first, in PEM format

# the following are used in network_mode=prod and run_remote=1:
prod_ssh=""              # In <user>@<host> form
prod_root_ssh=""         # In <user>@<host> form; someone who can run sudo on the prod_ssh host
remote_topdir=""         # On <user>@<host>, the top directory where the server is installed

docker_foks_tool="ghcr.io/foks-proj/foks-tool:latest"     # Docker image for foks-tool
docker_foks_server="ghcr.io/foks-proj/foks-server:latest" # Docker image for foks-server

# we can either compile code or use dockerized static images; by default, we compile code
do_compile=1

# directories and important files
topdir=$(pwd)
topdir_srv=$topdir
topdir_cli=$topdir
env_sh=${topdir}/env.sh
srcdir=$(my_realpath $(dirname $0)/../..)

# http ports: we need port=80 for let's encrypt, to answer ACME challenges; we need port=443
# for TLS and the admin web management portal. The external port and the internal port might
# differ in the case of dev network mode, since we'll map the port via ssh -R.
http_internal_port=80
http_external_port=80
https_internal_port=443
https_external_port=443
http_use_tls=1

# bind addresses for the server, whether it can listen to external requests or not
bind_addr_ext="127.0.0.1"

# temporary variables for command-line arguments
arg_run_beacon=0
arg_no_run_beacon=0
arg_run_mode=''
arg_db_port=''
arg_db_hostname=''
arg_db_byo=0
arg_db_no_tls=0
arg_db_pw_postgres=''

#----------------------------------

getargs() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
        --server-mode|--server_mode)
            shift
            server_mode="$1"
            case "$server_mode" in
                standalone|hosting_platform) ;;
                *) whoops "Invalid server mode: $server_mode" ;;
            esac
            ;;
        --network-mode|--network_mode)
            shift
            network_mode="$1"
            case "$network_mode" in
                prod|test|dev) ;;
                *) whoops "Invalid network mode: $network_mode" ;;
            esac
            ;;
        --run-remote|--run_remote)
            run_remote=1
            ;;
        --run-mode|--run_mode)
            shift
            arg_run_mode="$1"
            case "$arg_run_mode" in
                docker_compose|docker-composesystemd|pm2) ;;
                *) whoops "Invalid run mode: $arg_run_mode" ;;
            esac
            ;;
        --base-hostname|--base_hostname)
            shift
            base_hostname="$1"
            ;;
        --big-top-hostname|--big_top_hostname)
            shift
            big_top_hostname="$1"
            ;;
        --mgmt-hostname|--mgmt_hostname)
            shift
            mgmt_hostname="$1"
            ;;
        --ssh-key|--ssh_key)
            shift
            ssh_key="$1"
            ;;
        --ssh-proxy-hostname|--ssh_proxy_hostname)
            shift
            ssh_proxy_hostname="$1"
            ;;
        --run-beacon|--run_beacon)
            arg_run_beacon=1
            ;;
        --no-run-beacon|--no_run_beacon)
            arg_no_run_beacon=1
            ;;
        --beacon-hostname|--beacon_hostname)
            shift
            beacon_hostname="$1"
            ;;
        --db-hostname|--db_hostname)
            shift
            arg_db_hostname="$1"
            ;;
        --db-port|--db_port)
            shift
            arg_db_port="$1"
            ;;
        --db-byo|--db_byo)
            arg_db_byo=1
            ;;
        --db-pw-postgres|--db_pw_postgres)
            shift
            arg_db_pw_postgres="$1"
            ;;
        --db-no-tls|--db_no_tls)
            arg_db_no_tls=1
            ;;
        --stripe-pk|--stripe_pk)
            shift
            stripe_pk="$1"
            ;;
        --stripe-sk|--stripe_sk)
            shift
            stripe_sk="$1"
            ;;
        --stripe-whsec|--stripe_whsec)
            shift
            stripe_whsec="$1"
            ;;
        --canned-domain|--canned_domain)
            shift
            canned_domains+=("$1")
            ;;
        --vanity-hosting-domain|--vanity_hosting_domain)
            shift
            vanity_hosting_domain="$1"
            ;;
        --prod-ssh|--prod_ssh)
            shift
            prod_ssh="$1"
            ;;
        --prod-root-ssh|--prod_root_ssh)
            shift
            prod_root_ssh="$1"
            ;;
        --remote-topdir|--remote_topdir)
            shift
            remote_topdir="$1"
            ;;
        --no-compile)
            do_compile=0
            ;;
        --docker-foks-tool|--docker_foks_tool)
            shift
            docker_foks_tool="$1"
            ;;
        --docker-foks-server|--docker_foks_server)
            shift
            docker_foks_server="$1"
            ;;
        --probe-key|--probe_key)
            shift
            probe_key="$1"
            ;;
        --probe-cert-chain|--probe_cert_chain)
            shift
            probe_cert_chain="$1"
            ;;
        --beacon-key|--beacon_key)
            shift
            beacon_key="$1"
            ;;
        --beacon-cert-chain|--beacon_cert_chain)
            shift
            beacon_cert_chain="$1"
            ;;
        -*=*)
            echo "Cannot use --a=b style arguments; use --a b instead"
            exit 1
        esac
        shift
    done
}

#----------------------------------

whoops() {
    echo $1
    exit 1
}

#----------------------------------

check_config() {

    [ -z "$base_hostname" ] && whoops "base_hostname must be specified"

    if [ "$server_mode" == "hosting_platform" ]; then
        [ -z "$big_top_hostname" ] && whoops "big_top_hostname must be specified in server_mode=hosting_platform"
        [ -z "$mgmt_hostname" ] && whoops "mgmt_hostname must be specified in server_mode=hosting_platform"
        [ -z "$stripe_pk" ] && whoops "stripe_pk must be specified in server_mode=hosting_platform"
        [ -z "$stripe_sk" ] && whoops "stripe_sk must be specified in server_mode=hosting_platform"
        [ -z "$stripe_whsec" ] && whoops "stripe_whsec must be specified in server_mode=hosting_platform"
        [ ${#canned_domains[@]} -eq 0 ] && whoops "canned_domains must be specified in server_mode=hosting_platform"
        [ -z "$vanity_hosting_domain" ] && whoops "vanity_hosting_domain must be specified in server_mode=hosting_platform"
    else
        [ -n "$big_top_hostname" ] && whoops "big_top_hostname only needed in server_mode=hosting_platform"
        [ -n "$mgmt_hostname" ] && whoops "mgmt_hostname only needed in server_mode=hosting_platform"
        [ -n "$stripe_pk" ] && whoops "stripe_pk only needed in server_mode=hosting_platform"
        [ -n "$stripe_sk" ] && whoops "stripe_sk only needed in server_mode=hosting_platform"
        [ -n "$stripe_whsec" ] && whoops "stripe_whsec only needed in server_mode=hosting_platform"
        [ ${#canned_domains[@]} -ne 0 ] && whoops "canned_domains only needed in server_mode=hosting_platform"
        [ -n "$vanity_hosting_domain" ] && whoops "vanity_hosting_domain only needed in server_mode=hosting_platform"
    fi
    if [ "$network_mode" != "dev" ]; then 
        [ -n "$ssh_key" ] && whoops "ssh_key only needed in network_mode=dev"
        [ -n "$ssh_proxy_hostname" ] && whoops "ssh_proxy_hostname only needed in network_mode=dev"
    else 
        [ -z "$ssh_proxy_hostname" ] && whoops "ssh_proxy_hostname must be specified in network_mode=dev"
    fi

    if [ "$network_mode" = "prod" ]; then
       [ "$run_mode" = "pm2" ] && whoops "run_mode=pm2 only works with network_mode=dev or test"
    else
        [ "$run_remote" -eq 1 ] && whoops "run_remote=1 only works with network_mode=prod"
    fi

    if [ "$network_mode" != "prod" -o "$run_remote" -eq 0 ]; then
        [ -n "$remote_topdir" ] && whoops "remote_topdir only works with network_mode=prod and run_remote=1"
        [ -n "$prod_ssh" ] && whoops "prod_ssh only works with network_mode=prod and run_remote=1"
        [ -n "$prod_root_ssh" ] && whoops "prod_root_ssh only works with network_mode=prod and run_remote=1"
    fi

    if [ "$do_compile" -eq 0 ]; then
        [ "$network_mode" != "prod" ] && whoops "no-compile mode only works with network_mode=prod"
        [ "$run_mode" != "docker_compose" ] && whoops "no-compile mode only works with run_mode=docker_compose"
    fi

    [ "$probe_key" != "" -a "$probe_cert_chain" == "" ] && whoops "Both --probe-key and --probe-cert-chain must be specified, or neither"
    [ "$probe_key" == "" -a "$probe_cert_chain" != "" ] && whoops "Both --probe-key and --probe-cert-chain must be specified, or neither"
    [ "$beacon_key" != "" -a "$beacon_cert_chain" == "" ] && whoops "Both --beacon-key and --beacon-cert-chain must be specified, or neither"
    [ "$beacon_key" == "" -a "$beacon_cert_chain" != "" ] && whoops "Both --beacon-key and --beacon-cert-chain must be specified, or neither"

    true
}

#----------------------------------

set_beacon() {
    if [ "$network_mode" = "test" -o "$network_mode" = "dev" ] ; then
        [ "$arg_run_beacon" -eq 1 ] && whoops "Cannot use --run-beacon in network_mode=$network_mode"
        run_beacon=1
        if [ "$arg_no_run_beacon" -eq 1 ]; then
            run_beacon=0
        fi
    else
        [ "$arg_no_run_beacon" -eq 1 ] && whoops "Cannot use --no-run-beacon in network_mode=$network_mode, since it's on by default"
        run_beacon=0
        if [ "$arg_run_beacon" -eq 1 ]; then
            run_beacon=1
        fi
    fi

    if [ -z "$beacon_hostname" ]; then
        if [ "$run_beacon" -eq 0 ]; then
            beacon_hostname="b0.foks.app"
        elif [ "$network_mode" = "test" ]; then
            beacon_hostname="localhost"
        else 
            beacon_hostname="$base_hostname"
        fi
    fi

    if [ "$run_beacon" -eq 0 -a -n "$beacon_key" ]; then
        whoops "Cannot use --beacon-key and --beacon-cert-chain in run_beacon=0 mode"
    fi

    true
}

#----------------------------------

setup_run_mode() {
    case "$network_mode" in
        prod)
            case "$arg_run_mode" in
                docker_compose|docker-compose) run_mode="docker_compose" ;; 
                systemd) run_mode="systemd" ;;
                pm2) whoops "run_mode=pm2 only works with network_mode=dev or test" ;;
                '') run_mode="systemd" ;;
                *) whoops "Invalid run mode: $arg_run_mode" ;;
            esac
            ;;
        *)
            case "$arg_run_mode" in
                pm2) run_mode="$arg_run_mode" ;;
                '') run_mode="pm2" ;;
                systemd|docker_compose) whoops "run_mode=systemd only works with network_mode=prod" ;;
                *) whoops "Invalid run mode: $arg_run_mode" ;;
            esac
            ;;
    esac
}


#----------------------------------

setup_network_mode() {
    case "$network_mode" in
        test)
            topdir_srv=${topdir}/srv
            topdir_cli=${topdir}/cli
            ;;
        prod)
            bind_addr_ext="0.0.0.0"
            ;;
    esac
}

#----------------------------------

setup_http() {
    case "$network_mode" in
        test)
            http_use_tls=0
            ;;
        dev)
            http_internal_port=20080
            https_internal_port=20443
        ;;
        prod)
            http_internal_port=80
            https_internal_port=443
            ;;
        *)
            whoops "Invalid network mode: $network_mode"
            ;;
    esac
}
#----------------------------------

check_go() {
    if [ "$do_compile" -eq 0 ]; then
        return
    fi

    if ! command -v go &> /dev/null; then
        echo "Go is required but not installed. Please install Go and try again."
        exit 1
    fi

    # Ensure the Go version is compatible
    go_version=$(go version | awk '{print $3}')
    needed_version="go1.24"
    xx=$(printf '%s\n' "$go_version" "$needed_version" | sort -rV | head -n1)
    if [ "$xx" = "$go_version" ]; then
        echo "Go Version ${go_version} is supported (is >= $needed_version)"
    else
        whoops "Go version $go_version is not supported. Please install Go ${needed_version} or later, or specify --no-compile."
    fi
}

#----------------------------------

setup_db() {
    if [ -z "$arg_db_port" -a -z "$arg_db_hostname" -a "$arg_db_byo" -eq 0 -a -z "$arg_db_pw_postgres" ]; then
        return
    fi
    db_port=${arg_db_port:-$db_port_std}
    db_hostname=${arg_db_hostname:-"localhost"}
    db_byo=1
    db_no_tls=0
    if [ "$arg_db_no_tls" -eq 1 ]; then
        db_no_tls=1
    fi
    db_pw_postgres=${arg_db_pw_postgres:-""}
}

#----------------------------------

mkdir_srv() {
    mkdir -p ${topdir_srv}/sh
    mkdir -p ${topdir_srv}/conf
    mkdir -p ${topdir_srv}/tls
    mkdir -p ${topdir_srv}/keys
    mkdir -p ${topdir_srv}/system
    mkdir -p ${topdir_srv}/tmp
    mkdir -p ${topdir_srv}/bin
    mkdir -p ${topdir_srv}/scripts
    mkdir -p ${topdir_srv}/config-tools
}

#----------------------------------

foks_tool=""

build_tool() {
    if [ "$do_compile" -eq 1 ]; then
        targ_dir=${topdir_srv}/config-tools
        (cd ${srcdir}/server/foks-tool && GOBIN=${targ_dir} go install .)
        foks_tool="${targ_dir}/foks-tool --log-level=warn"
    else
        foks_tool="docker run --rm ${docker_foks_tool} --log-level=warn"
    fi
}

#----------------------------------

make_symlinks() {
    (cd ${topdir_srv}/scripts && 
        ln -fs ${srcdir}/scripts/srv/build.bash build.bash &&
        ln -fs ${srcdir}/scripts/srv/build-go.bash . 
    )
    if [ "$network_mode" = "prod" ]; then
        (cd ${topdir_srv}/scripts &&  \
            ln -fs ${srcdir}/scripts/srv/deploy.sh . &&
            ln -fs ${srcdir}/scripts/srv/restart.bash . && 
            ln -fs ${srcdir}/scripts/srv/config-remote.sh . )
    fi
}

#----------------------------------

mkpw() {
    ${foks_tool} random -n $1 -b 36
}
mkscrt() {
    ${foks_tool} random -n 32 -b 62
}
spl0() {
    echo $1 | cut -d, -f1
}
spl1() {
    echo $1 | cut -d, -f2
}

#----------------------------------

make_env_file() {
    compile_client=0
    cat <<EOF > ${env_sh}
# This file is auto-generated by scripts/srv/config.bash

export NETWORK_MODE=${network_mode}
export SERVER_MODE=${server_mode}
export RUN_MODE=${run_mode}
export TOPDIR=${topdir_srv}
export SRCDIR=${srcdir}
export INVITE_CODE=$(mkpw 5)
export DB_PORT=${db_port}
export DB_HOST=${db_hostname}
export DB_NO_TLS=${db_no_tls}
export DB_BYO=${db_byo}
export BINDIR=\${TOPDIR}/bin
export CONFDIR=\${TOPDIR}/conf
export SCRIPTDIR=\${TOPDIR}/scripts
export INSTANCE_ID=$(mkpw 4)
export SERVER=\${BINDIR}/foks-server
export TOOL=\${BINDIR}/foks-tool
export CONF=\${CONFDIR}/foks.jsonnet
export BASE_HOSTNAME=${base_hostname}
export RUN_BEACON=${run_beacon}
export DB_PW_FOKS=$(mkpw 9)
export RUN_REMOTE=${run_remote}
export COMPILE_SERVER=${do_compile}
export HTTP_LOCAL_PORT=${http_internal_port}
export HTTPS_LOCAL_PORT=${https_internal_port}
export DOCKER_FOKS_SERVER=${docker_foks_server}
export PROBE_KEY="${probe_key}"
export PROBE_CERT_CHAIN="${probe_cert_chain}"
export BEACON_KEY="${beacon_key}"
export BEACON_CERT_CHAIN="${beacon_cert_chain}"
EOF

    if [ "$server_mode" = "hosting_platform" ]; then
        cat <<EOF >> ${env_sh}
export VHOST_INVITE_CODE=$(mkpw 5)
EOF
    fi

    if [ "$db_byo" -eq 0 ]; then
        db_pw_postgres=$(mkpw 9)
    elif [ -z "$db_pw_postgres" ]; then
        db_pw_postgres="please-supply-pw-here"
        echo "❓ Please provide your DB's password for the postgres user in the env.sh file, for creation of new FOKS databases."
    fi

    cat <<EOF >> ${env_sh}
export DB_PW_POSTGRES="${db_pw_postgres}"
EOF

    if [ "$server_mode" = "hosting_platform" ]; then
        cat <<EOF >> ${env_sh}
export BIG_TOP_HOSTNAME=${big_top_hostname}
export MGMT_HOSTNAME=${mgmt_hostname}
EOF
    fi

    case "$network_mode" in
    test)
        cat <<EOF >> ${env_sh}
export TOPDIR_CLI=${topdir_cli}
export BINDIR_CLI=${topdir_cli}/bin
export HOMEDIR_CLI=${topdir_cli}/home
EOF
    compile_client=1
    ;;
    prod)
        cat <<EOF >> ${env_sh}
export PROD_SSH=${prod_ssh}
export PROD_ROOT_SSH=${prod_root_ssh}
export REMOTE_TOPDIR=${remote_topdir}
EOF
    ;;
    dev)
        cat <<EOF >> ${env_sh}
export SSH_KEY=${ssh_key}
export SSH_PROXY_HOSTNAME=${ssh_proxy_hostname}
EOF
    ;;
    esac

    cat <<EOF >> ${env_sh}
export COMPILE_CLIENT=${compile_client}
EOF

}

#----------------------------------

eq_to_json() {
    if [ "$1" = "$2" ]; then echo "true"; else echo "false"; fi
}
int_to_json_bool() {
    if [ "$1" -eq 1 ]; then echo "true"; else echo "false"; fi
}

#----------------------------------

make_local_pre() {
    cat <<EOF > ${topdir_srv}/conf/local.pre.libsonnet
local is_docker_guest = import "local.is_docker_guest.libsonnet";
local base(o) = o + {
    local top = self,
    is_docker_guest : is_docker_guest,
    top_dir : if top.is_docker_guest then "/foks/" else "${topdir_srv}/",
    db +: {
        password : "$(. ./env.sh && echo $DB_PW_FOKS)",
        port : if top.is_docker_guest then ${db_port_std} else ${db_port},
        host : if top.is_docker_guest then "postgresql" else "${db_hostname}",
        'no-tls' : $(int_to_json_bool "$db_no_tls"),
    },
    standalone : $(eq_to_json "$server_mode" "standalone"),
    external_addr : "${base_hostname}",
    localhost_test : $(eq_to_json "$network_mode" "test"),
    autocert_port : ${http_internal_port},
    bind_addr_ext : "${bind_addr_ext}",
    web_ports : {
        internal : ${https_internal_port},
        external : ${https_external_port},
    },
    web_use_tls : $(int_to_json_bool "$http_use_tls"),
    beacon +: {
        hostname : "${beacon_hostname}",
    },
    docker_compose : $(eq_to_json "$run_mode" "docker_compose"),
};
local final(o) = o;
{ base : base, final : final }
EOF
    echo "false" > ${topdir_srv}/conf/local.is_docker_guest.libsonnet
}

#----------------------------------

make_local_post() {
    cat <<EOF > ${topdir_srv}/conf/local.post.libsonnet
local final(o) = o + {
    cks : {
        enc_keys: [ "$(mkscrt)" ],
    },
EOF
    if [ "$server_mode" = "hosting_platform" ]; then
        cat <<EOF >> ${topdir_srv}/conf/local.post.libsonnet
    stripe : {
        pk : "${stripe_pk}",
        sk : "${stripe_sk}",
        whsec : "${stripe_whsec}",
        session_duration : "1h",
    },
    vhosts +: {
        canned_domains : [
EOF
        for cd in "${canned_domains[@]}"; do
            cat <<EOF >> ${topdir_srv}/conf/local.post.libsonnet
            { domain : "$(spl0 ${cd})", zone_id : "$(spl1 ${cd})" },
EOF
        done
        cat <<EOF >> ${topdir_srv}/conf/local.post.libsonnet
        ],
        vanity +: {
            hosting_domain : {
                domain : "$(spl0 ${vanity_hosting_domain})",
                zone_id : "$(spl1 ${vanity_hosting_domain})",
            },
        },
    },
    apps +: {
        reg +: {
            vhost_mgmt_addr: "${mgmt_hostname}",
        }
    },
EOF
    fi

    cat <<EOF >> ${topdir_srv}/conf/local.post.libsonnet
};
{ final: final }
EOF

}

#----------------------------------

make_pm2_ecosystem_js() {
    if [ "$run_mode" != "pm2" ]; then
        return
    fi

    cat <<EOF > ${topdir_srv}/ecosystem.config.local.js
module.exports = { 
    beacon : $(int_to_json_bool "$run_beacon"),
    web : $(eq_to_json "$server_mode" "hosting_platform")
};
EOF
}

#----------------------------------

make_server_local() {
    if [ "$run_remote" -eq 1 ]; then
        return
    fi

    # Server
    if [ "$run_mode" = "prod" ]; then
        # for production environment, don't change the master jsonnet file
        # changing out from underneath us
        cp $(realpath ${srcdir}/conf/src/foks.jsonnet) ${topdir_srv}/conf/
    else
        # in dev or test, we might want local changes made here to be committed
        ln -fs $(realpath ${srcdir}/conf/srv/foks.jsonnet) ${topdir_srv}/conf/
        ln -fs $(realpath ${srcdir}/scripts/srv/ecosystem.config.js) ${topdir_srv}/
        ln -fs $(realpath ${srcdir}/scripts/srv/run-air.sh) ${topdir_srv}/
        ln -fs $(realpath ${srcdir}/scripts/srv/pm2.sh) ${topdir_srv}/
    fi

    if [ "$network_mode" = "dev" ]; then
        ln -fs $(realpath ${srcdir}/scripts/srv/ssh-tun.sh) ${topdir_srv}/bin/
    fi

    if [ "$run_mode" = "pm2" ]; then
        cp ${srcdir}/scripts/srv/package.json ${topdir_srv}/
        cp ${srcdir}/scripts/srv/package-lock.json ${topdir_srv}/
    fi
}

#----------------------------------

make_client_local() {
    if [ "$network_mode" != "test" ]; then
        return
    fi

    (cd ${topdir_cli} && ln -sf ../env.sh)
    mkdir -p ${topdir_cli}/home
    mkdir -p ${topdir_cli}/bin
    ln -fs $(realpath ${srcdir}/conf/cli/config.jsonnet) ${topdir_cli}/home/
    (cd ${topdir_cli}/bin && ln -sf foks git-remote-helper-foks)

    cat <<EOF > ${topdir_cli}/bin/foks.sh
#!/bin/sh
. ${env_sh}
\${BINDIR_CLI}/foks --home \${HOMEDIR_CLI} --config \${HOMEDIR_CLI}/config.jsonnet "\$@"
EOF
    chmod +x ${topdir_cli}/bin/foks.sh
    cat <<EOF > ${topdir_cli}/home/local.libsonnet
{
    top_dir : "${topdir}",
    primary_hostname : "${base_hostname}",
    test : ${test},
EOF

    if [ "$server_mode" = "hosting_platform" ]; then
        cat <<EOF >> ${topdir_cli}/home/local.libsonnet
    big_top_hostname : "${big_top_hostname}",
    mgmt_hostname : "${mgmt_hostname}",
EOF
    fi

    cat <<EOF >> ${topdir_cli}/home/local.libsonnet
}
EOF

}

#----------------------------------

report_next() {
    echo "🙌 All configured! 🙌"
    echo "➡️  Next steps:"
    if [ "$run_remote" -eq 1 ] ; then
        echo " - Run ./scripts/config-remote.sh to copy necessary files to the remote server"
        echo " - Run ./scripts/build.bash on ${prod_ssh} to build the server"
    else
        echo " - Check out ./env.sh to make it sure it looks ok"
        echo " - Run scripts/build.bash to setup your FOKS instance"
        echo " - You can run 'scripts/build.bash next' until all setup steps are completed"
    fi
}

#----------------------------------

check_prereqs() {

    if [ "$run_mode" = "docker_compose" ]; then
        docker --version &> /dev/null
        [ $? -ne 0 ] && whoops "Docker is required for run_mode=docker_compose but not installed. Please install Docker and try again."
        docker compose version &> /dev/null
        [ $? -ne 0 ] && whoops "Docker compose (v2) is required for run_mode=docker_compose but not installed. Please install Docker Compose and try again."
        jsonnet --version &> /dev/null
        [ $? -ne 0 ] && whoops "Jsonnet is required for run_mode=docker_compose but not installed. Please install Jsonnet and try again."
        jq --version &> /dev/null
        [ $? -ne 0 ] && whoops "jq is required for run_mode=docker_compose but not installed. Please install jq and try again."
    fi
}


#----------------------------------

main() {
    getargs "$@"
    check_config
    check_prereqs
    set_beacon
    setup_run_mode
    setup_network_mode
    setup_db
    setup_http
    check_go
    mkdir_srv
    build_tool
    make_symlinks
    make_env_file
    make_local_pre
    make_local_post
    make_pm2_ecosystem_js
    make_server_local
    make_client_local
    report_next
}

#----------------------------------

main "$@"
