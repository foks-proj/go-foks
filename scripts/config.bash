#!/bin/bash
# Copyright (c) 2025 ne43, Inc.
# Licensed under the MIT License. See LICENSE in the project root for details.


if [ -f ./src ]; then 
    echo "Must run configure script from build (not source) directory"
    exit 1
fi

test=false
dev=false
prod=false
hostname=""
big_top_hostname=""
mgmt_hostname=""
topdir=""
ssh_proxy_hostname=""
ssh_key=""
beacon=false
bind_addr_ext="127.0.0.1"
use_rds=false
dbhost="localhost"
db_no_tls=true
dbport=54320
canned_domains=()
stripe_pk=""
stripe_sk=""
stripe_whsec=""
vanity_hosting_domain=""
autocert_bind_port=20080
prod_ssh=""
prod_root_ssh=""
remote_topdir=""

#
# needed parameters for starting a new FOKS instance:
#
#  --test (or not); in test, we're writing DNS mappings into the client config, mapping them to localhost,
#     we also make a local root CA for signing all PKI, and put that into the localhost file. In general,
#     we're trying to get away from this style of testing and are instead bouncing all global IP needs
#     (mainly for TLS) across a droplet/small EC2 node via ssh -R.
#
#  --dev; in dev, we run the server, client and everything on the same host, so therefore need
#     symlinks from our topdir to a source dir
#
#  --base-hostname; the hostname of the base server, e.g. base.ne43.net
#
#  --big-top-hostname; the hostname of the bigtop server, e.g. ne43.com; recall this is the server that
#     will host the teeming unwashed masses of the internet, without any per-server configuration.
#
#  --mgmt-hostname; the hostname of the management server, e.g. mgmt.ne43.net; this is the server that will
#     allow control of hosted vhosts, be they canned or full-on vanity.
#
#  --ssh-proxy-hostname: if in dev and not test, you need an externally-routable SSH proxy to point at
#     your local server. Specify that here.
#
#  --ssh-key: if providing an SSH proxy, you need to specify the path to the key to use for the proxy.
#
#  --beacon: supply if you're going to run a beacon node. You'll get one either way in dev or test, but
#     in prod, only if this is supplied.
#
#  --beacon-hostname: in a more realistic scenario, the beacon hostname is different from the base hostname.
#
#  --rds: if you're in prod, you can use this flag to indicate that you want to use RDS for the database,
#     and not a docker-based postgres instance.
#
#  --stripe-pk: stripe public API key
#  
#  --stripe-sk: stripe secret API key
#
#  --stripe-whsec: stripe webhook secret
#
#  --canned-domain <domain>,<zone_id>: a canned domain and its Route53 zone ID; can be repeated
#
#  --vanity-hosting-domain <domain>,<zone_id>: a vanity domain and its Route53 zone ID
#
#  --prod-ssh <user>@<host>: the SSH connection string for the production server 
# 
#  --prod-root-ssh <user>@<host>: the SSH connection string for the production server as root (or someone who can sudo there)
#

# The topdir is set to be the top of the working directory, where the script is currently 
# being run from. We'll set up a file tree here appropriately.
topdir=$(pwd)
srcdir=$(realpath $(dirname $0)/..)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --test)
            test=true
            ;;
        --dev)
            dev=true
            ;;
        --base-hostname)
            shift
            hostname=$1
            ;;
        --big-top-hostname)
            shift
            big_top_hostname=$1
            ;;
        --mgmt-hostname)
            shift
            mgmt_hostname=$1
            ;;
        --ssh-proxy-hostname)
            shift
            ssh_proxy_hostname=$1
            ;;
        --ssh-key)
            shift
            ssh_key=$1
            ;;
        --beacon)
            beacon=true
            ;;
        --rds)
            shift
            dbhost=$1
            use_rds=true
            db_no_tls=false
            ;;
        --stripe-pk)
            shift
            stripe_pk=$1
            ;;
        --stripe-sk)
            shift
            stripe_sk=$1
            ;;
        --stripe-whsec)
            shift
            stripe_whsec=$1
            ;;
        --canned-domain)
            shift
            canned_domains+=($1)
            ;;
        --vanity-hosting-domain)
            shift
            vanity_hosting_domain=$1
            ;;
        --prod-ssh)
            shift
            prod_ssh=$1
            ;; 
        --prod-root-ssh)
            shift
            prod_root_ssh=$1
            ;;
        --remote-topdir)
            shift
            remote_topdir=$1
            ;;
        *)
            echo "Unexpected option" $1
            exit 1
            ;;
    esac
    shift
done

# If specified, take the specialized beacon hostname; otherwise, just use the same as 
# everything else.
if [ -z "${beacon_hostname}" ]; then
    beacon_hostname=${hostname}
fi

echo "hostname: $hostname"
echo "big_top_hostname: $big_top_hostname"
echo "mgmt_hostname: $mgmt_hostname"
echo "test: $test"
echo "dev: $dev"
echo "beacon: $beacon"
echo "topdir: $topdir"
echo "ssh_proxy_hostname: $ssh_proxy_hostname"
echo "ssh_key: $ssh_key"
echo "beacon_hostname: $beacon_hostname"
echo "use_rds: $use_rds"
echo "dbhost: $dbhost"
echo "db_no_tls: $db_no_tls"
echo "stripe_pk: $stripe_pk"
echo "stripe_sk: $stripe_sk"
echo "stripe_whsec: $stripe_whsec"
echo "canned_domains: ${canned_domains[@]}"
echo "vanity_hosting_domain: $vanity_hosting_domain"
echo "srcdir: $srcdir"

check() {
    if [ -z "$1" ]; then
        echo "error: must specify $2"
        exit 1
    fi
}

check "$hostname" "--base-hostname"
check "$big_top_hostname" "--big-top-hostname"
check "$mgmt_hostname" "--mgmt-hostname"
check "$vanity_hosting_domain" "--vanity-hosting-domain"
check "$stripe_pk" "--stripe-pk"
check "$stripe_sk" "--stripe-sk"
check "$stripe_whsec" "--stripe-whsec"

if [ ${#canned_domains[@]} -eq 0 ]; then
    echo "error: must specify at least one --canned-domain"
    exit 1
fi

if [ "$dev" = true ] && [ "$test" = true ]; then
    echo "Error: dev and test are mutually exclusive"
    exit 1
fi

if [ "$dev" = false ] && [ "$test" = false ]; then
    prod=true
fi

if [ "$dev" = true ] && [ "$test" = false ]; then
    check "$ssh_proxy_hostname" "--ssh-proxy-hostname"
    check "$ssh_key" "--ssh-key"
fi

if [ "$prod" = true ]; then 
    check "$prod_ssh" "--prod-ssh"
    check "$prod_root_ssh" "--prod-root-ssh"
    check "$remote_topdir" "--remote-topdir"
fi

mkdir -p $topdir
topdir=$(realpath ${topdir})
topdir_srv=${topdir}
topdir_cli=${topdir}

if [ "$dev" = true ]; then
    topdir_srv=${topdir}/srv
    topdir_cli=${topdir}/cli
fi

if [ "$prod" = true ]; then
    bind_addr_ext="0.0.0.0"
fi

env_sh=${topdir}/env.sh

mkdir -p ${topdir_srv}/sh
mkdir -p ${topdir_srv}/conf
mkdir -p ${topdir_srv}/tls
mkdir -p ${topdir_srv}/keys
mkdir -p ${topdir_srv}/system
mkdir -p ${topdir_srv}/tmp
mkdir -p ${topdir_srv}/bin
mkdir -p ${topdir_srv}/build-tools

# Build the go tool for making random keys
( cd ${srcdir}/server/foks-tool && GOBIN=${topdir_srv}/build-tools go install )

mkpw() {
    ${topdir_srv}/build-tools/foks-tool random -n $1 -b 36
}
mkscrt() {
    ${topdir_srv}/build-tools/foks-tool random -n 32 -b 62
}
spl0() {
    echo $1 | cut -d, -f1
}
spl1() {
    echo $1 | cut -d, -f2
}

(cd ${topdir_srv} && \
    ln -fs ${srcdir}/scripts/build.bash . &&  \
    ln -fs ${srcdir}/scripts/build-go.bash)
(cd ${topdir_srv}/conf && ln -fs ${srcdir}/run/conf/foks.jsonnet .)

if [ "$prod" = true ]; then
    (cd ${topdir_srv} && \
        ln -fs ${srcdir}/scripts/deploy.sh . && \
        ln -fs ${srcdir}/scripts/restart.bash . && \
        ln -fs ${srcdir}/scripts/config-remote.sh )
fi


http_local_port=80
https_local_port=443
web_listen_port=443
web_ext_port=0
web_use_tls=true
if [ "$dev" = true ]; then
    http_local_port=20080
    https_local_port=20443
    web_listen_port=${https_local_port}
    web_ext_port=443
fi
if [ "$test" = true ]; then
    web_use_tls=false
fi
if [ "$use_rds" = true ]; then
    dbport=5432
fi

bool_to_num() {
  # Convert the input to lowercase for case-insensitive comparison
  local input=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  case "$input" in
    true)
      echo 1
      ;;
    false)
      echo 0
      ;;
    *)
      echo "Error: Input must be 'true' or 'false'. Got $1" >&2
      return 1
      ;;
  esac
}

cat <<EOF > ${env_sh}
#!/bin/bash

export TOPDIR=${topdir_srv}
export TOPDIR_CLI=${topdir_cli}
export DBPW_ROOT=$(mkpw 9)
export DBPW_FOKS=$(mkpw 9)
export INVITECODE=$(mkpw 5)
export VHOST_INVITECODE=$(mkpw 5)
export DBPORT=${dbport}
export DBHOST=${dbhost}
export DB_NO_TLS=$(bool_to_num $db_no_tls)
export BINDIR=\${TOPDIR}/bin
export BINDIR_CLI=\${TOPDIR_CLI}/bin
export HOMEDIR_CLI=\${TOPDIR_CLI}/home
export CONFDIR=\${TOPDIR}/conf
export TOOL=\${BINDIR}/foks-tool
export SERVER=\${BINDIR}/foks-server
export CONF=\${CONFDIR}/foks.jsonnet
export PRIMARY_HOSTNAME=${hostname}
export MGMT_HOSTNAME=${mgmt_hostname}
export BIG_TOP_HOSTNAME=${big_top_hostname}
export SSH_PROXY_HOSTNAME=${ssh_proxy_hostname}
export SSH_KEY=${ssh_key}
export HTTP_LOCAL_PORT=${http_local_port}
export HTTPS_LOCAL_PORT=${https_local_port}
export USE_RDS=$(bool_to_num $use_rds)
export SRCDIR=${srcdir}
export INSTANCE_ID=$(mkpw 4)
EOF

if [ "$test" = true ]; then
    beacon=true
    echo "export TEST=1" >> ${env_sh}
elif [ "$dev" = true ]; then
    beacon=true
    echo "export DEV=1" >> ${env_sh}
else 
    cat <<EOF6 >> ${env_sh}
export PROD=1
export GOOS=linux
export GOARCH=amd64
export GOFLAGS="-tags=noresinit"
export PROD_SSH=${prod_ssh}
export ROOT_PROD_SSH=${prod_root_ssh}
export REMOTE_TOPDIR=${remote_topdir}
EOF6
fi

if [ "$beacon" = true ]; then
    echo "export BEACON=1" >> ${env_sh}
fi

cat <<EOF2 > ${topdir_srv}/conf/local.pre.libsonnet
local base(o) = o + {
    top_dir : "${topdir_srv}/",
    db +: {
        password : "$(. ./env.sh && echo $DBPW_FOKS)",
        port : $(. ./env.sh && echo $DBPORT),
        host : "$(. ./env.sh && echo $DBHOST)",
        'no-tls' : $(. ./env.sh && echo $DB_NO_TLS),
    },
    external_addr : "${hostname}",
    localhost_test : ${test},
    autocert_port : ${http_local_port},
    web_listen_port : ${web_listen_port},
    bind_addr_ext : "${bind_addr_ext}",
    web_ports : {
        internal : ${web_listen_port},
        external : ${web_ext_port},
    },
    web_use_tls : ${web_use_tls},
    beacon +: {
        hostname : "${beacon_hostname}",
    },
};
local final(o) = o;
{ base : base, final : final }
EOF2

cat <<EOF4 > ${topdir_srv}/conf/local.post.libsonnet
local final(o) = o + {
    stripe : {
        pk: '${stripe_pk}',
        sk: '${stripe_sk}',
        whsec: '${stripe_whsec}',
        session_duration: '1h',
    },
    vhosts +: {
        canned_domains: [
EOF4
for cd in ${canned_domains[@]}; do
    cat <<EOF4 >> ${topdir_srv}/conf/local.post.libsonnet
            { domain: '$(spl0 ${cd})', zone_id: '$(spl1 ${cd})' },
EOF4
done
cat <<EOF5 >> ${topdir_srv}/conf/local.post.libsonnet
        ],
        vanity +: {
            hosting_domain: {
                domain: '$(spl0 ${vanity_hosting_domain})',
                zone_id: '$(spl1 ${vanity_hosting_domain})',
            },
        },
    },
    autocert_service : {
        bind_port : ${http_local_port}
    },
    cks : {
        enc_keys : [ '$(mkscrt)' ]
    },
    apps +: {
        reg +: {
            vhost_mgmt_addr : "${mgmt_hostname}"
        }
    }
};
{ final: final }
EOF5

if [ "$test" = true ] || [ "$dev" = true ]; then
    cat <<EOF7 > ${topdir_srv}/ecosystem.config.local.js
    module.exports = { beacon : ${beacon} }
EOF7
fi

dolocal() {
    # Server
    ln -fs $(realpath ${srcdir}/conf/srv/foks.jsonnet) ${topdir_srv}/conf/
    ln -fs $(realpath ${srcdir}/scripts/ecosystem.config.js) ${topdir_srv}/
    ln -fs $(realpath ${srcdir}/scripts/run-air.sh) ${topdir_srv}/
    ln -fs $(realpath ${srcdir}/scripts/ssh-tun.sh) ${topdir_srv}/bin/
    (cd ${topdir_srv} && ln -sf ../env.sh)

    # lock down the version of pm2 that we're using
    cp ${srcdir}/scripts/package.json ${topdir_srv}/
    cp ${srcdir}/scripts/package-lock.json ${topdir_srv}/

    # Client
    mkdir -p ${topdir_cli}/home
    mkdir -p ${topdir_cli}/bin
    ln -fs $(realpath ${srcdir}/conf/cli/config.jsonnet) ${topdir_cli}/home/
    (cd ${topdir_cli}/bin && ln -sf foks git-remote-helper-foks)

    cat <<EOF3 > ${topdir_cli}/bin/foks.sh
#!/bin/sh
. ${env_sh}
\${BINDIR_CLI}/foks --home \${HOMEDIR_CLI} --config \${HOMEDIR_CLI}/config.jsonnet "\$@"
EOF3
    chmod +x ${topdir_cli}/bin/foks.sh
    cat <<EOF4 > ${topdir_cli}/home/local.libsonnet
{
    top_dir : "${topdir}",
    primary_hostname : "${hostname}",
    big_top_hostname : "${big_top_hostname}",
    mgmt_hostname : "${mgmt_hostname}",
    beacon_hostname : ${beacon_hostname}"
    test : ${test}
}
EOF4
}

if [ "$dev" = true ]; then
    dolocal
fi