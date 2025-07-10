# Running Your Own FOKS Server

The FOKS server consists of 8-10 standalone Go statically-linked services, and a
PostgreSQL database. These services can run in a Docker container or on bare
metal.

## Wizard Experience

For a default configuration with few available options, you can
take the easy route:

```bash
/usr/bin/env bash <(curl -fsSL https://pkgs.foks.pub/server-install.sh)
```

## Guided Setup

It's possible to build configuration files from scratch, and to 
run setup steps manually. However, we've scripted some of the most
common scenarios. It might make sense to follow the scripted flows to learn
the basic steps, and then attempt manual setup afterwards. The scripts
are written to be readable and understandable, and serve as online
documentation for the setup process.

### Configuration Modes

When setting up a FOKS server, there are three important axes to consider:

#### Network Mode

Network mode describes how the FOKS processes use the network.

* The *prod* network mode speaks for itself, when a FOKS
  server is connected to the public internet and running in production. Running
  in *prod* does not preclude a private network setting, but some additional
  configuration might be required.

* In *test* mode, all services and clients run on the local machine, allowing for
  easier debugging and development. This mode overrides DNS to point everything
  relevant to `localhost`, and also uses non-standard TLS root CAs. FOKS clients
  and servers must be configured accordingly.

* In *dev* mode, all client and server processes run on the local machine.
  However, this machine is visible to the public internet via SSH reverse proxy,
  to some cloud server of your choosing. As such, servers can request real
  TLS certificates from Let's Encrypt, and can be used with standards FOKS clients.
  However, as in test, debugging and tests can happen conveniently on one machine.

#### Run Mode

Run mode describes how FOKS server processes get run, write logs, and restart
after a crash

* *systemd* mode is for running FOKS on production simply on a modern Linux.
 Systemd handles process lifetimes and logging. Each FOKS service corresponds to 
 a systemd unit, and can be configured to start when the machine starts up.
* *docker_compose* mode is for running FOKS in a Docker container, using
  [docker compose](https://docs.docker.com/compose/) for orchestration.
* *pm2* mode is useful in testing and development, where FOKS services are run
  using [PM2](https://pm2.keymetrics.io/), a process manager for Node.js. PM2
  provides a convenient way to run multiple processes, restart them on crash, and
  view logs.

#### Server Mode

FOKS servers can be configured as a standalone server, or as a platform that
allows other virtual servers, configured at runtime, to run atop it.

* In *standalone* mode, the FOKS server runs as a single instance. This is
  the simplest mode, and is suitable for most use cases.

* In *hosting_platform* mode, the FOKS server runs a base instance, but
  also two other instances at startup: a ``big top'' instance like 
  `foks.app`, good for signle users and small teams; and ``management host''
  instance, which allows group admins to set up a virtual FOKS service for
  their team or company. From here, more virtual serves can be added via
  the management host. See `vh.foks.app` for an example. In hosting platform
  mode, and not standalone mode, the FOKS server runs a web admin process.

## Configuration and Build

There are four basic steps: (1) get the FOKS source code; (2) make a work
directory; (3) run config.bash in that directory to make configuration files and
environment scripts; and (e) to run build.bash, which takes cues from the files
generated in the previous step.


### Get the FOKS Source Code

```bash
cd /path/to/some/srcdir
git clone https://github.com/foks-proj/go-foks.git
```

### Make a Work Directory

```bash
mkdir /path/to/some/workdir
```

This directory will eventually contain: FOKS binaries; configuration files;
environment files; server-side private keys; and scripts.

### Run config.bash

```bash
cd /path/to/some/workdir
/path/to/some/srcdir/go-foks/scripts/srv/config.bash \
    --network-mode prod \
    --run-mode systemd \
    --server-mode standalone \
    --base-hostname foks.yourdomain.gg ...
```

We recommend reading `config.bash` to understand the various options
and how they affect one another. The script outputs the following files, which
can now be examined to make sure they look correct:

* `conf/foks.jsonnet`: the main FOKS configuration file, in
  [Jsonnet](https://jsonnet.org/) format. Shared among all the FOKS services,
  this file is copied (or symlinked) to the unmodified file 
  in the [source tree](https://github.com/foks-proj/go-foks/blob/main/conf/srv/foks.jsonnet).
* `conf/local.pre.libsonnet` and `conf/local.post.libsonnet`: configuration 
  options based on arguments to `config.bash`. You can run `jsonnet foks.jsonnet`
  to see the final configuration (assuming you have the `jsonnet` tool installed).
* `env.sh`: variable settings useful for running the `build.bash` script, generated
   from command line arguments to `config.bash`.
* `scripts/build.bash`: the script used in the next step

### Run build.bash

```bash
cd /path/to/some/workdir

# step through the setup process, one step at a time
./scripts/build.bash next
``` 

Again, we recommend reading `build.bash` to understand the various steps
required to configure a FOKS server. The sequence of operations is seen here:

```bash
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
    "p:make_systemd_units dt:noop"
    "p:install_systemd_units dt:noop"
    "p:start_systemd dt:start_pm2"
    "beacon_register"
    "init_mgmt_vhost"
    "init_big_top_vhost"
    "init_plans"
    "eof"
)
```

Those without a prefix pertain to all network modes; those with a `t:` prefix
are for the test network mode; those with a `p:` prefix are for the production
mode; and those with a `d:` prefix are for dev mode.

Some operations are later short-circuited, depending on other config options.
For instance:

```bash
reate_docker_db() {
    if [ "$DB_BYO" -eq 1 ]; then
        echo "Skipping create_docker_db since using BYO DB"
        return
    fi
    docker \
        run -d --name foks-postgresql-${INSTANCE_ID} \
        -v foks-db-${INSTANCE_ID}:/var/lib/postgresql/data \
        -p ${DB_PORT}:5432 \
        -e POSTGRES_PASSWORD=${DB_PW_POSTGRES} \
        arm64v8/postgres:17-alpine
    sleep2
}
```

If `--db-byo` is supplied to  `config.bash`, then `export DB_BYO=1`
is set in `env.sh`, and the `create_docker_db` function is skipped.