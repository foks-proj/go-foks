# FOKS - Federated Open Key Service

Welcome to FOKS. This is our provisional name for this project, but it might stick.
Documentation is a work-in-progress, but below you'll find the most important information
to get started.

## Overview

* See [foks.pub](https://foks.pub) for a high-level overview of the project.
* Read our [whitepaper](https://github.com/foks-proj/foks-whitepaper)
* We run a [hosting service (foks.app)](https://w.foks.app)

## Build / Test / Install

### Prerequisites
* A modern go, v1.24 or later
* Optional
   * A modern NodeJS if building the admin Web portal (not needed for the CLI)
   * Docker; for MacOS, Docker Desktop is very nice. This is used in testing to run PostgreSQL

### Build the Client (to test against live alpha prod data):

```bash
make             # build for the local platform; install into $GOPATH/bin
make git-link    # symlink git-remote-foks to foks (only needed once)
foks ctl start   # start the agent, persistently via systemd or launchd or Windows Registry
foks signup      # sign up for a new account on `foks.app`, invite code is `cczjho9r`
```

#### Linux

On Linux, you'll need the [PCSC lite library](https://pcsclite.apdu.fr/) before you can build:

```bash
sudo apt-get install gcc make libpcsclite-dev pkg-config
```

And to run with YubiKey support, you'll need:

```bash
sudo apt-get install pcscd
```

On some Linux distributions, I've found that standard users lack
permission to access `pcscd`, which is a service Linux runs to manage access to
YubiKeys. I've found that the following configurations can give unprivileged
users access:

```bash
cat <<EOF > /etc/polkit-1/rules.d/90-pcscd.rules 
polkit.addRule(function(action, subject) {
    if (action.id == "org.debian.pcsc-lite.access_pcsc" &&
        subject.isInGroup("pcscd")) {
        return polkit.Result.YES;
    }
});
EOF

groupadd pcscd
usermod -aG pcscd $USER
systemctl daemon-reload
systemctl restart polkit
systemctl restart pcscd
```

### Testing on Prod (foks.app)

* For now, you can use the invite code `cczjho9r`.
* Contact me (max AT ne43.com) if you'd like a coupon code for a free or discounted plan.
* If you want to try a virtual host, first signup for an account on `vh.foks.app`, using
  the same invite code. Then you can add virtual hosting via the web interface (`foks admin web` to login).

### Run all Tests

Running `make ci` will run all tests on a mock yubikey. I do this 99% of the time. Every
so often I test against a hardware yubikey, but I recommend a throwaway yubikey for that, since it
will make destructive changes to the yubikey. You'll need Docker installed

```bash
make ci                   # uses a mock yubikey
make ci-yubi-destructive  # uses a real yubikey; it's way slower, and it will make destructive changes to the yubikey
```

### Run Locally Against Local Server

```bash
# YMMV!!! 
cd /path/to/your/workdir
/path/to/srcdir/scripts/config.bash --dev # and lots of other options
cd srv
./build.bash all # or you can single-step if something goes wrong
```

## Protocols

See `proto-src` for protocol definition files that dictate how the various parts of the FOKS
system communicate. They are split into 4 groups:

* `lcl`: used on the client machine, to specify how the one-shot client talks to the local agent. 
* `rem`: used for client-server interaction
* `infra`: used for server-server interaction
* `lib`: shared libraries for all protocols

To allow `go install` to work as expected, we include the built protocol files in the repository;
see the `proto/` director for the generated files. To rebuild the protocol files, run `make proto`.

## Processes

When run in "production", there are several processes running on both server and client. On server:

- reg - doesn't require mTLS, useful for signing up, logging in, or other public operations
- user - requires mTLS, does many user operations, and also team operations
- probe - doesn't require mTLS, a "discovery" service that allows clients to discover where the other
   services running for this host are. Sends back links of the "hostchain" so that a connecting
   client can verify that its current key is consistent with its prior keys.
- beacon - run once globally on the whole FOKS system. Allows clients to map a raw host ID
   (which is just a hash of the public key) to a DNS name. For now, this is doing the trivial
   thing, but for DoS-prevention, might consider a more distributed system for this purpose,
   Anyone can "register" as host ID as long as they can product signatures that are consistent
   with that hostID, though we probably want some durable notion of key rotations, so that 
   an evil beacon server can't roll them back.
- merkle_query - doesn't require mTLS, allows clients to probe the Merkle Tree for this FOKS instance.
- merkle_batcher - internal service, runs periodically, batches up unrelated transactions into a 
  stable batch of operations that dictactes what the next Merkle Epoch will look like.
- merkle_builder - internal service, processes the output of merkle_batcher to update the Merkle Tree.
- merkle_signer - internal service, signs the Merkle Tree root, finalizing the process.
- queue - internal service, something like SQS that allows various FOKS services to queue up
  operations to each other. Used mainly in "KEX", key-exchange, whereby one device provisions
  another.
- internal_ca - internal service, signs the mTLS certificates for various backend services, allowing
  them to mutually authenticate
- kv-store - requires mTLS, the server-side backend to the key-value store

On client, the main service is the "agent", which is a persistent process somewhat akin to ssh-agent.
Like ssh-agent, it keeps keys in memory. Unlike ssh-agent, it performs background rekeying jobs
on users and teams, to handle the follow-on-effects of key revocations, and removing users from teams.
Right now, two other processes connect to this agent to do things. One is the `foks` command,
which enables everything from device management, to key-value store access, to team maintenance 
operations, etc. The other is `git-remote-foks`, a git remote helper that interfaces
with the FOKS key-value store. This process is just a symlink (or hardlink) to the `foks` command,
but it acts differently when called as `git-remote-foks`. BTw, the agent itself runs 
with the `foks agent` subcommand. A design goal here is to have ultra-simple installation. Just
one binary dumped onto your system (essentially statically linked as Go likes to do) is all you need.

## Testing Philosophy / Context / MetaContext

I've found it immensely useful to run all the above processes in the same address space
for the purposes of testing. Meaning, you can set breakpoints in the client code or
the server code, and the debugger will just bounce-back and forth between them. These
various processes still communicate via TCP or Unix domain sockets, as they would if they
were running as separate processes in production.

To enable this configuration to work, it's important that there are few if any global
variables. Meaning, all global state is roughly passed through an an argument, from `main()`
on down. In Go, this can be slightly cumbersome, since Go in a lot of cases wants to you
pass `context.Context` as a first argument to any method that you might cancel based on 
timeout or some external factors. This would put you in a situation of now passing 
two boilerplate arguments, first a `context.Context` and then some sort of `*GlobalState`.

To slightly smooth this out, we liberally use these things called `MetaContext`, which have
`context.Context` passed by value, and a `GlobalState` passed by reference. Now there is
only one boilerplate argument to pass instead of two. This is the case on the server and
the client, and we sometimes have MetaContexts that are quite different internally
(since server and client state are quite different).

In both cases, we sometimes dangle methods off of `MetaContext` if they use fields
from both. Logging is a the most commonly-used example, since logging often includes
"context tags" that are set at the beginning of a request or logical-operation. They
are also shared via RPC so that we can debug how the server logs based on specific
client operations.

## Directory Layout

The directories are, roughly from lowest-level to highest level:

* proto/ - protocol definitions
* lib/core - lowest level library, with utilities common to client and server
* lib/core/kv - low-level key-value store library
* lib/merkle/ - Merkle library, 
* lib/team/ - Team routines
* lib/probe - Implementations of probes for FOKS servers; useful on client and server since 
    servers probe each other for team sharing
* lib/chain - Implementation of chain players, again, useful on client and server
* client/libclient - Client library routines
* client/libgit - Git client library
* client/libkv - Key-value store client library
* client/libyubi - Yubikey access and test
* server/shared - Routines shared across all server processes and tools
* server/engine - High-level services
* client/agent - High-level client-side agent services

In general, the dependencies are:

 - lib/core > proto
 - lib/core/kv > lib/core
 - lib/merkle > lib/core
 - lib/team > lib/core
 - lib/chains > lib/merkle
 - client/libclient > {lib/*}
 - client/libkv > client/libclient
 - client/libgit > client/libkv
 - client/libyubi > client/libclient
    - (note this dependency can be removed by changing intiialization pathways in libyubi/top.go)
 - client/agent > client/libyubi
 - server/shared > {lib/*}
 - server/engine > server/shared
 - integration_tests/common > client/lib*, server/shared*
 - integration_tests/lib > integration_tests/common
 - integration_tests/cli > integration_tests/common, client/*

## Entities, Teams, Users, Parties

Nomenclature is still in flux, but we have some rough definitions:

- `EntityID` (see `proto/common.snowp`) - A public key that servers as an identifier for a thing,
  like a host, a user, a team, a TLS Cert, etc. Usually they are 33 bytes, where the first byte
  is the type, and the next 32 bytes are the EdDSA public key. There is an important exception,
  which as a YubiKey. Yubi exposes ECDSA keys, which are 33 bytes. Therefore, YubiKey entities
  are 34 bytes. Entities can all be expressed as fixed 34-byte entities, which can be used
  as map keys, or map key components.
- Pariies: A party is a user or a team, they can often do similar things, and sometimes 
  we can use the notion of a `PartyID` to express that the thing operating might either be
  a user or a team. Note that `PartyID`s, `UID`s, and `TeamID`s are all subclasses, more or less,
  of `EntityID`s.

## Further Documentation

Some important docs are:

- `docs/passphrase.snowp` - A description of our unfortunately complicated passphrase system.
   Passphrases are used to lock secret keys locally, but have many requirements that they 
   behave well on passphrase change, and key rotation, so this protocol is really something.
   I was hoping we wouldn't need passphrases altogether, but I also think it's likely
   that some users will ask for them, and they would be hard to add later.
- `docs/kv_store.md` - A pretty up-to-date description of how the KV store is working,
   and ideas for future work there.

## Future Work

Lots, left blank for now.
