# Logging When Running FOKS in Docker

This note describes how logging is configured when you stand up a FOKS server
using `foks-tool standup` and run it with Docker Compose. It covers log
rotation and verbosity so that logs stay bounded and quiet in normal operation.

## Overview

When you run `foks-tool standup`, it generates a `docker-compose.yml` that
starts the FOKS server services and supporting containers. By default, Docker
would keep one unbounded log file per container. To avoid that, standup configures
each service with log rotation and an explicit log level. High-frequency logs
in the server code are emitted at debug level so that at the default level,
steady-state output is minimal.

## Log Rotation

The generated `docker-compose.yml` sets a `logging` block on every service
(postgresql, each FOKS server process, and beacon_register):

* **Driver:** `json-file` (Docker's default, with options below).
* **Options:**
  * `max-size: "10m"` — rotate when a log file reaches 10 MB.
  * `max-file: "3"` — keep at most 3 rotated files per container.

So each container's logs are capped at roughly 30 MB. This applies only to
new standups; if you already have a standup from before this was added,
re-run standup or add the same `logging` block to each service in your
`docker-compose.yml` to get rotation.

## Verbosity in Steady State

Two things keep logs from being noisy when the server is just running normally:

### Default log level

Every service in the generated compose is started with `--log-level info`.
That way the default is never more verbose than info, and you still see
startup, errors, and notable events.

### High-frequency logs at debug

Routine, repeated events are logged at **debug** level so they do not appear
at the default **info** level. Examples:

* Per-connection RPC: new connection, OK, client disconnected, exit.
* Per-request: autocert HTTP requests, cert fetches.
* Lock acquire/release, DNS lookups.
* Periodic work: beacon probe, merkle poll/commit, autocert refresh, quota poll.

Startup, shutdown, and one-off events (e.g. "listening", "shutdown complete",
"HostID") remain at info so they still show when the server starts or stops.

To see the high-frequency logs, run the server (or a single service) with
`--log-level debug`.
