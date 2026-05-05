# Auto-deploy to Hetzner

Tag-triggered deploy from GitHub to the production FOKS server.

```
git tag v0.1.7-seco.1
git push origin v0.1.7-seco.1
       │
       ▼
GH Actions ─ build linux/arm64 (QEMU) ─ push ghcr.io/seco-pbc/foks-{server,tool}
       │
       ▼
SSH ─ /opt/foks/deploy.sh ─ pull → patch-db → compose up -d → health check
       │                                             (rollback on failure)
       ▼
   Hetzner CAX11 (ARM64)
```

## One-time setup

### 1. GitHub repository secrets

Settings → Secrets and variables → Actions → New repository secret:

| Name             | Value                                                             |
|------------------|-------------------------------------------------------------------|
| `DEPLOY_HOST`    | Server IP or hostname (e.g. `foks.example.com`)                   |
| `DEPLOY_USER`    | `root`                                                            |
| `DEPLOY_SSH_KEY` | Private key (full PEM, including header/footer) for the deploy user |

`GITHUB_TOKEN` is provided automatically and handles GHCR push + pull.

### 2. SSH key on the server

On a workstation:

```bash
ssh-keygen -t ed25519 -f foks-deploy -N "" -C "github-actions-foks-deploy"
ssh-copy-id -i foks-deploy.pub root@<server>
# paste the contents of `foks-deploy` into the DEPLOY_SSH_KEY GitHub secret
# delete the local copy of the private key
```

### 3. Server prerequisites

The server must already be running FOKS (per `foks-server-setup.md`) with:

- `/opt/foks/workdir/docker-compose.yml`
- `/opt/foks/workdir/.env`
- `/opt/foks/workdir/conf-guest/`, `/opt/foks/workdir/keys/`
- `docker compose ps` showing the stack up

The first deploy will:

1. Back up the existing compose file to `docker-compose.yml.pre-ci.bak`.
2. Replace the hardcoded `image: ghcr.io/foks-proj/foks-server:...` lines with `image: ${FOKS_SERVER_IMAGE}`.
3. Append `FOKS_SERVER_IMAGE=...` to `.env` (initially seeded with the old image — that is the rollback target if the very first deploy fails).

This is idempotent: subsequent deploys skip the rewrite.

## Triggering a deploy

**On tag push:**

```bash
git tag v0.1.7-seco.1
git push origin v0.1.7-seco.1
```

**Manual re-run** (e.g. retry without re-tagging): GitHub → Actions → "Build & Deploy" → Run workflow → enter tag.

## Rollback

Automatic on health-check failure (TCP probe on `127.0.0.1:4430`, 90 s timeout).

Manual rollback to a previous tag — re-run the workflow with the old tag, or on the server:

```bash
ssh root@<server>
sed -i 's|^FOKS_SERVER_IMAGE=.*|FOKS_SERVER_IMAGE=ghcr.io/seco-pbc/foks-server:v0.1.7-seco.0|' \
    /opt/foks/workdir/.env
cd /opt/foks/workdir && docker compose up -d
```

## DB migrations

`foks-tool patch-db --yes --db <name>` runs once per database on every deploy. It is idempotent (already-applied patches are skipped via the `schema_patches` table). The deploy script iterates over: `server-config users beacon merkle-tree merkle-raft merkle-raft-archive queue-service`.

KV-store shards are not migrated automatically — if you ever add a kv-store patch, run it manually with `--shard <id>`.

## What lives where

| File                                     | Role                                  |
|------------------------------------------|---------------------------------------|
| `.github/workflows/deploy.yml`           | CI: build images, SCP script, run it  |
| `scripts/deploy/server-deploy.sh`        | Server: pull, migrate, restart, check |
| `server/foks-tool/patch_db.go` (`--yes`) | Non-interactive migration confirmation |
