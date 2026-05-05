#!/usr/bin/env bash
# Server-side FOKS auto-deploy.
# Invoked by .github/workflows/deploy.yml over SSH.
# Required env: FOKS_TAG, REGISTRY (e.g. ghcr.io/seco-pbc)
#
# Behaviour:
#   1. One-time bootstrap: rewrites docker-compose.yml so foks-server image
#      is sourced from $FOKS_SERVER_IMAGE in .env (idempotent).
#   2. Pulls foks-server + foks-tool at $FOKS_TAG.
#   3. Runs DB patches (idempotent).
#   4. Switches .env to new tag and restarts compose.
#   5. Health-checks the probe port. On failure, rolls back to previous tag.

set -euo pipefail

: "${FOKS_TAG:?FOKS_TAG env var required}"
: "${REGISTRY:?REGISTRY env var required (e.g. ghcr.io/seco-pbc)}"

WORKDIR="${WORKDIR:-/opt/foks/workdir}"
ENV_FILE="${WORKDIR}/.env"
COMPOSE_FILE="${WORKDIR}/docker-compose.yml"
SERVER_IMAGE="${REGISTRY}/foks-server:${FOKS_TAG}"
TOOL_IMAGE="${REGISTRY}/foks-tool:${FOKS_TAG}"
HEALTH_HOST="${HEALTH_HOST:-127.0.0.1}"
HEALTH_PORT="${HEALTH_PORT:-4430}"
HEALTH_TIMEOUT_S="${HEALTH_TIMEOUT_S:-90}"

# All FOKS databases known to foks-tool patch-db (excl. kv-store, which uses shards).
DBS=(server-config users beacon merkle-tree merkle-raft merkle-raft-archive queue-service)

log()  { printf '[deploy %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() { printf '[deploy] FATAL: %s\n' "$*" >&2; exit 1; }

[ -d "$WORKDIR" ]      || fail "workdir not found: $WORKDIR"
[ -f "$COMPOSE_FILE" ] || fail "compose file not found: $COMPOSE_FILE"
[ -f "$ENV_FILE" ]     || fail ".env not found: $ENV_FILE"

cd "$WORKDIR"

# ---------------------------------------------------------------------------
# 1. One-time bootstrap: rewrite compose to use ${FOKS_SERVER_IMAGE} env var.
# ---------------------------------------------------------------------------
if ! grep -q '^FOKS_SERVER_IMAGE=' "$ENV_FILE"; then
    log "first run — rewriting compose image refs to use \${FOKS_SERVER_IMAGE}"
    cp "$COMPOSE_FILE" "${COMPOSE_FILE}.pre-ci.bak"
    # Replace any image: <registry>/<ns>/foks-server:<anything> with the env var.
    sed -i -E 's|^(\s*image:\s*)[^[:space:]]*foks-server:[^[:space:]]+|\1${FOKS_SERVER_IMAGE}|' "$COMPOSE_FILE"
    if ! grep -q '\${FOKS_SERVER_IMAGE}' "$COMPOSE_FILE"; then
        mv "${COMPOSE_FILE}.pre-ci.bak" "$COMPOSE_FILE"
        fail "bootstrap rewrite did not match any foks-server image lines — aborting"
    fi
    # Seed .env with the OLD image so we have a working rollback target.
    OLD_IMAGE=$(grep -oE 'image:\s*[^[:space:]]*foks-server:[^[:space:]]+' "${COMPOSE_FILE}.pre-ci.bak" | head -1 | awk '{print $2}')
    OLD_IMAGE="${OLD_IMAGE:-$SERVER_IMAGE}"
    printf '\n# managed by scripts/deploy/server-deploy.sh\nFOKS_SERVER_IMAGE=%s\n' "$OLD_IMAGE" >> "$ENV_FILE"
    log "bootstrap ok (previous image: $OLD_IMAGE)"
fi

PREV_IMAGE=$(grep '^FOKS_SERVER_IMAGE=' "$ENV_FILE" | tail -1 | cut -d= -f2-)
log "prev image: $PREV_IMAGE"
log "new  image: $SERVER_IMAGE"

# ---------------------------------------------------------------------------
# 2. Pull new images.
# ---------------------------------------------------------------------------
log "pulling $SERVER_IMAGE"
docker pull "$SERVER_IMAGE"
log "pulling $TOOL_IMAGE"
docker pull "$TOOL_IMAGE"

# ---------------------------------------------------------------------------
# 3. Apply DB patches (idempotent — patch-db skips already-applied patches
#    and exits with "no patches to apply" if there's nothing to do).
# ---------------------------------------------------------------------------
# Compose's default network is "<project>_default"; project name defaults to
# the workdir basename (here: "workdir"). Allow override via env.
COMPOSE_NETWORK="${COMPOSE_NETWORK:-$(basename "$WORKDIR")_default}"
if ! docker network inspect "$COMPOSE_NETWORK" >/dev/null 2>&1; then
    fail "docker network '$COMPOSE_NETWORK' not found; set COMPOSE_NETWORK to the right name"
fi
log "using docker network: $COMPOSE_NETWORK"

run_patch() {
    local db="$1"
    local out rc
    set +e
    out=$(docker run --rm \
        --network "$COMPOSE_NETWORK" \
        -v "${WORKDIR}/conf-guest:/foks/conf:ro" \
        -v "${WORKDIR}/keys:/foks/keys" \
        --env-file "$ENV_FILE" \
        "$TOOL_IMAGE" \
        patch-db --yes \
            --config-path /foks/conf/foks.jsonnet \
            --db "$db" 2>&1)
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        log "  $db: patched"
        return 0
    fi
    if echo "$out" | grep -q "no patches to apply"; then
        log "  $db: up to date"
        return 0
    fi
    echo "$out" >&2
    return $rc
}

log "applying DB patches"
for db in "${DBS[@]}"; do
    run_patch "$db" || fail "patch-db failed for db=$db"
done

# ---------------------------------------------------------------------------
# 4. Switch .env to new image and restart compose.
# ---------------------------------------------------------------------------
log "switching .env to new image and restarting"
sed -i -E "s|^FOKS_SERVER_IMAGE=.*|FOKS_SERVER_IMAGE=${SERVER_IMAGE}|" "$ENV_FILE"
docker compose up -d

# ---------------------------------------------------------------------------
# 5. Health check; rollback on failure.
# ---------------------------------------------------------------------------
log "health-checking ${HEALTH_HOST}:${HEALTH_PORT} (up to ${HEALTH_TIMEOUT_S}s)"
deadline=$(( $(date +%s) + HEALTH_TIMEOUT_S ))
ok=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    if (echo > "/dev/tcp/${HEALTH_HOST}/${HEALTH_PORT}") >/dev/null 2>&1; then
        ok=1; break
    fi
    sleep 2
done

if [ "$ok" -ne 1 ]; then
    log "HEALTH CHECK FAILED — rolling back to $PREV_IMAGE"
    sed -i -E "s|^FOKS_SERVER_IMAGE=.*|FOKS_SERVER_IMAGE=${PREV_IMAGE}|" "$ENV_FILE"
    docker compose up -d || true
    fail "deploy aborted, rolled back to $PREV_IMAGE"
fi

log "deploy ok: $SERVER_IMAGE"
