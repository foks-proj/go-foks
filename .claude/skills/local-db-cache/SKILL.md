---
name: local-db-cache
description: Store locally cached data in the FOKS client's local SQLite DB (soft/hard state) via DbGet/DbPut, optionally two-tiered with an in-memory map in front. Use when adding client-side persistence or caching keyed by scope + key.
---

# Storing locally cached data in the client DB

The FOKS client persists local state in SQLite through `m.DbPut` / `m.DbGet`
(`client/libclient/db.go`). Rows are addressed by **(scope, DataType, key)** and
hold one codec-encoded proto value plus a write timestamp.

## 1. Pick soft vs hard state

- `DbTypeSoft` — expendable cache state. The system must function if it's
  wiped. Caches go here.
- `DbTypeHard` — critical state (sigchain state, keys, etc.).

## 2. Add a DataType

Add a new enum value in `proto-src/lcl/db.snowp` (`enum DataType`), taking the
next free slot in the relevant block; then run `make proto`. Never hand-edit
`proto/lcl/db.go`. Name it after the value stored (`SharedKeyCacheEntry`,
`UsernameCacheEntry` are precedents). Check for an existing DataType first —
similar-sounding ones may serve a different purpose (e.g. `UsernameLookup` is
username→UID in hard state; `UsernameCacheEntry` is UID→username in soft state).

## 3. Write and read

```go
// Write. Scope/Key/Val requirements below.
err := m.DbPut(DbTypeSoft, PutArg{
    Scope: &fqu.HostID,                      // Scoper = core.Codecable; nil for global
    Typ:   lcl.DataType_UsernameCacheEntry,
    Key:   fqu.Uid,                          // see key coercion below
    Val:   &nm,                              // core.Codecable (any proto type pointer)
})

// Read. Returns the row's write time (proto.Time) — use it for TTL.
var nm proto.NameUtf8
tm, err := m.DbGet(&nm, DbTypeSoft, &fqu.HostID,
    lcl.DataType_UsernameCacheEntry, fqu.Uid)
if errors.Is(err, core.RowNotFoundError{}) { /* miss */ }
```

- **Scope**: anything `core.Codecable` (e.g. `*proto.HostID`, `*proto.FQUser`);
  `nil` for unscoped rows.
- **Key** (`core.NewDbKey`, lib/core/dbkey.go) accepts, in order: a `DbKeyer`;
  anything with `Bytes() []byte` (all EntityID-derived types like `proto.UID`);
  a `CryptoPayloader` (hashed); `string`; `[]byte`; a `String()` stringer;
  a `Uint16()`. Multi-field keys: define a small snowp struct with a unique
  type ID (see `PUKBoxDBKey`) so it's a `CryptoPayloader`.
- **Val**: pointer to any generated proto type (implements `core.Codecable`).
- Use `core.EmptyKey{}` when the scope alone addresses the row.
- Batch writes: `m.DbPutTx(which, []PutArg{...})`.

## 4. Two-tier caching (memory in front of the DB)

Two established patterns:

- **Generic**: `Cache[S, K, V, VP, MV]` in `client/libclient/cache.go` — one
  fixed scope per instance, memory map + soft-DB, no TTL.
- **Hand-rolled** (when the scope varies per entry or you need TTL):
  `UsernameCache` in `client/libclient/username_cache.go`. Rules it follows:
  - `sync.RWMutex` map in front; `Get` tries memory, then `DbGet`.
  - TTL: derive expiry from the row's write time returned by `DbGet` — warm the
    memory tier with expiry anchored at the *write* time, not the read time, so
    the staleness bound holds across tiers.
  - Capture values at decision time; never re-read the cache later (a TTL
    eviction between two reads loses the value — TOCTOU).
  - Soft-state error handling: a failed DB read/write degrades to a cache miss
    or a warning (`m.Warnw`), never an error for the caller.
  - Register the cache on `GlobalContext` (`globals.go`) with an accessor, next
    to `deviceNameCache`/`usernameCache`.
  - Fill the cache at the site where the data is loaded (right after the
    expensive call), not via a separate harvest pass.

## 5. Verify

`go build ./...`; test the DB tier by round-tripping through a fresh cache
value (empty memory tier) so `Get` must hit the DB — see the end of
`TestSimpleCreateTeamAdHoc` (integration-tests/lib/team_adhoc_test.go).
