---
name: add-sql-patch
description: Add a new SQL schema patch (pN.sql) to a FOKS server database. Use whenever changing server-side DDL (new table/index/column/type) on an existing database — the patch must be registered in THREE files or it silently never applies.
---

# Adding a SQL schema patch

Server DDL changes ship two ways at once: a **patch** (`pN.sql`) upgrades
existing deployments via `foks-tool patch-db`, and the **base schema file**
gives fresh installs the same end state directly. Both must be updated, and
the patch must be registered in the Go embed map — **a pN.sql file on disk
that isn't in `embed.go` is dead: the patch engine never sees it.**

## The checklist — 3 files, 4 touches

For a new patch `N` on database `D` (e.g. `foks_realtime`):

1. **The patch file** — `server/sql/patches/D/pN.sql`
   - `N` = next integer for that DB (check both the directory and the
     `Patches` map). Numbering is per-database.
   - Include a comment explaining the change; write it for the deployment
     operator reading it before applying.

2. **The embed registry** — `server/sql/embed.go` (the always-forgotten one)
   - Add the embed directive + var:
     ```go
     //go:embed patches/D/pN.sql
     var dPatchN string
     ```
   - Add `N: dPatchN,` to `Patches["D"]`.
   - The engine (`server/shared/patch.go`) applies exactly the entries of
     this map that aren't recorded in the DB's `schema_patches` table.

3. **The base schema file** — `server/sql/D.sql` (two touches)
   - **Incorporate the DDL**: apply the same change to the base definitions,
     so a fresh install lands in the identical end state (e.g., if the patch
     is `DROP INDEX x; CREATE UNIQUE INDEX x ...`, the base file's
     `CREATE INDEX x` becomes `CREATE UNIQUE INDEX x`).
   - **Register the patch**: append at the bottom
     ```sql
     INSERT INTO schema_patches (id, ctime) VALUES (N, NOW());
     ```
     Without this, a fresh install (which already has the end state) would
     re-apply pN via the patch engine and typically fail (duplicate
     index/column). This registration has been forgotten before — verify the
     bottom of the base file lists every incorporated patch id contiguously.

## Verify

- `go build ./server/sql/` — a typo'd embed path fails the build.
- Run an integration test that stands up the affected DB fresh from the base
  file (they create all tables at startup), plus tests exercising the
  affected writers — e.g. `go test ./integration-tests/lib/ -run TestRT...`
  for `foks_realtime`. This validates the base-file DDL and that live code
  satisfies any new constraint.
- The patch path itself (`pN.sql` against a pre-patch DB) can be validated
  with an ephemeral `postgres:17-alpine` via Docker: create the old schema,
  apply pN, compare. Existing deployments apply it with `foks-tool patch-db`.

## Consistency rule

Patch DDL and base-file DDL must converge to byte-equivalent schemas. When
reviewing, diff what a fresh install produces against what old-schema + all
patches produces — indexes, constraints, enum values, defaults.
