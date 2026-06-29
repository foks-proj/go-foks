---
name: add-foks-error-type
description: Use when adding a new error / status code to FOKS. Wires a new StatusCode through proto-src/lib/status.snowp (enum + variant Status arm), regenerates proto with `make proto`, and mirrors it as a Go error in lib/core/errors.go (type + both conversion switches). Canonical precedent: TeamAdhocCreatorIncludedError (@7101).
---

# Add a new FOKS error type

FOKS errors are `StatusCode`s defined in a `.snowp` proto source, then mirrored as
Go error types in `lib/core/errors.go`. Both halves must be wired for the error to
round-trip over the wire. The canonical example is `TeamAdhocCreatorIncludedError`
(`TEAM_ADHOC_CREATOR_INCLUDED_ERROR @7101`).

Do NOT hand-edit generated files under `proto/lib`, `proto/rem`, `proto/lcl`. They are
generated from `proto-src/*.snowp` via `make proto`. (Hand-written `*extras.go` files are
the only editable generated-package files.)

## Steps

### 1. Pick a status code in `proto-src/lib/status.snowp`

Add an enum entry with a new unique `@NNNN` number, grouped near related codes:

```
TEAM_ADHOC_OPEN_VIEWERSHIP_ERROR @7102;
```

### 2. Add it to the correct arm of `variant Status switch (sc : StatusCode)`

Same file, further down. Pick the arm by the error's payload:

- **No payload** (a Go `struct{}` error): add to the big `case OK, ... : void;` arm.
- **Carries a message string**: add to the `@1: Text` arm.
- **Typed payload**: add to (or create) the matching arm.

Most new errors are `struct{}` -> the `void` arm. Place the new code next to a sibling.

### 3. Regenerate

```
make proto
```

Confirm `proto/lib/status.go` gained: the `StatusCode_<NAME> = NNNN` const, a
`NewStatusWith<CamelName>()` constructor, and the new code inside the `void`-case list.
Do not edit that file by hand.

### 4. Mirror as a Go error in `lib/core/errors.go`

Three edits, each next to the `TeamAdhocCreatorIncludedError` precedent:

a. The error type + `Error()`:

```go
type TeamAdhocOpenViewershipError struct{}

func (t TeamAdhocOpenViewershipError) Error() string {
	return "ad-hoc teams require an open-viewership host"
}
```

b. In the Go-error -> `Status` switch:

```go
case TeamAdhocOpenViewershipError:
	return proto.NewStatusWithTeamAdhocOpenViewershipError()
```

c. In the `Status` -> Go-error switch:

```go
case proto.StatusCode_TEAM_ADHOC_OPEN_VIEWERSHIP_ERROR:
	return TeamAdhocOpenViewershipError{}
```

For errors with a message payload, the type is `type FooError string` with
`func (f FooError) Error() string { return string(f) }`, and the switches use the
`@1: Text` constructor/accessor instead of the payload-less forms — again, copy the
nearest precedent that uses the same arm.

### 5. Throw it

Return the Go error value (e.g. `core.TeamAdhocOpenViewershipError{}`) at the relevant
client and/or server chokepoint. It serializes to the status code and reconstitutes as
the same Go type on the other side.

### 6. Verify

```
gofmt -w <hand-edited .go files>
go build ./...
```
