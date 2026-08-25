# SECO fork ↔ upstream tracker

Every change this fork carries that upstream `foks-proj/go-foks` does not, and
what we decided to do about it. **One row per change, and every row has a
verdict.** A change with no row is a bug in this file, not a change with no
opinion.

Read this before proposing anything upstream. It exists so that nobody — human
or AI — has to re-derive a decision we already made, re-propose something
already proposed, or wonder why half a change went out and half did not.

Last synced against upstream: **v0.1.9** (`cb2d8ac`), 2026-08-25.

## How to use it

- **Adding a fork change?** Add a row, even if the verdict is "never upstream".
- **Proposing upstream?** Branch `upstream-pr/<topic>` off `upstream/main` (not
  our `main`), push to SECO-PBC, then
  `gh pr create --repo foks-proj/go-foks --head SECO-PBC:<branch>`.
- **PR closed or merged?** Update the row the same day. A stale row is worse
  than no row, because it gets trusted.
- **After each upstream merge?** Re-check every `Proposed` row: merged ones
  become `Upstreamed` and drop out of our diff.

The sorting rule: **propose it if it fixes a defect or inefficiency any FOKS
user hits; keep it local if it encodes how SECO deploys or what SECO builds.**

## Status vocabulary

| Status | Meaning |
|---|---|
| `Upstreamed` | Merged upstream. Ours only until the next merge drops it. |
| `Proposed` | PR open. Link it. |
| `Queued` | Decided yes, not yet opened. **Must name what it waits on.** |
| `Local` | Deliberately never upstream. **Must say why.** |
| `Declined` | Considered and rejected. **Must say why**, so it stays rejected. |

---

## Proposed — open upstream

| Change | PR | Notes |
|---|---|---|
| merkle loop DB resilience | [#323](https://github.com/foks-proj/go-foks/pull/323) | Transient DB error permanently killed the merkle pipeline. |
| libkv stale VO bearer token re-mint | [#324](https://github.com/foks-proj/go-foks/pull/324) | Freshly-admitted member's first KV write failed for minutes. |
| explore double-load | [#325](https://github.com/foks-proj/go-foks/pull/325) | 60→36 round trips. Shipped **without** its budget test — see RpcStats below. |
| roster by member names | [#326](https://github.com/foks-proj/go-foks/pull/326) | Uses upstream's own username cache (#298) on a path that missed it. |
| `--vhost` strict lookup | [#327](https://github.com/foks-proj/go-foks/pull/327) | Typo'd `--vhost` rewrote the **primary** host's public zone. Found by cubic on our merge PR #21. |

## Queued — decided yes, not yet opened

| Change | Waiting on | Notes |
|---|---|---|
| `patch-db --yes` | nothing — open it | ~20 LoC. Unattended deploys can't answer a prompt. |
| `Config.RPCLogOptions` via env/config | nothing — open it | ~10 LoC. Flag-only today, so the mobile agent can never enable RPC tracing. Must be split out of our RpcStats commit. |
| parallel explore waves | **#325 landing** | 4533→1367ms. Builds on #325; racing it would conflict. |
| `TeamCancelRequest` + `TeamReject` | nothing — open it | Withdraw your own join request; let an admin deliberately reject one. Upstream calls `RejectJoinReq` only automatically on cycle errors — there is no deliberate path. |
| issue: how should "leave a team" be modelled? | nothing — open it | See `TeamLeaveSelf` under Declined. Ask before spending a PR. |

## Declined — considered, rejected, stays rejected

### RpcStats scope reporter
Was upstream [#318](https://github.com/foks-proj/go-foks/pull/318); we closed it
ourselves. **Keep it local.**

The counting is general — one context-scoped counter at `RpcClient.Call2`, the
funnel every generated client passes through, nil-safe and ~free when nothing
collects. But the *reporter hook* exists for a mobile-only reason: go-foks logs
inside the iOS app container where no device capture reaches, and the gomobile
bridge cannot open a scope itself because `RpcStats` travels by context value
and the bridge talks to the agent over loopback RPC. A CLI or server operator
has zap and needs none of this.

**One open thread:** #325 had to ship without its round-trip budget test, which
needs this hook. #325's body offers the hook separately. If maxtaco asks for it,
that is a request, not a re-proposal — reopen this decision then, and not before.

### `TeamLeaveSelf`
**Local, and do not propose without the design conversation first.**

It writes only the member's own membership chain. It does *not* update
`team_members` or rotate PTKs — that needs an admin `EditTeam` with role `NONE`.
So a member who "leaves" still holds the current PTK and can still read team
data written afterwards, and still appears in everyone's roster. Our app is safe
because it pairs the call with a signal to the owner; as general public API the
name invites a security-relevant misreading.

Worse since upstream #319: **a sole owner** can self-attest leaving but can never
be removed, because removing the last owner is now refused server-side. The team
is stuck with an owner who believes they left.

### Upstream release tooling (`make/server.mk`, `release.md`)
cubic flagged a hardcoded `maxtaco` GHCR username and inconsistent `cd ../pkgs`
paths on our merge PR #21. Both are upstream's own release process; our deploy
does not use `server.mk` at all. **Not ours to patch.**

### `HasMemberRole` / `MakeChange` host-guard mismatch
cubic finding on #21. **Not a defect.** The premise is that `TeamAdmit` builds
rows whose `Id.Host` is non-nil and equal to the home host — the shape
`MakeChange` rejects. But `AtHost(h)` sets `Host = nil` exactly when the host
equals `h`, so that shape cannot arise. If it could, every admit would fail.

### `team_admin.go` "edit" vs "change" wording
cubic finding on #21. Real but cosmetic — same error type, one word apart, in a
subsystem unrelated to anything we are proposing. Not worth the review cost.

## Local — deliberately ours forever

| Change | Why |
|---|---|
| `.github/workflows/deploy.yml`, `scripts/deploy/*` | Our Hetzner deploy. Means nothing upstream. |
| `.github/workflows/ci.yml` `GO_PKGS` scoping | We exclude `integration-tests/` because this workflow provisions no postgres. Upstream runs plain `./...`. |

## Upstreamed — merged, ours only until the next merge

| Change | PR |
|---|---|
| lockstate propagation | [#287](https://github.com/foks-proj/go-foks/pull/287) — upstream tightened it to run only after `UnlockKeys` succeeds; our unguarded copy is deleted |
| iOS `sharedHome` nil guard | [#289](https://github.com/foks-proj/go-foks/pull/289) |
| libclient public Config setters | [#290](https://github.com/foks-proj/go-foks/pull/290) |
| rejoin partial unique index | [#316](https://github.com/foks-proj/go-foks/pull/316) — our #288 was closed as superseded; upstream took our text verbatim as `p7.sql` |
