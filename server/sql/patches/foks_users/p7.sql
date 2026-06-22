/*
 * Rejoin-after-leave fix (SECO): allow a former member to create a NEW join
 * request once their earlier one is no longer pending.
 *
 * The original index enforced "one join request per joiner per team, EVER" —
 * but admit/reject only UPDATE the row's state (never delete), so a user who
 * joined once, left, and was re-invited could never re-RSVP: the insert hit
 * the index and returned TeamInviteAlreadyAcceptedError ("team invite
 * already accepted" — observed in the wild on 2026-06-10).
 *
 * The partial index preserves the original intent (no duplicate PENDING
 * requests — the insert handler's IsDuplicateKeyError check keeps working,
 * same index name) while letting historical approved/rejected/withdrawn rows
 * accumulate harmlessly. All readers are state- or token-scoped; the parallel
 * remote_joinreqs table never had joiner uniqueness at all.
 */

DROP INDEX IF EXISTS local_joinreq_joiner_idx;
CREATE UNIQUE INDEX local_joinreq_joiner_idx
    ON local_joinreqs(short_host_id, team_id, joiner_party_id,
                      joiner_src_role_type, joiner_src_viz_level)
    WHERE state = 'pending';
