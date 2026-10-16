/*
 * Push holds, part 1 (see p7.sql).
 *
 * A push_outbox row written under a push hold is 'held'. The relay does not
 * claim it; the hold's holder either queues it or deletes it.
 *
 * This is alone in its patch because Postgres cannot use a new enum value in
 * the transaction that adds it, and each patch runs in one transaction.
 */
ALTER TYPE push_status ADD VALUE IF NOT EXISTS 'held';
