/*
 * No-push channels.
 *
 * A channel marked no_push is skipped by the push_outbox fan-out on send. The
 * inbox-version bump is untouched, so members' parked long-polls still wake
 * and online delivery is unchanged; what a no-push channel never does is
 * queue a phone notification.
 *
 * A plaintext column rather than something derived from the channel's name:
 * names are PTK-encrypted (name_box), so the send path cannot tell a control
 * channel from a conversational one any other way.
 */
ALTER TABLE channels ADD COLUMN no_push BOOLEAN NOT NULL DEFAULT false;
