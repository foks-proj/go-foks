
/*
 * Upgrade the inbox-sync hot index to UNIQUE, enforcing the invariant that no
 * two of a user's channel rows share an inbox version (each version is
 * allocated by a serialized +1 bump of user_inbox and stamps exactly one
 * user_channels row). get_changed_threads' cursor pagination depends on this;
 * see the comment on the index in foks_realtime.sql.
 */
DROP INDEX user_channels_inbox_idx;
CREATE UNIQUE INDEX user_channels_inbox_idx ON user_channels(short_host_id, uid, app_id, inbox_version);
