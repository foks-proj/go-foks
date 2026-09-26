
/*
 * Channel archive.
 *
 * An archived channel is closed to new activity and leaves the inbox, but it
 * is not deleted: its messages, parties and delivery rows all stay. NULL means
 * live, so existing channels need no backfill.
 *
 * A nullable timestamp rather than a boolean, because "when was this closed"
 * is the question asked afterwards and the column costs the same either way.
 *
 * An archived channel deliberately STAYS in rtListAllChannelsForTeam. The
 * channel set doubles as the team's name registry: name_box is PTK-encrypted,
 * so only a client can compare names, and a client can only refuse a duplicate
 * name it can still see. Dropping archived rows from the listing would free
 * the name and make every un-archive a collision the server has no way to
 * detect. What archive removes is the channel's presence in the INBOX
 * (rtGetChangedThreads) and in the late-join fan-in.
 */
ALTER TABLE channels ADD COLUMN archived_at TIMESTAMPTZ;
