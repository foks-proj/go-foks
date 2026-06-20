
/* Rename the channel "class" concept to "tier" (see foks_realtime.sql).
 * Renaming the enum type and the column preserves all existing data and the
 * 'bottom'/'admin' values; only the names change. */
ALTER TYPE channel_class RENAME TO channel_tier;
ALTER TABLE channels RENAME COLUMN class TO tier;
