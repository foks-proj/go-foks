
/* 
 * Allows clients to ask for all channels updated since a particular set version,
 * so it can get only the updates since last sync.
 */
CREATE INDEX channel_set_updates_idx ON channels(short_host_id, parent_team_id, updated_at_set_vers);