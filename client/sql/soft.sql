
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS global_kv (
    key TEXT NOT NULL PRIMARY KEY,
    val BLOB,
    ctime INTEGER NOT NULL,
    mtime INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS global_set (
    key TEXT NOT NULL,
    hash BLOB NOT NULL,
    val BLOB NOT NULL,
    ctime INTEGER NOT NULL,
    PRIMARY KEY(key, hash)
) STRICT;

CREATE TABLE IF NOT EXISTS scope (
    id INTEGER NOT NULL PRIMARY KEY,
    label BLOB NOT NULL
) STRICT;

CREATE UNIQUE INDEX IF NOT EXISTS scope_idx ON scope(label);

CREATE TABLE IF NOT EXISTS scoped_data (
    scope_id INTEGER NOT NULL,
    typ INTEGER NOT NULL,
    key BLOB NOT NULL,
    val BLOB,
    ctime INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    gc_bit INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(scope_id, typ, key),
    FOREIGN KEY(scope_id) REFERENCES scope(id)
) STRICT;

CREATE TABLE IF NOT EXISTS scoped_counters (
    scope_id INTEGER NOT NULL,
    typ INTEGER NOT NULL,
    val INTEGER NOT NULL,
    ctime INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    PRIMARY KEY (scope_id, typ),
    FOREIGN KEY(scope_id) REFERENCES scope(id)
) STRICT;

CREATE INDEX IF NOT EXISTS scoped_data_ctime_idx ON scoped_data(ctime);

/*
 * We can select a number of rows in a selected numerical range,
 * using the same other key components as above.
 */
CREATE TABLE IF NOT EXISTS ranged_data (
    scope_id INTEGER NOT NULL,
    typ INTEGER NOT NULL,
    key BLOB NOT NULL,
    idx INTEGER NOT NULL,
    val BLOB, 
    ctime INTEGER NOT NULL,
    PRIMARY KEY(scope_id, typ, key, idx),
    FOREIGN KEY(scope_id) REFERENCES scope(id)
) STRICT;

CREATE TABLE IF NOT EXISTS ranged_data_gc_bit (
    scope_id INTEGER NOT NULL,
    typ INTEGER NOT NULL,
    key BLOB NOT NULL,
    gc_bit INTEGER NOT NULL DEFAULT 0,
    ctime INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    PRIMARY KEY(scope_id, typ, key),
    FOREIGN KEY(scope_id) REFERENCES scope(id)
) STRICT;


INSERT OR IGNORE INTO scope (id, label) VALUES (0, X'00')