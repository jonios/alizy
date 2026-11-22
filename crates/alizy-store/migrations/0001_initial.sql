-- Profiles: only the NON-secret projection of the config is stored here.
-- Private keys and pre-shared keys live in the OS secret store.
CREATE TABLE profiles (
    id                TEXT PRIMARY KEY NOT NULL,
    name              TEXT NOT NULL,
    category          TEXT,
    favorite          INTEGER NOT NULL DEFAULT 0,
    fingerprint       TEXT NOT NULL UNIQUE,
    public_config     TEXT NOT NULL,
    cached_endpoints  TEXT NOT NULL DEFAULT '[]',
    sort_order        INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    last_connected_at INTEGER
);
CREATE INDEX profiles_name ON profiles(name);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id   TEXT NOT NULL,
    profile_name TEXT NOT NULL,
    started_at   INTEGER NOT NULL,
    ended_at     INTEGER,
    rx_bytes     INTEGER NOT NULL DEFAULT 0,
    tx_bytes     INTEGER NOT NULL DEFAULT 0,
    end_reason   TEXT
);
CREATE INDEX history_started ON history(started_at DESC);

CREATE TABLE events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    level    TEXT NOT NULL,
    category TEXT NOT NULL,
    source   TEXT NOT NULL,
    message  TEXT NOT NULL
);
CREATE INDEX events_ts ON events(ts DESC);
