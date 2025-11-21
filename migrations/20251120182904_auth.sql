-- Add migration script here
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY,

    display_name TEXT,

    admin BOOLEAN NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    permissions INTEGER NOT NULL,

    version TEXT NOT NULL,

    UNIQUE(username)
);

CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,

    user_agent TEXT NOT NULL,
    last_active INTEGER NOT NULL,

    FOREIGN KEY (user_id) REFERENCES user (id)
);

CREATE TABLE IF NOT EXISTS refresh_token (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,

    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,

    FOREIGN KEY (session_id) REFERENCES session(id)
);