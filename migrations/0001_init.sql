-- One row per synced key (recipe libraries, settings, and one row per planned week)
CREATE TABLE state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Global change counter so clients can cheaply ask "anything new since version N?"
CREATE TABLE meta (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
);

-- kind: 'auto' (session checkpoint), 'undo' (before a destructive action), 'saved' (named plan)
CREATE TABLE snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  kind TEXT NOT NULL,
  label TEXT NOT NULL,
  week TEXT,
  summary TEXT NOT NULL,
  data TEXT NOT NULL
);
CREATE INDEX snapshots_kind_id ON snapshots (kind, id);

CREATE TABLE login_attempts (
  ip TEXT PRIMARY KEY,
  fails INTEGER NOT NULL,
  first_fail_at INTEGER NOT NULL
);
