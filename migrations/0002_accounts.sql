-- Each account signs in with its own password and gets its own synced state, version counter and history.
-- password_secret names the Worker secret that holds the password. baby = 1 shows the baby features.
-- Rows are added with wrangler d1 execute (see AGENTS.md) so usernames stay out of the repo.
CREATE TABLE accounts (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_secret TEXT NOT NULL,
  baby INTEGER NOT NULL DEFAULT 1
);

-- Existing data becomes account 1
CREATE TABLE state_new (
  account INTEGER NOT NULL,
  key TEXT NOT NULL,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (account, key)
);
INSERT INTO state_new (account, key, value, updated_at) SELECT 1, key, value, updated_at FROM state;
DROP TABLE state;
ALTER TABLE state_new RENAME TO state;

CREATE TABLE meta_new (
  account INTEGER PRIMARY KEY,
  version INTEGER NOT NULL
);
INSERT INTO meta_new (account, version) SELECT 1, version FROM meta;
DROP TABLE meta;
ALTER TABLE meta_new RENAME TO meta;

ALTER TABLE snapshots ADD COLUMN account INTEGER NOT NULL DEFAULT 1;
DROP INDEX snapshots_kind_id;
CREATE INDEX snapshots_account_kind_id ON snapshots (account, kind, id);
