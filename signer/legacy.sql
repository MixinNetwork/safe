CREATE TABLE IF NOT EXISTS properties (
  key           VARCHAR NOT NULL,
  value         VARCHAR NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  PRIMARY KEY ('key')
);

CREATE TABLE IF NOT EXISTS keys (
	public      VARCHAR NOT NULL,
	fingerprint VARCHAR NOT NULL,
	curve       INTEGER NOT NULL,
	share       VARHCAR NOT NULL,
	session_id  VARCHAR NOT NULL,
	created_at  TIMESTAMP NOT NULL,
	PRIMARY KEY ('public')
);

CREATE UNIQUE INDEX IF NOT EXISTS keys_by_session_id ON keys(session_id);
CREATE UNIQUE INDEX IF NOT EXISTS keys_by_fingerprint ON keys(fingerprint);

CREATE TABLE IF NOT EXISTS sessions (
	session_id    VARCHAR NOT NULL,
	mixin_hash    VARCHAR NOT NULL,
	mixin_index   INTEGER NOT NULL,
	operation     INTEGER NOT NULL,
	curve         INTEGER NOT NULL,
	public        VARCHAR NOT NULL,
	extra         VARCHAR NOT NULL,
	state         INTEGER NOT NULL,
	created_at    TIMESTAMP NOT NULL,
	updated_at    TIMESTAMP NOT NULL,
	committed_at  TIMESTAMP,
	prepared_at   TIMESTAMP,
	PRIMARY KEY ('session_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS sessions_by_mixin_hash_index ON sessions(mixin_hash, mixin_index);
CREATE INDEX IF NOT EXISTS sessions_by_state_created ON sessions(state, created_at);


CREATE TABLE IF NOT EXISTS session_signers (
	session_id  VARCHAR NOT NULL,
	signer_id   VARCHAR NOT NULL,
	extra       VARCHAR NOT NULL,
	created_at  TIMESTAMP NOT NULL,
	updated_at  TIMESTAMP NOT NULL,
	PRIMARY KEY ('session_id', 'signer_id')
);


CREATE TABLE IF NOT EXISTS session_works (
	session_id  VARCHAR NOT NULL,
	signer_id   VARCHAR NOT NULL,
	round       INTEGER NOT NULL,
	extra       VARCHAR NOT NULL,
	created_at  TIMESTAMP NOT NULL,
	PRIMARY KEY ('session_id', 'signer_id', 'round')
);