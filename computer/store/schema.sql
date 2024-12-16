CREATE TABLE IF NOT EXISTS properties (
	key           VARCHAR NOT NULL,
	value         VARCHAR NOT NULL,
	created_at    TIMESTAMP NOT NULL,
	PRIMARY KEY ('key')
);


CREATE TABLE IF NOT EXISTS keys (
	public       VARCHAR NOT NULL,
	fingerprint  VARCHAR NOT NULL,
	share        VARCHAR NOT NULL,
	session_id   VARCHAR NOT NULL,
	user_id      VARCHAR,
	created_at   TIMESTAMP NOT NULL,
	updated_at   TIMESTAMP NOT NULL,
	backed_up_at TIMESTAMP,
	PRIMARY KEY ('public')
);

CREATE UNIQUE INDEX IF NOT EXISTS keys_by_session_id ON keys(session_id);
CREATE UNIQUE INDEX IF NOT EXISTS keys_by_fingerprint ON keys(fingerprint);
CREATE INDEX IF NOT EXISTS keys_by_user_created ON keys(user_id, created_at);


CREATE TABLE IF NOT EXISTS sessions (
	session_id    VARCHAR NOT NULL,
	mixin_hash    VARCHAR NOT NULL,
	mixin_index   INTEGER NOT NULL,
    sub_index     INTEGER NOT NULL,
	operation     INTEGER NOT NULL,
	public        VARCHAR NOT NULL,
	extra         VARCHAR NOT NULL,
	state         INTEGER NOT NULL,
	created_at    TIMESTAMP NOT NULL,
	updated_at    TIMESTAMP NOT NULL,
	committed_at  TIMESTAMP,
	prepared_at   TIMESTAMP,
	PRIMARY KEY ('session_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS sessions_by_mixin_hash_index ON sessions(mixin_hash, mixin_index, sub_index);
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


CREATE TABLE IF NOT EXISTS requests (
  request_id  VARCHAR NOT NULL,
  mixin_hash  VARCHAR NOT NULL,
  mixin_index INTEGER NOT NULL,
  asset_id    VARCHAR NOT NULL,
  amount      VARCHAR NOT NULL,
  role        INTEGER NOT NULL,
  action      INTEGER NOT NULL,
  extra       VARCHAR NOT NULL,
  state       INTEGER NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  updated_at  TIMESTAMP NOT NULL,
  sequence    INTEGER NOT NULL,
  PRIMARY KEY ('request_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS requests_by_mixin_hash_index ON requests(mixin_hash, mixin_index);
CREATE INDEX IF NOT EXISTS requests_by_state_created ON requests(state, created_at);


CREATE TABLE IF NOT EXISTS programs (
  program_id  VARCHAR NOT NULL,
  request_id  VARCHAR NOT NULL,
  address     VARCHAR NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  PRIMARY KEY ('program_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS programs_by_address ON programs(address);
CREATE INDEX IF NOT EXISTS programs_by_created ON programs(created_at);


CREATE TABLE IF NOT EXISTS users (
  user_id     VARCHAR NOT NULL,
  request_id  VARCHAR NOT NULL,
  address     VARCHAR NOT NULL,
  public      VARCHAR NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  PRIMARY KEY ('user_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS users_by_address ON users(address);
CREATE INDEX IF NOT EXISTS users_by_created ON users(created_at);


CREATE TABLE IF NOT EXISTS action_results (
	output_id       VARCHAR NOT NULL,
	compaction      VARCHAR NOT NULL,
	transactions    TEXT NOT NULL,
	request_id      VARCHAR NOT NULL,
	created_at      TIMESTAMP NOT NULL,
	PRIMARY KEY ('output_id')
);

CREATE INDEX IF NOT EXISTS action_results_by_request ON action_results(request_id);
