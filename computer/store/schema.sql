CREATE TABLE IF NOT EXISTS properties (
  key           VARCHAR NOT NULL,
  value         VARCHAR NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  updated_at    TIMESTAMP NOT NULL,
  PRIMARY KEY ('key')
);


CREATE TABLE IF NOT EXISTS keys (
  public       VARCHAR NOT NULL,
  fingerprint  VARCHAR NOT NULL,
  share        VARCHAR NOT NULL,
  session_id   VARCHAR NOT NULL,
  created_at   TIMESTAMP NOT NULL,
  updated_at   TIMESTAMP NOT NULL,
  confirmed_at TIMESTAMP,
  backed_up_at TIMESTAMP,
  PRIMARY KEY ('public')
);

CREATE UNIQUE INDEX IF NOT EXISTS keys_by_session_id ON keys(session_id);
CREATE UNIQUE INDEX IF NOT EXISTS keys_by_fingerprint ON keys(fingerprint);
CREATE INDEX IF NOT EXISTS keys_by_confirmed ON keys(confirmed_at);


CREATE TABLE IF NOT EXISTS sessions (
  session_id    VARCHAR NOT NULL,
  request_id    VARCHAR NOT NULL,
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



CREATE TABLE IF NOT EXISTS operation_params (
  request_id           VARCHAR NOT NULL,
  price_asset          VARCHAR NOT NULL,
  price_amount         VARCHAR NOT NULL,
  created_at           TIMESTAMP NOT NULL,
  PRIMARY KEY ('request_id')
);

CREATE INDEX IF NOT EXISTS operation_params_by_created ON operation_params(created_at);


CREATE TABLE IF NOT EXISTS users (
  user_id        VARCHAR NOT NULL,
  request_id     VARCHAR NOT NULL,
  mix_address    VARCHAR NOT NULL,
  chain_address  VARCHAR NOT NULL,
  public         VARCHAR NOT NULL,
  created_at     TIMESTAMP NOT NULL,
  PRIMARY KEY ('user_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS users_by_mix_address ON users(mix_address);
CREATE UNIQUE INDEX IF NOT EXISTS users_by_chain_address ON users(chain_address);
CREATE INDEX IF NOT EXISTS users_by_created ON users(created_at);


CREATE TABLE IF NOT EXISTS deployed_assets (
  asset_id        VARCHAR NOT NULL,
  address         VARCHAR NOT NULL,
  created_at      TIMESTAMP NOT NULL,
  PRIMARY KEY ('asset_id')
);

CREATE INDEX IF NOT EXISTS assets_by_address ON deployed_assets(address);


CREATE TABLE IF NOT EXISTS system_calls (
  request_id            VARCHAR NOT NULL,
  superior_request_id   VARCHAR NOT NULL,
  call_type             VARCHAR NOT NULL,
  nonce_account         VARCHAR NOT NULL,
  public                VARCHAR NOT NULL,
  message               VARCHAR NOT NULL,
  raw                   TEXT NOT NULL,
  state                 INTEGER NOT NULL,
  withdrawal_ids        VARCHAR NOT NULL,
  withdrew_at           TIMESTAMP,
  signature             VARCHAR,
  request_signer_at     TIMESTAMP,
  created_at            TIMESTAMP NOT NULL,
  updated_at            TIMESTAMP NOT NULL,
  PRIMARY KEY ('request_id')
);


CREATE TABLE IF NOT EXISTS nonce_accounts (
  address        VARCHAR NOT NULL,
  hash           VARCHAR NOT NULL,
  mix            VARCHAR,
  call_id        VARCHAR,
  created_at     TIMESTAMP NOT NULL,
  updated_at     TIMESTAMP NOT NULL,
  PRIMARY KEY ('address')
);


CREATE TABLE IF NOT EXISTS confirmed_withdrawals (
  hash           VARCHAR NOT NULL,
  trace_id       VARCHAR NOT NULL,
  call_id        VARCHAR NOT NULL,
  created_at     TIMESTAMP NOT NULL,
  PRIMARY KEY ('hash')
);


CREATE TABLE IF NOT EXISTS action_results (
  output_id       VARCHAR NOT NULL,
  compaction      VARCHAR NOT NULL,
  transactions    TEXT NOT NULL,
  request_id      VARCHAR NOT NULL,
  created_at      TIMESTAMP NOT NULL,
  PRIMARY KEY ('output_id')
);

CREATE INDEX IF NOT EXISTS action_results_by_request ON action_results(request_id);
