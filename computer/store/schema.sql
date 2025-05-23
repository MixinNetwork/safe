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
CREATE INDEX IF NOT EXISTS sessions_by_state_operation_created_index ON sessions(state, operation, created_at, sub_index);


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
CREATE INDEX IF NOT EXISTS requests_by_hash ON requests(mixin_hash);
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



CREATE TABLE IF NOT EXISTS external_assets (
  asset_id        VARCHAR NOT NULL,
  uri             TEXT,
  icon_url        TEXT,
  created_at      TIMESTAMP NOT NULL,
  requested_at    TIMESTAMP,
  deployed_at     TIMESTAMP,
  PRIMARY KEY ('asset_id')
);

CREATE INDEX IF NOT EXISTS assets_by_deployed ON external_assets(icon_url, deployed_at);


CREATE TABLE IF NOT EXISTS deployed_assets (
  asset_id        VARCHAR NOT NULL,
  chain_id        VARCHAR NOT NULL,
  address         VARCHAR NOT NULL,
  decimals        INTEGER NOT NULL,
  state           INTEGER NOT NULL,
  created_at      TIMESTAMP NOT NULL,
  PRIMARY KEY ('asset_id')
);

CREATE INDEX IF NOT EXISTS assets_by_address_state ON deployed_assets(address, state);


CREATE TABLE IF NOT EXISTS system_calls (
  id                    VARCHAR NOT NULL,
  superior_id           VARCHAR NOT NULL,
  request_hash          VARCHAR NOT NULL,
  call_type             VARCHAR NOT NULL,
  nonce_account         VARCHAR NOT NULL,
  public                VARCHAR NOT NULL,
  skip_postprocess      BOOLEAN NOT NULL,
  message               VARCHAR NOT NULL,
  raw                   TEXT NOT NULL,
  state                 INTEGER NOT NULL,
  withdrawal_traces     VARCHAR,
  withdrawn_at          TIMESTAMP,
  signature             VARCHAR,
  request_signer_at     TIMESTAMP,
  hash                  VARCHAR,
  created_at            TIMESTAMP NOT NULL,
  updated_at            TIMESTAMP NOT NULL,
  PRIMARY KEY ('id')
);

CREATE INDEX IF NOT EXISTS calls_by_message ON system_calls(message);
CREATE INDEX IF NOT EXISTS calls_by_hash ON system_calls(hash);
CREATE INDEX IF NOT EXISTS calls_by_state_withdrawal_created ON system_calls(state, withdrawal_traces, withdrawn_at, created_at);
CREATE INDEX IF NOT EXISTS calls_by_state_signature_created ON system_calls(state, withdrawal_traces, signature, created_at);
CREATE INDEX IF NOT EXISTS calls_by_superior_state_created ON system_calls(superior_id, state, created_at);


CREATE TABLE IF NOT EXISTS user_outputs (
  output_id          VARCHAR NOT NULL,
  user_id            VARCHAR NOT NULL,
  request_id         VARCHAR NOT NULL,
  transaction_hash   VARCHAR NOT NULL,
  output_index       INTEGER NOT NULL,
  asset_id           VARCHAR NOT NULL,
  chain_id           VARCHAR NOT NULL,
  amount             VARCHAR NOT NULL,
  state              INTEGER NOT NULL,
  sequence           INTEGER NOT NULL,
  signed_by          VARCHAR,
  created_at         TIMESTAMP NOT NULL,
  updated_at         TIMESTAMP NOT NULL,
  PRIMARY KEY ('output_id')
);


CREATE TABLE IF NOT EXISTS nonce_accounts (
  address        VARCHAR NOT NULL,
  hash           VARCHAR NOT NULL,
  mix            VARCHAR,
  call_id        VARCHAR,
  updated_by     VARCHAR,
  created_at     TIMESTAMP NOT NULL,
  updated_at     TIMESTAMP NOT NULL,
  PRIMARY KEY ('address')
);

CREATE INDEX IF NOT EXISTS nonces_by_mix_call_updated ON nonce_accounts(mix, call_id, updated_at);


CREATE TABLE IF NOT EXISTS confirmed_withdrawals (
  hash           VARCHAR NOT NULL,
  trace_id       VARCHAR NOT NULL,
  call_id        VARCHAR NOT NULL,
  created_at     TIMESTAMP NOT NULL,
  PRIMARY KEY ('hash')
);


CREATE TABLE IF NOT EXISTS fees (
  fee_id         VARCHAR NOT NULL,
  ratio          VARCHAR NOT NULL,
  created_at     TIMESTAMP NOT NULL,
  PRIMARY KEY ('fee_id')
);

CREATE INDEX IF NOT EXISTS fees_by_created ON fees(created_at);


-- TODO use a separate sqlite3 for caches
CREATE TABLE IF NOT EXISTS caches (
  key           VARCHAR NOT NULL,
  value         TEXT NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  PRIMARY KEY ('key')
);

CREATE INDEX IF NOT EXISTS caches_by_created ON caches(created_at);


CREATE TABLE IF NOT EXISTS failed_calls (
  call_id       VARCHAR NOT NULL,
  reason        TEXT NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  PRIMARY KEY ('call_id')
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
