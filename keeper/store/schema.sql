CREATE TABLE IF NOT EXISTS requests (
  request_id  VARCHAR NOT NULL,
  mixin_hash  VARCHAR NOT NULL,
  mixin_index INTEGER NOT NULL,
  asset_id    VARCHAR NOT NULL,
  amount      VARCHAR NOT NULL,
  role        INTEGER NOT NULL,
  action      INTEGER NOT NULL,
  curve       INTEGER NOT NULL,
  holder      VARCHAR NOT NULL,
  extra       VARCHAR NOT NULL,
  state       INTEGER NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  updated_at  TIMESTAMP NOT NULL,
  sequence    INTEGER NOT NULL,
  PRIMARY KEY ('request_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS requests_by_mixin_hash_index ON requests(mixin_hash, mixin_index);
CREATE INDEX IF NOT EXISTS requests_by_state_created ON requests(state, created_at);




CREATE TABLE IF NOT EXISTS network_infos (
  request_id      VARCHAR NOT NULL,
  chain           INTEGER NOT NULL,
  fee             INTEGER NOT NULL,
  hash            VARCHAR NOT NULL,
  height          INTEGER NOT NULL,
  created_at      TIMESTAMP NOT NULL,
  PRIMARY KEY ('request_id')
);

CREATE INDEX IF NOT EXISTS network_infos_by_chain_created ON network_infos(chain, created_at);




CREATE TABLE IF NOT EXISTS operation_params (
  request_id           VARCHAR NOT NULL,
  chain                INTEGER NOT NULL,
  price_asset          VARCHAR NOT NULL,
  price_amount         VARCHAR NOT NULL,
  transaction_minimum  VARCHAR NOT NULL,
  created_at           TIMESTAMP NOT NULL,
  PRIMARY KEY ('request_id')
);

CREATE INDEX IF NOT EXISTS operation_params_by_chain_created ON operation_params(chain, created_at);




CREATE TABLE IF NOT EXISTS assets (
  asset_id      VARCHAR NOT NULL,
  mixin_id      VARCHAR NOT NULL,
  asset_key     VARCHAR NOT NULL,
  symbol        VARCHAR NOT NULL,
  name          VARCHAR NOT NULL,
  decimals      INTEGER NOT NULL,
  chain         INTEGER NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  PRIMARY KEY ('asset_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS assets_by_mixin_id ON assets(mixin_id);





CREATE TABLE IF NOT EXISTS keys (
  public_key      VARCHAR NOT NULL,
  curve           INTEGER NOT NULL,
  request_id      VARCHAR NOT NULL,
  role            INTEGER NOT NULL,
  extra           VARCHAR NOT NULL,
  flags           INTEGER NOT NULL,
  holder          VARCHAR,
  created_at      TIMESTAMP NOT NULL,
  updated_at      TIMESTAMP NOT NULL,
  PRIMARY KEY ('public_key')
);

CREATE UNIQUE INDEX IF NOT EXISTS keys_by_request_id ON keys(request_id);
CREATE UNIQUE INDEX IF NOT EXISTS keys_by_holder_role ON keys(holder, role);






CREATE TABLE IF NOT EXISTS safe_proposals (
  request_id       VARCHAR NOT NULL,
  chain            INTEGER NOT NULL,
  holder           VARCHAR NOT NULL,
  signer           VARCHAR NOT NULL,
  observer         VARCHAR NOT NULL,
  timelock         INTEGER NOT NULL,
  path             VARCHAR NOT NULL,
  address          VARCHAR NOT NULL,
  extra            VARCHAR NOT NULL,
  receivers        VARCHAR NOT NULL,
  threshold        INTEGER NOT NULL,
  created_at       TIMESTAMP NOT NULL,
  updated_at       TIMESTAMP NOT NULL,
  PRIMARY KEY ('request_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS safe_proposals_by_signer ON safe_proposals(signer);
CREATE UNIQUE INDEX IF NOT EXISTS safe_proposals_by_observer ON safe_proposals(observer);
CREATE UNIQUE INDEX IF NOT EXISTS safe_proposals_by_address ON safe_proposals(address);






CREATE TABLE IF NOT EXISTS safes (
  holder           VARCHAR NOT NULL,
  chain            INTEGER NOT NULL,
  signer           VARCHAR NOT NULL,
  observer         VARCHAR NOT NULL,
  timelock         INTEGER NOT NULL,
  path             VARCHAR NOT NULL,
  address          VARCHAR NOT NULL,
  extra            VARCHAR NOT NULL,
  receivers        VARCHAR NOT NULL,
  threshold        INTEGER NOT NULL,
  request_id       VARCHAR NOT NULL,
  nonce            INTEGER NOT NULL,
  state            INTEGER NOT NULL,
  receiver         VARCHAR NOT NULL,
  created_at       TIMESTAMP NOT NULL,
  updated_at       TIMESTAMP NOT NULL,
  PRIMARY KEY ('holder')
);

CREATE UNIQUE INDEX IF NOT EXISTS safes_by_signer ON safes(signer);
CREATE UNIQUE INDEX IF NOT EXISTS safes_by_observer ON safes(observer);
CREATE UNIQUE INDEX IF NOT EXISTS safes_by_address ON safes(address);
CREATE UNIQUE INDEX IF NOT EXISTS safes_by_request_id ON safes(request_id);





CREATE TABLE IF NOT EXISTS bitcoin_outputs (
  transaction_hash   VARCHAR NOT NULL,
  output_index       INTEGER NOT NULL,
  address            VARCHAR NOT NULL,
  satoshi            INTEGER NOT NULL,
  script             VARCHAR NOT NULL,
  sequence           INTEGER NOT NULL,
  chain              INTEGER NOT NULL,
  state              INTEGER NOT NULL,
  spent_by           VARCHAR,
  request_id         VARCHAR NOT NULL,
  created_at         TIMESTAMP NOT NULL,
  updated_at         TIMESTAMP NOT NULL,
  PRIMARY KEY ('transaction_hash', 'output_index')
);

CREATE UNIQUE INDEX IF NOT EXISTS bitcoin_outputs_by_request_id ON bitcoin_outputs(request_id);
CREATE INDEX IF NOT EXISTS bitcoin_outputs_by_address_state_created ON bitcoin_outputs(address, state, created_at);






CREATE TABLE IF NOT EXISTS ethereum_balances (
  address            VARCHAR NOT NULL,
  asset_id           VARCHAR NOT NULL,
  asset_address      VARCHAR NOT NULL,
  balance            VARCHAR NOT NULL,
  latest_tx_hash     VARCHAR NOT NULL,
  updated_at         TIMESTAMP NOT NULL,
  PRIMARY KEY ('address', 'asset_id')
);







CREATE TABLE IF NOT EXISTS deposits (
  transaction_hash   VARCHAR NOT NULL,
  output_index       VARCHAR NOT NULL,
  asset_id           VARCHAR NOT NULL,
  amount             VARCHAR NOT NULL,
  receiver           VARCHAR NOT NULL,
  sender             VARCHAR NOT NULL,
  state              INTEGER NOT NULL,
  chain              INTEGER NOT NULL,
  holder             VARCHAR NOT NULL,
  category           INTEGER NOT NULL,
  created_at         TIMESTAMP NOT NULL,
  updated_at         TIMESTAMP NOT NULL,
  PRIMARY KEY ('transaction_hash', 'output_index')
);







CREATE TABLE IF NOT EXISTS transactions (
  transaction_hash   VARCHAR NOT NULL,
  raw_transaction    VARCHAR NOT NULL,
  holder             VARCHAR NOT NULL,
  chain              INTEGER NOT NULL,
  asset_id           VARCHAR NOT NULL,
  state              INTEGER NOT NULL,
  data               VARCHAR NOT NULL,
  request_id         VARCHAR NOT NULL,
  created_at         TIMESTAMP NOT NULL,
  updated_at         TIMESTAMP NOT NULL,
  PRIMARY KEY ('transaction_hash')
);

CREATE UNIQUE INDEX IF NOT EXISTS transactions_by_request_id ON transactions(request_id);





CREATE TABLE IF NOT EXISTS signature_requests (
  request_id          VARCHAR NOT NULL,
  transaction_hash    VARCHAR NOT NULL,
  input_index         INTEGER NOT NULL,
  signer              VARCHAR NOT NULL,
  curve               INTEGER NOT NULL,
  message             VARCHAR NOT NULL,
  signature           VARCHAR,
  state               INTEGER NOT NULL,
  created_at          TIMESTAMP NOT NULL,
  updated_at          TIMESTAMP NOT NULL,
  PRIMARY KEY ('request_id')
);

CREATE INDEX IF NOT EXISTS signature_requests_by_transaction_state_created ON signature_requests(transaction_hash, state, created_at);




CREATE TABLE IF NOT EXISTS properties (
  key           VARCHAR NOT NULL,
  value         VARCHAR NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  PRIMARY KEY ('key')
);
