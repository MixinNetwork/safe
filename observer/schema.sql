CREATE TABLE IF NOT EXISTS properties (
  key           VARCHAR NOT NULL,
  value         VARCHAR NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  updated_at    TIMESTAMP NOT NULL,
  PRIMARY KEY ('key')
);


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




CREATE TABLE IF NOT EXISTS accountants (
  public_key     VARCHAR NOT NULL,
  private_key    VARCHAR NOT NULL,
  address        VARCHAR NOT NULL,
  curve          INTEGER NOT NULL,
  created_at     TIMESTAMP NOT NULL,
  PRIMARY KEY ('public_key')
);

CREATE UNIQUE INDEX IF NOT EXISTS accountants_by_private_key ON accountants(private_key);




CREATE TABLE IF NOT EXISTS observers (
  public_key     VARCHAR NOT NULL,
  curve          INTEGER NOT NULL,
  chain_code     VARCHAR NOT NULL,
  created_at     TIMESTAMP NOT NULL,
  PRIMARY KEY ('public_key')
);



CREATE TABLE IF NOT EXISTS accounts (
  address       VARCHAR NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  signature     VARCHAR,
  approved_at   TIMESTAMP,
  migrated_at   TIMESTAMP,
  PRIMARY KEY ('address')
);




CREATE TABLE IF NOT EXISTS deposits (
  transaction_hash   VARCHAR NOT NULL,
  output_index       VARCHAR NOT NULL,
  asset_id           VARCHAR NOT NULL,
  asset_address      VARCHAR NOT NULL,
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

CREATE INDEX IF NOT EXISTS deposits_by_chain_state_created ON deposits(chain, state, created_at);




CREATE TABLE IF NOT EXISTS transactions (
  transaction_hash   VARCHAR NOT NULL,
  raw_transaction    VARCHAR NOT NULL,
  chain              INTEGER NOT NULL,
  holder             VARCHAR NOT NULL,
  signer             VARCHAR NOT NULL,
  state              INTEGER NOT NULL,
  spent_hash         VARCHAR,
  spent_raw          VARCHAR,
  created_at         TIMESTAMP NOT NULL,
  updated_at         TIMESTAMP NOT NULL,
  PRIMARY KEY ('transaction_hash')
);

CREATE INDEX IF NOT EXISTS transactions_by_chain_state_created ON transactions(chain, state, created_at);




CREATE TABLE IF NOT EXISTS bitcoin_outputs (
  transaction_hash   VARCHAR NOT NULL,
  output_index       INTEGER NOT NULL,
  address            VARCHAR NOT NULL,
  satoshi            INTEGER NOT NULL,
  chain              INTEGER NOT NULL,
  state              INTEGER NOT NULL,
  spent_by           VARCHAR,
  raw_transaction    VARCHAR,
  created_at         TIMESTAMP NOT NULL,
  updated_at         TIMESTAMP NOT NULL,
  PRIMARY KEY ('transaction_hash', 'output_index')
);

CREATE INDEX IF NOT EXISTS bitcoin_outputs_by_chain_state_created ON bitcoin_outputs(chain, state, created_at);



CREATE TABLE IF NOT EXISTS recoveries (
  address            VARCHAR NOT NULL,
  chain              INTEGER NOT NULL,
  holder             VARCHAR NOT NULL,
  observer           VARCHAR NOT NULL,
  raw_transaction    VARCHAR NOT NULL,
  transaction_hash   VARCHAR,
  state              INTEGER NOT NULL,
  created_at         TIMESTAMP NOT NULL,
  updated_at         TIMESTAMP NOT NULL,
  PRIMARY KEY ('address')
);
