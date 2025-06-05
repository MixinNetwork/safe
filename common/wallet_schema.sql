CREATE TABLE IF NOT EXISTS properties (
  key           VARCHAR NOT NULL,
  value         VARCHAR NOT NULL,
  created_at    TIMESTAMP NOT NULL,
  updated_at    TIMESTAMP NOT NULL,
  PRIMARY KEY ('key')
);

CREATE TABLE IF NOT EXISTS outputs (
  output_id            VARCHAR NOT NULL,
  transaction_hash     VARCHAR NOT NULL,
  output_index         INTEGER NOT NULL,
  asset_id             VARCHAR NOT NULL,
  kernel_asset_id      VARCHAR NOT NULL,
  amount               VARCHAR NOT NULL,
  senders_threshold    INTEGER NOT NULL,
  senders              VARCHAR NOT NULL,
  state                VARCHAR NOT NULL,
  sequence             INTEGER NOT NULL,
  created_at           TIMESTAMP NOT NULL,
  updated_at           TIMESTAMP NOT NULL,
  signed_by            VARCHAR,
  PRIMARY KEY ('output_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS outputs_by_sequence ON outputs(sequence);
CREATE INDEX IF NOT EXISTS outputs_by_asset_state_signedx ON outputs(asset_id, state, signed_by);
