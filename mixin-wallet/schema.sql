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
CREATE INDEX IF NOT EXISTS outputs_by_trace_sequence ON outputs(trace_id, sequence);
CREATE INDEX IF NOT EXISTS outputs_by_hash_sequence ON outputs(transaction_hash, sequence);
CREATE INDEX IF NOT EXISTS outputs_by_app_asset_state_sequence ON outputs(app_id, asset_id, state, sequence);
CREATE INDEX IF NOT EXISTS outputs_by_transaction_hash_output_index ON outputs(transaction_hash, output_index);