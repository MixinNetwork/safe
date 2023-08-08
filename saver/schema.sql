CREATE TABLE IF NOT EXISTS items (
  id          VARCHAR NOT NULL,
  node_id     VARCHAR NOT NULL,
  data        VARCHAR NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  updated_at  TIMESTAMP NOT NULL,
  PRIMARY KEY ('id')
);

CREATE INDEX IF NOT EXISTS items_by_node_created ON items(node_id, created_at);


CREATE TABLE IF NOT EXISTS tokens (
  node_id     VARCHAR NOT NULL,
  public_key  VARCHAR NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  updated_at  TIMESTAMP NOT NULL,
  PRIMARY KEY ('node_id')
);

CREATE UNIQUE INDEX IF NOT EXISTS tokens_by_public ON tokens(public_key);
