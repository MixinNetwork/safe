CREATE TABLE IF NOT EXISTS items (
  id          VARCHAR NOT NULL,
  data        VARCHAR NOT NULL,
  created_at  TIMESTAMP NOT NULL,
  updated_at  TIMESTAMP NOT NULL,
  PRIMARY KEY ('id')
);
