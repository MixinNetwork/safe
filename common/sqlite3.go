package common

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func OpenSQLite3Store(path, schema string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=rwc&_journal_mode=WAL&cache=private", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(schema)
	if err != nil {
		return nil, err
	}
	return db, db.Ping()
}

func OpenSQLite3ReadOnlyStore(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro", path)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	return db, db.Ping()
}
