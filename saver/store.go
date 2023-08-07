package saver

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"sync"
	"time"

	"github.com/MixinNetwork/safe/common"
)

//go:embed schema.sql
var SCHEMA string

type SQLite3Store struct {
	db    *sql.DB
	mutex *sync.Mutex
}

func OpenSQLite3Store(path string) (*SQLite3Store, error) {
	db, err := common.OpenSQLite3Store(path, SCHEMA)
	if err != nil {
		return nil, err
	}
	return &SQLite3Store{
		db:    db,
		mutex: new(sync.Mutex),
	}, nil
}

func (s *SQLite3Store) Close() error {
	return s.db.Close()
}

func (s *SQLite3Store) WriteItemIfNotExist(ctx context.Context, id, data string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var old string
	timestamp := time.Now().UTC()
	row := s.db.QueryRowContext(ctx, "SELECT data FROM items WHERE id=?", id)
	err = row.Scan(&old)
	if err == sql.ErrNoRows {
		err = s.execOne(ctx, tx, "INSERT INTO items (id, data, created_at, updated_at) VALUES (?, ?, ?, ?)",
			id, data, timestamp, timestamp)
		if err != nil {
			return fmt.Errorf("SQLite3Store INSERT items %v", err)
		}
	} else if err != nil {
		return err
	} else if data != old {
		panic(data)
	}

	err = s.execOne(ctx, tx, "UPDATE items SET updated_at=? WHERE id=? AND data=? AND updated_at<?",
		timestamp, id, data, timestamp)
	if err != nil {
		return fmt.Errorf("SQLite3Store UPDATE items %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) execOne(ctx context.Context, tx *sql.Tx, sql string, params ...any) error {
	res, err := tx.ExecContext(ctx, sql, params...)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != 1 {
		return fmt.Errorf("SQLite3Store.execOne(%s) => %d %v", sql, rows, err)
	}
	return nil
}
