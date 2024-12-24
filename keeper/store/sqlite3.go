package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
)

//go:embed schema.sql
var SCHEMA string

//go:embed legacy.sql
var LEGACY_SCHEMA string

type SQLite3Store struct {
	db    *sql.DB
	mutex *sync.Mutex
}

func OpenSQLite3Store(path string, legacy bool) (*SQLite3Store, error) {
	schema := SCHEMA
	if legacy {
		schema = LEGACY_SCHEMA
	}
	db, err := common.OpenSQLite3Store(path, schema)
	if err != nil {
		return nil, err
	}
	return &SQLite3Store{
		db:    db,
		mutex: new(sync.Mutex),
	}, nil
}

func OpenSQLite3ReadOnlyStore(path string) (*SQLite3Store, error) {
	db, err := common.OpenSQLite3ReadOnlyStore(path)
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

func (s *SQLite3Store) execOne(ctx context.Context, tx *sql.Tx, sql string, params ...any) error {
	return s.execMultiple(ctx, tx, 1, sql, params...)
}

func (s *SQLite3Store) execMultiple(ctx context.Context, tx *sql.Tx, num int64, sql string, params ...any) error {
	res, err := tx.ExecContext(ctx, sql, params...)
	logger.Verbosef("SQLite3Store.ExecContext(%s, %v) => %v %v", sql, params, res, err)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil || rows != num {
		return fmt.Errorf("exec(%d, %s) => %d %v", num, sql, rows, err)
	}
	return nil
}

func buildInsertionSQL(table string, cols []string) string {
	vals := strings.Repeat("?, ", len(cols))
	return fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table, strings.Join(cols, ","), vals[:len(vals)-2])
}

func (s *SQLite3Store) checkExistence(ctx context.Context, tx *sql.Tx, sql string, params ...any) (bool, error) {
	rows, err := tx.QueryContext(ctx, sql, params...)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	return rows.Next(), nil
}

func (s *SQLite3Store) ReadProperty(ctx context.Context, k string) (string, error) {
	row := s.db.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", k)
	var value string
	err := row.Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *SQLite3Store) WriteProperty(ctx context.Context, k, v string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	cols := []string{"key", "value", "created_at"}
	err = s.execOne(ctx, tx, buildInsertionSQL("properties", cols), k, v, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("INSERT properties %v", err)
	}
	return tx.Commit()
}

func (s *SQLite3Store) WriteTerminate(ctx context.Context) error {
	k := "node-state-terminate"
	return s.WriteProperty(ctx, k, "1")
}

func (s *SQLite3Store) ReadTerminate(ctx context.Context) (bool, error) {
	k := "node-state-terminate"
	v, err := s.ReadProperty(ctx, k)
	return v == "1", err
}
