package saver

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"sync"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
)

//go:embed schema.sql
var SCHEMA string

type Item struct {
	Id   string
	Data string
}

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

func (s *SQLite3Store) ReadNodePublicKey(ctx context.Context, nodeId string) (*crypto.Key, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, "SELECT public_key FROM tokens WHERE node_id=?", nodeId)
	var publicKey string
	err = row.Scan(&publicKey)
	if err != nil {
		return nil, err
	}
	key, err := crypto.KeyFromString(publicKey)
	return &key, err
}

func (s *SQLite3Store) WriteNodePublicKey(ctx context.Context, nodeId, publicKey string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	timestamp := time.Now().UTC()
	err = s.execOne(ctx, tx, "INSERT INTO tokens (node_id, public_key, created_at, updated_at) VALUES (?, ?, ?, ?)",
		nodeId, publicKey, timestamp, timestamp)
	if err != nil {
		return fmt.Errorf("SQLite3Store INSERT tokens %v", err)
	}

	return tx.Commit()
}

func (s *SQLite3Store) WriteItemIfNotExist(ctx context.Context, id, nodeId, data string) error {
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
		err = s.execOne(ctx, tx, "INSERT INTO items (id, node_id, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
			id, nodeId, data, timestamp, timestamp)
		if err != nil {
			return fmt.Errorf("SQLite3Store INSERT items %v", err)
		}
	} else if err != nil {
		return err
	} else if data != old {
		panic(data)
	} else {
		err = s.execOne(ctx, tx, "UPDATE items SET updated_at=? WHERE id=? AND node_id=? AND updated_at<?",
			timestamp, id, nodeId, timestamp)
		if err != nil {
			return fmt.Errorf("SQLite3Store UPDATE items %v", err)
		}
	}
	return tx.Commit()
}

func (s *SQLite3Store) ListItemsForNode(ctx context.Context, nodeId string) ([]*Item, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,data FROM items WHERE node_id=? ORDER BY node_id,created_at ASC", nodeId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []*Item
	for rows.Next() {
		var item Item
		err := rows.Scan(&item.Id, &item.Data)
		if err != nil {
			return nil, err
		}
		items = append(items, &item)
	}
	return items, nil
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
