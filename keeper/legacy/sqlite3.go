package legacy

import (
	"database/sql"
	_ "embed"
	"sync"

	"github.com/MixinNetwork/safe/common"
)

//go:embed legacy.sql
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
