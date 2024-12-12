package store

import (
	"context"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/common"
)

const startProgramId = 16777217

type Program struct {
	ProgramId string
	RequestId string
	Address   string
	CreatedAt time.Time
}

var programCols = []string{"program_id", "request_id", "address", "created_at"}

func programFromRow(row *sql.Row) (*Program, error) {
	var p Program
	err := row.Scan(&p.ProgramId, &p.RequestId, &p.Address, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return &p, err
}

func (p *Program) Id() *big.Int {
	b, ok := new(big.Int).SetString(p.ProgramId, 10)
	if !ok || b.Sign() < 0 {
		panic(p.ProgramId)
	}
	return b
}

func (s *SQLite3Store) GetNextProgramId(ctx context.Context) (*big.Int, error) {
	program, err := s.ReadLatestProgram(ctx)
	if err != nil {
		return nil, err
	}
	if program == nil {
		return big.NewInt(startProgramId), nil
	}
	return program.Id(), nil
}

func (s *SQLite3Store) ReadLatestProgram(ctx context.Context) (*Program, error) {
	query := fmt.Sprintf("SELECT %s FROM programs ORDER BY created_at DESC LIMIT 1", strings.Join(programCols, ","))
	row := s.db.QueryRowContext(ctx, query)

	return programFromRow(row)
}

func (s *SQLite3Store) ReadProgram(ctx context.Context, id *big.Int) (*Program, error) {
	query := fmt.Sprintf("SELECT %s FROM programs WHERE program_id=?", strings.Join(programCols, ","))
	row := s.db.QueryRowContext(ctx, query, id.String())

	return programFromRow(row)
}

func (s *SQLite3Store) ReadProgramByAddress(ctx context.Context, address string) (*Program, error) {
	query := fmt.Sprintf("SELECT %s FROM programs WHERE address=?", strings.Join(programCols, ","))
	row := s.db.QueryRowContext(ctx, query, address)

	return programFromRow(row)
}

func (s *SQLite3Store) WriteProgramWithRequest(ctx context.Context, req *Request, address string) error {
	id, err := s.GetNextProgramId(ctx)
	if err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer common.Rollback(tx)

	existed, err := s.checkExistence(ctx, tx, "SELECT program_id FROM programs WHERE address=?", address)
	if err != nil || existed {
		return err
	}

	vals := []any{id.String(), req.Id, address, time.Now()}
	err = s.execOne(ctx, tx, buildInsertionSQL("programs", programCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT programs %v", err)
	}
	return tx.Commit()
}
