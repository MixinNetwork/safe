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

var startProgramId = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(24), nil)

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
	id := startProgramId
	if program != nil {
		id = program.Id()
	}
	id = big.NewInt(0).Add(id, big.NewInt(1))
	return id, nil
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

	vals := []any{id.String(), req.Id, address, time.Now()}
	err = s.execOne(ctx, tx, buildInsertionSQL("programs", programCols), vals...)
	if err != nil {
		return fmt.Errorf("INSERT programs %v", err)
	}

	err = s.execOne(ctx, tx, "UPDATE requests SET state=?, updated_at=? WHERE request_id=?", common.RequestStateDone, time.Now().UTC(), req.Id)
	if err != nil {
		return fmt.Errorf("UPDATE requests %v", err)
	}
	err = s.writeActionResult(ctx, tx, req.Output.OutputId, nil, "", req.Id)
	if err != nil {
		return err
	}

	return tx.Commit()
}
