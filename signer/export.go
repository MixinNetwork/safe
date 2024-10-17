package signer

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/MixinNetwork/mixin/logger"
)

type ExportData struct {
	Properties     []*Property
	Sessions       []*Session
	SessionSigners []*SessionSigner
	SessionWorks   []*SessionWork
}

func (s *SQLite3Store) ImportBackup(ctx context.Context, bd *SQLite3Store) error {
	logger.Println("Reading data from database...")

	properties, err := bd.listProperties(ctx)
	if err != nil {
		return err
	}
	sessions, err := bd.listSessions(ctx)
	if err != nil {
		return err
	}
	signers, err := bd.listSessionSigners(ctx)
	if err != nil {
		return err
	}
	works, err := bd.listSessionWorks(ctx)
	if err != nil {
		return err
	}

	return s.Export(ctx, ExportData{
		Properties:     properties,
		Sessions:       sessions,
		SessionSigners: signers,
		SessionWorks:   works,
	})
}

func (s *SQLite3Store) Export(ctx context.Context, data ExportData) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	logger.Println("Exporting properties...")
	err = s.exportProperties(ctx, tx, data.Properties)
	if err != nil {
		return err
	}

	logger.Println("Exporting sessions...")
	err = s.exportSessions(ctx, tx, data.Sessions)
	if err != nil {
		return err
	}

	logger.Println("Exporting session_signers...")
	err = s.exportSessionSigners(ctx, tx, data.SessionSigners)
	if err != nil {
		return err
	}

	logger.Println("Exporting session_works...")
	err = s.exportSessionWorks(ctx, tx, data.SessionWorks)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLite3Store) listProperties(ctx context.Context) ([]*Property, error) {
	var cols = []string{"key", "value", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM properties", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ps []*Property
	for rows.Next() {
		var p Property
		err := rows.Scan(&p.Key, &p.Value, &p.CreatedAt)
		if err != nil {
			return nil, err
		}
		ps = append(ps, &p)
	}
	return ps, nil
}

func (s *SQLite3Store) listSessions(ctx context.Context) ([]*Session, error) {
	cols := "session_id, mixin_hash, mixin_index, operation, curve, public, extra, state, created_at, updated_at, committed_at, prepared_at"
	query := fmt.Sprintf("SELECT %s FROM sessions", cols)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*Session
	for rows.Next() {
		var r Session
		err := rows.Scan(&r.Id, &r.MixinHash, &r.MixinIndex, &r.Operation, &r.Curve, &r.Public, &r.Extra, &r.State, &r.CreatedAt, &r.UpdatedAt, &r.CommittedAt, &r.PreparedAt)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, &r)
	}
	return sessions, nil
}

func (s *SQLite3Store) listSessionSigners(ctx context.Context) ([]*SessionSigner, error) {
	var cols = []string{"session_id", "signer_id", "extra", "created_at", "updated_at"}
	query := fmt.Sprintf("SELECT %s FROM session_signers", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var signers []*SessionSigner
	for rows.Next() {
		var s SessionSigner
		err := rows.Scan(&s.SessionId, &s.SignerId, &s.Extra, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, err
		}
		signers = append(signers, &s)
	}
	return signers, nil
}

func (s *SQLite3Store) listSessionWorks(ctx context.Context) ([]*SessionWork, error) {
	var cols = []string{"session_id", "signer_id", "round", "extra", "created_at"}
	query := fmt.Sprintf("SELECT %s FROM session_works", strings.Join(cols, ","))
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var works []*SessionWork
	for rows.Next() {
		var s SessionWork
		err := rows.Scan(&s.SessionId, &s.SignerId, &s.Round, &s.Extra, &s.CreatedAt)
		if err != nil {
			return nil, err
		}
		works = append(works, &s)
	}
	return works, nil
}

func (s *SQLite3Store) exportProperties(ctx context.Context, tx *sql.Tx, properties []*Property) error {
	for _, p := range properties {
		cols := []string{"key", "value", "created_at"}
		err := s.execOne(ctx, tx, buildInsertionSQL("properties", cols), p.Key, p.Value, p.CreatedAt)
		if err != nil {
			return fmt.Errorf("INSERT properties %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportSessions(ctx context.Context, tx *sql.Tx, sessions []*Session) error {
	for _, session := range sessions {
		cols := []string{"session_id", "mixin_hash", "mixin_index", "operation", "curve", "public",
			"extra", "state", "created_at", "updated_at", "committed_at", "prepared_at"}
		vals := []any{session.Id, session.MixinHash, session.MixinIndex, session.Operation, session.Curve, session.Public,
			session.Extra, session.State, session.CreatedAt, session.UpdatedAt, session.CommittedAt, session.PreparedAt}
		err := s.execOne(ctx, tx, buildInsertionSQL("sessions", cols), vals...)
		if err != nil {
			return fmt.Errorf("SQLite3Store INSERT sessions %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportSessionSigners(ctx context.Context, tx *sql.Tx, signers []*SessionSigner) error {
	for _, signer := range signers {
		cols := []string{"session_id", "signer_id", "extra", "created_at", "updated_at"}
		err := s.execOne(ctx, tx, buildInsertionSQL("session_signers", cols),
			signer.SessionId, signer.SignerId, signer.Extra, signer.CreatedAt, signer.UpdatedAt)
		if err != nil {
			return fmt.Errorf("SQLite3Store INSERT session_signers %v", err)
		}
	}
	return nil
}

func (s *SQLite3Store) exportSessionWorks(ctx context.Context, tx *sql.Tx, works []*SessionWork) error {
	for _, work := range works {
		cols := []string{"session_id", "signer_id", "round", "extra", "created_at"}
		err := s.execOne(ctx, tx, buildInsertionSQL("session_works", cols),
			work.SessionId, work.SignerId, work.Round, work.Extra, work.CreatedAt)
		if err != nil {
			return fmt.Errorf("SQLite3Store INSERT session_works %v", err)
		}
	}
	return nil
}
