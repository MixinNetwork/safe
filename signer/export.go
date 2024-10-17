package signer

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/MixinNetwork/mixin/logger"
)

type ExportData struct {
	Properties     []*Property
	Sessions       []*Session
	SessionSigners []*SessionSigner
	SessionWorks   []*SessionWork
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
