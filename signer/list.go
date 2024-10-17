package signer

import (
	"context"
	"fmt"
	"strings"

	"github.com/MixinNetwork/mixin/logger"
)

func (s *SQLite3Store) ImportBackup(ctx context.Context, bd *SQLite3Store) error {
	logger.Println("Reading data from backup database...")

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
