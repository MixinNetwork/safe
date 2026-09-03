package mtg

import "context"

const outputsReservedByMigrationKey = "SCHEMA:VERSION:OUTPUTS_RESERVED_BY"

func (s *SQLite3Store) Migrate(ctx context.Context) error {
	return s.migrateOutputsReservedBy(ctx)
}

func (s *SQLite3Store) migrateOutputsReservedBy(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer rollBack(tx)

	applied, err := s.checkExistence(ctx, tx, "SELECT value FROM properties WHERE key=?", outputsReservedByMigrationKey)
	if err != nil || applied {
		return err
	}

	query := "ALTER TABLE outputs ADD COLUMN reserved_by VARCHAR NOT NULL DEFAULT ''"
	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}
	err = s.writeProperty(ctx, tx, outputsReservedByMigrationKey, query)
	if err != nil {
		return err
	}
	return tx.Commit()
}
