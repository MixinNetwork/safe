package signer

import (
	"context"
	"encoding/hex"

	"github.com/MixinNetwork/safe/common"
)

// FIXME these code should all be removed

func (s *SQLite3Store) fixKeyShareHEX(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := s.db.QueryContext(ctx, "SELECT public, share FROM keys")
	if err != nil {
		return err
	}
	for rows.Next() {
		var public, share string
		err = rows.Scan(&public, &share)
		if err != nil {
			return err
		}
		b, err := hex.DecodeString(share)
		if err != nil || len(b)*2 != len(share) {
			continue
		}
		share = common.Base91Encode(b)
		err = s.execOne(ctx, tx, "UPDATE keys SET share=? WHERE public=?", share, public)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
