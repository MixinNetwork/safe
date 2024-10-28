package signer

import (
	"context"
	"slices"
	"time"

	"github.com/MixinNetwork/multi-party-sig/pkg/party"
)

// TODO put all works query to the custodian module
func (node *Node) DailyWorks(ctx context.Context, now time.Time) []byte {
	day := time.Hour * 24
	end := now.UTC().Truncate(day)
	begin := end.Add(-day)

	members := node.GetPartySlice()
	works, err := node.store.CountDailyWorks(ctx, members, begin, end)
	if err != nil {
		panic(err)
	}
	for i, id := range members {
		if id == node.id && works[i] != 0 {
			panic(works[i])
		}
	}

	return normalizeWorks(works)
}

func (s *SQLite3Store) CountDailyWorks(ctx context.Context, members []party.ID, begin, end time.Time) ([]int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	works := make([]int, len(members))
	for i, id := range members {
		var work int
		sql := "SELECT COUNT(*) FROM session_works WHERE signer_id=? AND created_at>? AND created_at<?"
		row := tx.QueryRowContext(ctx, sql, id, begin, end)
		err = row.Scan(&work)
		if err != nil {
			return nil, err
		}
		works[i] = work
	}

	return works, nil
}

func normalizeWorks(works []int) []byte {
	max := slices.Max(works)
	norms := make([]byte, len(works))
	for i, w := range works {
		norms[i] = byte(255 * w / max)
	}
	return norms
}
