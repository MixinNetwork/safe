package computer

import (
	"context"
	"slices"
	"time"
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

func normalizeWorks(works []int) []byte {
	max := slices.Max(works)
	norms := make([]byte, len(works))
	for i, w := range works {
		norms[i] = byte(255 * w / max)
	}
	return norms
}
