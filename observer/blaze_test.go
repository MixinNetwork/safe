package observer

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeStatsPreserveColonsInValues(t *testing.T) {
	message := "🧱🧱🧱🧱🧱 Keeper 🧱🧱🧱🧱🧱\n🎆 Latest request: 2026-10-21T12:34:56Z"
	stats := parseNodeStats(base64.RawURLEncoding.EncodeToString([]byte(message)))
	require.Equal(t, "2026-10-21T12:34:56Z", stats.MTG.LatestRequest)
}
