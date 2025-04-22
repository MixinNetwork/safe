package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestString(t *testing.T) {
	require := require.New(t)

	id := "187ef443-6122-31cc-af40-dc2b92f0eba0"
	require.Equal(id, UniqueId("a", "b"))
	require.Equal(id, UniqueId("b", "a"))
	require.NotEqual(id, UniqueId("b", "c"))

	require.Len(SplitIds("", ","), 0)
	require.Len(SplitIds("hello", ","), 1)
	require.Len(SplitIds("hello,1", ","), 2)
}
