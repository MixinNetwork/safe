package common

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTilde(t *testing.T) {
	require := require.New(t)

	HOME := os.Getenv("HOME")
	require.Equal(HOME+"/bin/safe", ExpandTilde("~/bin/safe"))
	require.Equal("/tmp/safe", ExpandTilde("/tmp/safe"))
	require.Equal("/home/mixin/safe", ExpandTilde("/home/mixin/safe"))
}
