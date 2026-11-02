package observer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigurationRejectsInvalidCustomKeyPrice(t *testing.T) {
	require.Error(t, (&Configuration{CustomKeyPriceAmount: "invalid"}).Validate())
	require.Error(t, (&Configuration{CustomKeyPriceAmount: "1"}).Validate())
}
