package cmd

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestTransactionProposalRejectsAmountsBeforeExternalLookups(t *testing.T) {
	for _, amount := range []string{"", "NaN", "+Inf", "0", "-1", "0.000000001", "90071992.547409931", "92233720368.54775808", "1e2147483647"} {
		t.Run(amount, func(t *testing.T) {
			flags := flag.NewFlagSet("transaction", flag.ContinueOnError)
			flags.Int("chain", 1, "")
			flags.String("amount", amount, "")
			err := GenerateTestTransactionProposal(cli.NewContext(cli.NewApp(), flags, nil))
			require.ErrorContains(t, err, "invalid bitcoin amount")
		})
	}
}
