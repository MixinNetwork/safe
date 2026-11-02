package cmd

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestAccountantFundingAcceptsFeeBelowChangeDust(t *testing.T) {
	for _, rate := range []int64{1, 20} {
		t.Run(fmt.Sprint(rate), func(t *testing.T) {
			root := t.TempDir()
			configuration := fmt.Sprintf("[dev]\nnetwork = 'local'\n[keeper.mtg]\n[observer]\nstore-dir = %q\n", root)
			path := root + "/config.toml"
			require.NoError(t, os.WriteFile(path, []byte(configuration), 0600))
			flags := flag.NewFlagSet("accountants", flag.ContinueOnError)
			flags.Int("chain", 1, "")
			flags.Int64("satoshi", 100_000, "")
			flags.Int64("count", 1, "")
			flags.Int64("fee", rate, "")
			flags.String("key", strings.Repeat("01", 32), "")
			flags.String("input", strings.Repeat("01", 32)+":0", "")
			flags.String("config", path, "")

			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			previous := os.Stdout
			os.Stdout = writer
			t.Cleanup(func() { os.Stdout = previous; reader.Close(); writer.Close() })
			err = ObserverFillAccountants(cli.NewContext(cli.NewApp(), flags, nil))
			os.Stdout = previous
			require.NoError(t, writer.Close())
			require.NoError(t, err)
			output, err := io.ReadAll(reader)
			require.NoError(t, err)
			raw, err := hex.DecodeString(strings.TrimSpace(string(output)))
			require.NoError(t, err)
			tx, err := btcutil.NewTxFromBytes(raw)
			require.NoError(t, err)
			require.Len(t, tx.MsgTx().TxOut, 1)
			require.Equal(t, rate*144, 100_000-tx.MsgTx().TxOut[0].Value)
			require.Len(t, tx.MsgTx().TxIn[0].Witness, 2)
			private, err := parseBitcoinPrivateKey(strings.Repeat("01", 32))
			require.NoError(t, err)
			previousAddress, err := address.NewAddressWitnessPubKeyHash(address.Hash160(private.PubKey().SerializeCompressed()), bitcoin.NetConfig(bitcoin.ChainBitcoin))
			require.NoError(t, err)
			previousScript, err := txscript.PayToAddrScript(previousAddress)
			require.NoError(t, err)
			fetcher := txscript.NewCannedPrevOutputFetcher(previousScript, 100_000)
			hashes := txscript.NewTxSigHashes(tx.MsgTx(), fetcher)
			engine, err := txscript.NewEngine(previousScript, tx.MsgTx(), 0, txscript.StandardVerifyFlags, nil, hashes, 100_000, fetcher)
			require.NoError(t, err)
			require.NoError(t, engine.Execute(), "funding transaction must have a valid witness signature")
		})
	}
}

func TestObserverKeyGenerationPreservesFileOnInvalidArguments(t *testing.T) {
	for _, which := range []string{"offset", "count", "seed"} {
		t.Run(which, func(t *testing.T) {
			path := t.TempDir() + "/keys"
			require.NoError(t, os.WriteFile(path+".pub", []byte("existing keys"), 0o600))
			flags := flag.NewFlagSet("keys", flag.ContinueOnError)
			flags.Int("chain", 1, "")
			flags.Uint("offset", 1, "")
			flags.Uint("count", 1, "")
			flags.String("seed", strings.Repeat("01", 32), "")
			flags.String("list", path, "")
			value := "0"
			if which == "seed" {
				value = "invalid"
			}
			require.NoError(t, flags.Set(which, value))
			err := GenerateObserverKeys(cli.NewContext(cli.NewApp(), flags, nil))
			require.Error(t, err)
			content, err := os.ReadFile(path + ".pub")
			require.NoError(t, err)
			require.Equal(t, "existing keys", string(content))
		})
	}
}

func TestAccountantRejectsInvalidInputBeforeOpeningStore(t *testing.T) {
	for _, which := range []string{"chain", "index", "input", "fee", "count"} {
		t.Run(which, func(t *testing.T) {
			flags := flag.NewFlagSet("accountants", flag.ContinueOnError)
			flags.Int("chain", 1, "")
			flags.Int64("satoshi", 100_000, "")
			flags.Int64("count", 1, "")
			flags.Int64("fee", 1, "")
			flags.String("key", strings.Repeat("01", 32), "")
			flags.String("input", strings.Repeat("01", 32)+":0", "")
			flags.String("config", "missing.toml", "")
			switch which {
			case "chain":
				require.NoError(t, flags.Set("chain", "257"))
			case "index":
				require.NoError(t, flags.Set("input", strings.Repeat("01", 32)+":4294967296"))
			case "input":
				require.NoError(t, flags.Set("input", "missing separator"))
			case "fee":
				require.NoError(t, flags.Set("fee", "9223372036854775807"))
			case "count":
				require.NoError(t, flags.Set("count", "9223372036854775807"))
			}
			err := ObserverFillAccountants(cli.NewContext(cli.NewApp(), flags, nil))
			require.Error(t, err)
			require.NotContains(t, err.Error(), "missing.toml")
		})
	}
}

func TestObserverKeyImportReturnsScannerError(t *testing.T) {
	path := t.TempDir() + "/keys.pub"
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("x", 100_000)), 0o600))
	_, err := scanKeyList(path, 1)
	require.ErrorContains(t, err, "token too long")
}
