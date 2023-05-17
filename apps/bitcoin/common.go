package bitcoin

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/domains/bitcoin"
	"github.com/MixinNetwork/mixin/domains/litecoin"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/shopspring/decimal"
)

const (
	ChainBitcoin  = 1
	ChainLitecoin = 5

	ValuePrecision = 8
	ValueSatoshi   = 100000000
	ValueDust      = 1000

	TimeLockMinimum = time.Hour * 1
	TimeLockMaximum = time.Hour * 24 * 365

	ScriptPubKeyTypeWitnessKeyHash    = "witness_v0_keyhash"
	ScriptPubKeyTypeWitnessScriptHash = "witness_v0_scripthash"

	InputTypeP2WPKHAccoutant             = 1
	InputTypeP2WSHMultisigHolderSigner   = 2
	InputTypeP2WSHMultisigObserverSigner = 3

	MaxTransactionSequence = 0xffffffff
	MaxStandardTxWeight    = 300000

	TransactionConfirmations = 1
)

func ParseSatoshi(amount string) int64 {
	amt, err := decimal.NewFromString(amount)
	if err != nil {
		panic(amount)
	}
	amt = amt.Mul(decimal.New(1, ValuePrecision))
	if !amt.IsInteger() {
		panic(amount)
	}
	if !amt.BigInt().IsInt64() {
		panic(amount)
	}
	return amt.BigInt().Int64()
}

func ParseAddress(addr string, chain byte) (string, error) {
	switch chain {
	case ChainBitcoin:
		err := bitcoin.VerifyAddress(addr)
		if err != nil {
			return "", fmt.Errorf("bitcoin.VerifyAddress(%s) => %v", addr, err)
		}
	case ChainLitecoin:
		err := litecoin.VerifyAddress(addr)
		if err != nil {
			return "", fmt.Errorf("litecoin.VerifyAddress(%s) => %v", addr, err)
		}
	default:
		return "", fmt.Errorf("ParseAddress(%s, %d)", addr, chain)
	}
	bda, err := btcutil.DecodeAddress(addr, netConfig(chain))
	if err != nil {
		return "", fmt.Errorf("btcutil.DecodeAddress(%s, %d) => %v", addr, chain, err)
	}
	_, err = txscript.PayToAddrScript(bda)
	if err != nil {
		return "", fmt.Errorf("txscript.PayToAddrScript(%s, %d) => %v", addr, chain, err)
	}
	return addr, nil
}

func ParseSequence(lock time.Duration) int64 {
	if lock < TimeLockMinimum || lock > TimeLockMaximum {
		panic(lock.String())
	}
	return wire.SequenceLockTimeIsSeconds | (int64(lock.Seconds()) >> wire.SequenceLockTimeGranularity)
}

func CheckFinalization(num uint64, coinbase bool) bool {
	if num >= uint64(chaincfg.MainNetParams.CoinbaseMaturity) {
		return true
	}
	return !coinbase && num >= TransactionConfirmations
}

func HashMessageForSignature(msg string) []byte {
	var buf bytes.Buffer
	_ = wire.WriteVarString(&buf, 0, "Bitcoin Signed Message:\n")
	_ = wire.WriteVarString(&buf, 0, msg)
	return chainhash.DoubleHashB(buf.Bytes())
}

func IsInsufficientInputError(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "insufficient ")
}

func buildInsufficientInputError(cat string, inSatoshi, outSatoshi int64) error {
	return fmt.Errorf("insufficient %s %d %d", cat, inSatoshi, outSatoshi)
}

func writeBytes(enc *common.Encoder, b []byte) {
	enc.WriteInt(len(b))
	enc.Write(b)
}
