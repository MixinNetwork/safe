package bitcoin

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/domains/bitcoin"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/shopspring/decimal"
)

const (
	ValuePrecision = 8
	ValueSatoshi   = 100000000

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

func ParseAddress(addr string) (string, error) {
	err := bitcoin.VerifyAddress(addr)
	if err != nil {
		return "", err
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

func IsInsufficientFeeError(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "insufficient fee")
}

func buildInsufficientFeeError(feeSatoshi, feeConsumed int64) error {
	return fmt.Errorf("insufficient fee %d %d", feeSatoshi, feeConsumed)
}

func writeBytes(enc *common.Encoder, b []byte) {
	enc.WriteInt(len(b))
	enc.Write(b)
}
