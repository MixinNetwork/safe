package bitcoin

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/domains/bitcoin"
	"github.com/MixinNetwork/mixin/domains/litecoin"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
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

func ParseSequence(lock time.Duration, chain byte) int64 {
	if lock < TimeLockMinimum || lock > TimeLockMaximum {
		panic(lock.String())
	}
	blockDuration := 10 * time.Minute
	switch chain {
	case ChainBitcoin:
	case ChainLitecoin:
		blockDuration = 150 * time.Second
	default:
	}
	// FIXME check litecoin timelock modifications as this may exceed 0xffff
	return int64(lock / blockDuration)
}

func CheckFinalization(num uint64, coinbase bool) bool {
	if num >= uint64(chaincfg.MainNetParams.CoinbaseMaturity) {
		return true
	}
	return !coinbase && num >= TransactionConfirmations
}

func CheckDerivation(public string, chainCode []byte, maxRange uint32) error {
	for i := uint32(0); i <= maxRange; i++ {
		children := []uint32{i, i, i}
		_, err := DeriveBIP32(public, chainCode, children...)
		if err != nil {
			return err
		}
	}
	return nil
}

func DeriveBIP32(public string, chainCode []byte, children ...uint32) (string, error) {
	key, err := hex.DecodeString(public)
	if err != nil {
		return "", err
	}
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	version := []byte{0x04, 0x88, 0xb2, 0x1e}
	extPub := hdkeychain.NewExtendedKey(version, key, chainCode, parentFP, 0, 0, false)
	for _, i := range children {
		extPub, err = extPub.Derive(i)
		if err != nil {
			return "", err
		}
		if bytes.Equal(extPub.ChainCode(), chainCode) {
			panic(i)
		}
	}
	pub, err := extPub.ECPubKey()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub.SerializeCompressed()), nil
}

func HashMessageForSignature(msg string, chain byte) []byte {
	var buf bytes.Buffer
	prefix := "Bitcoin Signed Message:\n"
	switch chain {
	case ChainBitcoin:
	case ChainLitecoin:
		prefix = "Litecoin Signed Message:\n"
	default:
		panic(chain)
	}
	_ = wire.WriteVarString(&buf, 0, prefix)
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
