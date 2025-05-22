package bitcoin

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/common"
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

	MaxUnspentUtxo = 512

	TimeLockMinimum = time.Hour * 1
	TimeLockMaximum = time.Hour * 24 * 365

	ScriptPubKeyTypeWitnessKeyHash    = "witness_v0_keyhash"
	ScriptPubKeyTypeWitnessScriptHash = "witness_v0_scripthash"
	SigHashType                       = txscript.SigHashAll | txscript.SigHashAnyOneCanPay

	InputTypeP2WPKHAccoutant             = 1
	InputTypeP2WSHMultisigHolderSigner   = 2
	InputTypeP2WSHMultisigObserverSigner = 3

	MaxTransactionSequence = 0xffffffff
	MaxStandardTxWeight    = 300000
)

func ParseSatoshi(amount string) int64 {
	amt := decimal.RequireFromString(amount)
	amt = amt.Mul(decimal.New(1, ValuePrecision))
	if !amt.IsInteger() {
		panic(amount)
	}
	if !amt.BigInt().IsInt64() {
		panic(amount)
	}
	return amt.BigInt().Int64()
}

func ParseAddress(addr string, chain byte) ([]byte, error) {
	switch chain {
	case ChainBitcoin, ChainLitecoin:
	default:
		return nil, fmt.Errorf("ParseAddress(%s, %d)", addr, chain)
	}
	bda, err := btcutil.DecodeAddress(addr, NetConfig(chain))
	if err != nil {
		return nil, fmt.Errorf("btcutil.DecodeAddress(%s, %d) => %v", addr, chain, err)
	}
	if !bda.IsForNet(NetConfig(chain)) {
		return nil, fmt.Errorf("btcutil.IsForNet(%s, %d)", addr, chain)
	}
	script, err := txscript.PayToAddrScript(bda)
	if err != nil {
		return nil, fmt.Errorf("txscript.PayToAddrScript(%s, %d) => %v", addr, chain, err)
	}
	return script, nil
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
	// FIXME check litecoin timelock consensus as this may exceed 0xffff
	lock = lock / blockDuration
	if lock >= 0xffff {
		lock = 0xffff
	}
	return int64(lock)
}

func CheckFeeRange(fvb int64, chain byte) bool {
	switch chain {
	case ChainBitcoin:
		return fvb >= 2 && fvb <= 1000
	case ChainLitecoin:
		return fvb >= 1 && fvb <= 20
	default:
		panic(chain)
	}
}

func CheckFinalization(num uint64, coinbase bool) bool {
	if num >= uint64(chaincfg.MainNetParams.CoinbaseMaturity) {
		return true
	}
	return !coinbase && num >= 1
}

func CheckDerivation(public string, chainCode []byte, maxRange uint32) error {
	for i := uint32(0); i <= maxRange; i++ {
		children := []uint32{i, i, i}
		_, _, err := DeriveBIP32(public, chainCode, children...)
		if err != nil {
			return err
		}
	}
	return nil
}

func DeriveBIP32(public string, chainCode []byte, children ...uint32) (string, string, error) {
	key, err := hex.DecodeString(public)
	if err != nil {
		return "", "", err
	}
	parentFP := []byte{0x00, 0x00, 0x00, 0x00}
	version := []byte{0x04, 0x88, 0xb2, 0x1e}
	extPub := hdkeychain.NewExtendedKey(version, key, chainCode, parentFP, 0, 0, false)
	for _, i := range children {
		extPub, err = extPub.Derive(i)
		if err != nil {
			return "", "", err
		}
		if bytes.Equal(extPub.ChainCode(), chainCode) {
			panic(i)
		}
	}
	pub, err := extPub.ECPubKey()
	if err != nil {
		return "", "", err
	}
	return extPub.String(), hex.EncodeToString(pub.SerializeCompressed()), nil
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

func BuildInsufficientInputError(cat, inSatoshi, outSatoshi string) error {
	return fmt.Errorf("insufficient %s %s %s", cat, inSatoshi, outSatoshi)
}

func WriteBytes(enc *common.Encoder, b []byte) {
	enc.WriteInt(len(b))
	enc.Write(b)
}
