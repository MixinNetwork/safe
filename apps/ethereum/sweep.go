package ethereum

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const MaximumSweepOutputs = 256

type SweepValidation struct {
	SafeAddress        string
	ChainID            int64
	Nonce              *big.Int
	RequestID          string
	TransactionHash    string
	Balances           map[string]*big.Int
	AllowedDestination string
}

func ValidateSweepTransaction(tx *SafeTransaction, expected SweepValidation) ([]*Output, error) {
	if tx == nil {
		return nil, fmt.Errorf("nil sweep transaction")
	}
	if expected.ChainID <= 0 || tx.ChainID != expected.ChainID {
		return nil, fmt.Errorf("invalid sweep chain id: %d, expected %d", tx.ChainID, expected.ChainID)
	}
	if !ethcommon.IsHexAddress(expected.SafeAddress) {
		return nil, fmt.Errorf("invalid expected safe address: %s", expected.SafeAddress)
	}
	if !ethcommon.IsHexAddress(tx.SafeAddress) {
		return nil, fmt.Errorf("invalid sweep safe address: %s", tx.SafeAddress)
	}
	expectedSafe := ethcommon.HexToAddress(expected.SafeAddress)
	if expectedSafe == (ethcommon.Address{}) || ethcommon.HexToAddress(tx.SafeAddress) != expectedSafe {
		return nil, fmt.Errorf("invalid sweep safe address: %s, expected %s", tx.SafeAddress, expectedSafe.Hex())
	}
	if expected.Nonce == nil || expected.Nonce.Sign() < 0 || !expected.Nonce.IsInt64() || tx.Nonce == nil || tx.Nonce.Cmp(expected.Nonce) != 0 {
		return nil, fmt.Errorf("invalid sweep nonce: %v, expected %v", tx.Nonce, expected.Nonce)
	}
	if tx.Value == nil || tx.SafeTxGas == nil || tx.BaseGas == nil || tx.GasPrice == nil {
		return nil, fmt.Errorf("invalid nil sweep transaction fields")
	}
	if tx.SafeTxGas.Sign() != 0 || tx.BaseGas.Sign() != 0 || tx.GasPrice.Sign() != 0 ||
		tx.GasToken != (ethcommon.Address{}) || tx.RefundReceiver != (ethcommon.Address{}) {
		return nil, fmt.Errorf("invalid sweep gas or refund fields")
	}

	message := tx.GetTransactionHash()
	if len(tx.Message) != len(message) || !bytes.Equal(tx.Message, message) {
		return nil, fmt.Errorf("sweep message does not match transaction fields")
	}
	if expected.RequestID == "" {
		return nil, fmt.Errorf("empty sweep request id")
	}
	expectedHash, err := decodeSweepHash(expected.TransactionHash)
	if err != nil {
		return nil, fmt.Errorf("invalid expected sweep transaction hash: %w", err)
	}
	transactionHash, err := decodeSweepHash(tx.RequestHash)
	if err != nil {
		return nil, fmt.Errorf("invalid sweep transaction hash: %w", err)
	}
	if !bytes.Equal(transactionHash, expectedHash) {
		return nil, fmt.Errorf("unexpected sweep transaction hash: %s", tx.RequestHash)
	}
	requestHash := crypto.Keccak256(append([]byte(expected.RequestID), message...))
	if !bytes.Equal(requestHash, expectedHash) {
		return nil, fmt.Errorf("sweep transaction hash is not bound to request %s", expected.RequestID)
	}

	outputs, err := tx.ExtractOutputs()
	if err != nil {
		return nil, err
	}
	if len(outputs) == 0 || len(outputs) > MaximumSweepOutputs {
		return nil, fmt.Errorf("invalid sweep output count: %d", len(outputs))
	}
	balances, err := normalizeSweepBalances(expected.Balances)
	if err != nil {
		return nil, err
	}
	if len(outputs) != len(balances) {
		return nil, fmt.Errorf("sweep outputs do not match balance count: %d, expected %d", len(outputs), len(balances))
	}

	destination := ethcommon.HexToAddress(outputs[0].Destination)
	if destination == (ethcommon.Address{}) || destination == expectedSafe {
		return nil, fmt.Errorf("invalid sweep destination: %s", outputs[0].Destination)
	}
	if expected.AllowedDestination != "" {
		allowed := ethcommon.HexToAddress(expected.AllowedDestination)
		if allowed == (ethcommon.Address{}) || destination != allowed {
			return nil, fmt.Errorf("unexpected sweep destination: %s, expected %s", destination.Hex(), allowed.Hex())
		}
	}

	seen := make(map[string]bool, len(outputs))
	for _, output := range outputs {
		if output == nil || output.Amount == nil || output.Amount.Sign() <= 0 {
			return nil, fmt.Errorf("invalid sweep output")
		}
		if !ethcommon.IsHexAddress(output.Destination) || ethcommon.HexToAddress(output.Destination) != destination {
			return nil, fmt.Errorf("sweep outputs have different destinations")
		}
		if !ethcommon.IsHexAddress(output.TokenAddress) {
			return nil, fmt.Errorf("invalid sweep token address: %s", output.TokenAddress)
		}
		token := ethcommon.HexToAddress(output.TokenAddress).Hex()
		if seen[token] {
			return nil, fmt.Errorf("duplicate sweep token output: %s", token)
		}
		seen[token] = true
		balance, ok := balances[token]
		if !ok || balance.Cmp(output.Amount) != 0 {
			return nil, fmt.Errorf("sweep amount does not match %s balance: %s", token, output.Amount)
		}
	}
	return outputs, nil
}

func normalizeSweepBalances(balances map[string]*big.Int) (map[string]*big.Int, error) {
	if len(balances) == 0 {
		return nil, fmt.Errorf("empty sweep balances")
	}
	normalized := make(map[string]*big.Int, len(balances))
	for token, balance := range balances {
		if !ethcommon.IsHexAddress(token) {
			return nil, fmt.Errorf("invalid sweep balance token: %s", token)
		}
		if balance == nil || balance.Sign() <= 0 {
			return nil, fmt.Errorf("invalid sweep balance for %s: %v", token, balance)
		}
		token = ethcommon.HexToAddress(token).Hex()
		if _, exists := normalized[token]; exists {
			return nil, fmt.Errorf("duplicate sweep balance token: %s", token)
		}
		normalized[token] = new(big.Int).Set(balance)
	}
	return normalized, nil
}

func decodeSweepHash(hash string) ([]byte, error) {
	hash = strings.TrimPrefix(strings.TrimPrefix(hash, "0x"), "0X")
	if len(hash) != 64 {
		return nil, fmt.Errorf("invalid hash length: %d", len(hash))
	}
	return hex.DecodeString(hash)
}
