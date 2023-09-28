package ethereum

import (
	"math/big"

	commonAbi "github.com/MixinNetwork/safe/common/abi"
	"github.com/ethereum/go-ethereum/common"
)

// gnosis safe
// https://github.com/safe-global/safe-core-sdk/blob/main/guides/integrating-the-safe-core-sdk.md
// execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)

type SafeTransaction struct {
	SafeAddress    string
	Destination    common.Address
	Value          *big.Int
	Data           []byte
	SafeTxGas      *big.Int
	BaseGas        *big.Int
	GasPrice       *big.Int
	GasToken       common.Address
	RefundReceiver common.Address
	Signatures     []byte
	Nonce          *big.Int
	Message        []byte
}

func CreateTransferTransaction(rpc, safeAddress string, destination string, value *big.Int, data []byte, safeTxGas, baseGas, gasPrice *big.Int, gasToken, refundReceiver common.Address, nonce int64) (*SafeTransaction, error) {
	conn, abi, err := safeInit(rpc, safeAddress)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tx := &SafeTransaction{
		SafeAddress:    safeAddress,
		Destination:    common.HexToAddress(destination),
		Value:          value,
		Data:           data,
		SafeTxGas:      safeTxGas,
		BaseGas:        baseGas,
		GasPrice:       gasPrice,
		GasToken:       gasToken,
		RefundReceiver: refundReceiver,
		Nonce:          new(big.Int).SetInt64(nonce),
	}

	hash, err := abi.GetTransactionHash(
		nil,
		tx.Destination,
		tx.Value,
		tx.Data,
		operationTypeCall,
		tx.SafeTxGas,
		tx.BaseGas,
		tx.GasPrice,
		tx.GasToken,
		tx.RefundReceiver,
		tx.Nonce,
	)
	if err != nil {
		return nil, err
	}
	tx.Message = hash[:]
	return tx, nil
}

func (tx *SafeTransaction) AddSignature(signature []byte) {
	tx.Signatures = append(tx.Signatures, signature...)
}

func (tx *SafeTransaction) ValidTransaction(rpc string) (bool, error) {
	conn, abi, err := safeInit(rpc, tx.SafeAddress)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	isValid, err := abi.ValidTransaction(
		tx.Destination,
		tx.Value,
		tx.Data,
		operationTypeCall,
		tx.SafeTxGas,
		tx.BaseGas,
		tx.GasPrice,
		tx.GasToken,
		tx.RefundReceiver,
		tx.Signatures,
	)
	if err != nil {
		return false, err
	}
	return isValid, nil
}

func (tx *SafeTransaction) ExecTransaction(rpc, key string) (string, error) {
	signer, err := commonAbi.SignerInit(key)
	if err != nil {
		return "", err
	}
	conn, safeAbi, err := safeInit(rpc, tx.SafeAddress)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	txResponse, err := safeAbi.ExecTransaction(
		signer,
		tx.Destination,
		tx.Value,
		tx.Data,
		operationTypeCall,
		tx.SafeTxGas,
		tx.BaseGas,
		tx.GasPrice,
		tx.GasToken,
		tx.RefundReceiver,
		tx.Signatures,
	)
	if err != nil {
		return "", err
	}
	return txResponse.Hash().Hex(), nil
}

func GetNonce(rpc, address string) (int64, error) {
	conn, abi, err := safeInit(rpc, address)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	nonce, err := abi.Nonce(nil)
	if err != nil {
		return 0, err
	}
	return nonce.Int64(), nil
}
