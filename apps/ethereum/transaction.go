package ethereum

import (
	"math/big"

	"github.com/MixinNetwork/safe/common/abi"
	gethAbi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// gnosis safe
// https://github.com/safe-global/safe-core-sdk/blob/main/guides/integrating-the-safe-core-sdk.md
// execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)

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

func GetTransactionHash(rpc, address, destination string, value *big.Int, data []byte, safeTxGas, baseGas, gasPrice *big.Int, gasToken, refundReceiver common.Address, _nonce int64) ([]byte, error) {
	conn, abi, err := safeInit(rpc, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	nonce := new(big.Int).SetInt64(_nonce)
	hash, err := abi.GetTransactionHash(
		nil,
		common.HexToAddress(destination),
		value,
		data,
		operationTypeCall,
		safeTxGas,
		baseGas,
		gasPrice,
		gasToken,
		refundReceiver,
		nonce,
	)
	if err != nil {
		return nil, err
	}
	return hash[:], nil
}

func ValidTransaction(rpc, address, destination string, value *big.Int, data []byte, safeTxGas, baseGas, gasPrice *big.Int, gasToken, refundReceiver common.Address, signatures []byte) (bool, error) {
	conn, abi, err := safeInit(rpc, address)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	isValid, err := validTransaction(
		abi,
		common.HexToAddress(destination),
		value,
		signatures,
		data,
		operationTypeCall,
		safeTxGas,
		baseGas,
		gasPrice,
		gasToken,
		refundReceiver,
	)
	if err != nil {
		return false, err
	}
	return isValid, nil
}

func ExecTransaction(rpc, key, address, destination string, value *big.Int, data []byte, safeTxGas, baseGas, gasPrice *big.Int, gasToken, refundReceiver common.Address, signatures []byte) (string, error) {
	signer, err := abi.SignerInit(key)
	if err != nil {
		return "", err
	}
	conn, safeAbi, err := safeInit(rpc, address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	tx, err := safeAbi.ExecTransaction(
		signer,
		common.HexToAddress(destination),
		value,
		data,
		operationTypeCall,
		safeTxGas,
		baseGas,
		gasPrice,
		gasToken,
		refundReceiver,
		signatures,
	)
	if err != nil {
		return "", err
	}
	return tx.Hash().Hex(), nil
}

func validTransaction(safe *GnosisSafe, destination common.Address, value *big.Int, signatures []byte, data []byte, operation uint8, safeTxGas, baseGas, gasPrice *big.Int, gasToken, refundReceiver common.Address) (bool, error) {
	var out []interface{}
	err := safe.GnosisSafeCaller.contract.Call(nil, &out, "execTransaction", destination, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures)

	if err != nil {
		return false, err
	}

	out0 := *gethAbi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err
}
