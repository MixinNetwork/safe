package ethereum

import (
	"math/big"
	"strings"

	"github.com/MixinNetwork/safe/apps/ethereum/abi"
	commonAbi "github.com/MixinNetwork/safe/common/abi"
	gethAbi "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// gnosis safe
// https://github.com/safe-global/safe-core-sdk/blob/main/guides/integrating-the-safe-core-sdk.md
// execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)

type SafeTransaction struct {
	ChainID        int64
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

func CreateTransferTransaction(chainID int64, safeAddress, destination string, value *big.Int, safeTxGas, baseGas, gasPrice *big.Int, gasToken, refundReceiver common.Address, nonce int64) (*SafeTransaction, error) {
	tx := &SafeTransaction{
		ChainID:        chainID,
		SafeAddress:    safeAddress,
		Destination:    common.HexToAddress(destination),
		Value:          value,
		SafeTxGas:      safeTxGas,
		BaseGas:        baseGas,
		GasPrice:       gasPrice,
		GasToken:       gasToken,
		RefundReceiver: refundReceiver,
		Nonce:          new(big.Int).SetInt64(nonce),
	}
	tx.Message = tx.GetTransactionHash()
	return tx, nil
}

func CreateSetGuardTransaction(chainID int64, safeAddress, guardAddress string, safeTxGas, baseGas, gasPrice *big.Int, gasToken, refundReceiver common.Address, nonce int64) (*SafeTransaction, error) {
	tx := &SafeTransaction{
		ChainID:        chainID,
		SafeAddress:    safeAddress,
		Destination:    common.HexToAddress(safeAddress),
		Value:          new(big.Int).SetInt64(0),
		SafeTxGas:      safeTxGas,
		BaseGas:        baseGas,
		GasPrice:       gasPrice,
		GasToken:       gasToken,
		RefundReceiver: refundReceiver,
		Nonce:          new(big.Int).SetInt64(nonce),
	}
	tx.Data = tx.GetEnableGuradData(guardAddress)
	tx.Message = tx.GetTransactionHash()
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

func (tx *SafeTransaction) GetTransactionHash() []byte {
	safeTxHash := crypto.Keccak256(packSafeTransactionArguments(tx))
	domain := packDomainSeparatorArguments(tx.ChainID, tx.SafeAddress)
	domainSeparator := crypto.Keccak256(domain)
	var txData []byte
	txData = append(txData, []byte{0x19, 0x01}...)
	txData = append(txData, domainSeparator...)
	txData = append(txData, safeTxHash...)
	hash := crypto.Keccak256(txData)
	return hash
}

func (tx *SafeTransaction) GetEnableGuradData(address string) []byte {
	safeAbi, err := gethAbi.JSON(strings.NewReader(abi.GnosisSafeMetaData.ABI))
	if err != nil {
		panic(err)
	}

	args, err := safeAbi.Pack(
		"setGuard",
		common.HexToAddress(address),
	)
	if err != nil {
		panic(err)
	}
	return args
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
