package ethereum

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	mixinCommon "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/safe/apps"
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
	Operation      uint8
	SafeTxGas      *big.Int
	BaseGas        *big.Int
	GasPrice       *big.Int
	GasToken       common.Address
	RefundReceiver common.Address
	Nonce          *big.Int
	Message        []byte
	Signatures     [][]byte
}

type Output struct {
	Destination string
	Wei         int64
	Nonce       int64
}

func CreateTransaction(ctx context.Context, enableGuardTx bool, rpc string, chainID int64, safeAddress, destination string, value int64, nonce *big.Int) (*SafeTransaction, error) {
	tx := &SafeTransaction{
		ChainID:        chainID,
		SafeAddress:    safeAddress,
		Destination:    common.HexToAddress(destination),
		Value:          new(big.Int).SetInt64(value),
		Operation:      operationTypeCall,
		SafeTxGas:      new(big.Int).SetInt64(0),
		BaseGas:        new(big.Int).SetInt64(0),
		GasPrice:       new(big.Int).SetInt64(0),
		GasToken:       common.HexToAddress(EthereumEmptyAddress),
		RefundReceiver: common.HexToAddress(EthereumEmptyAddress),
		Nonce:          nonce,
		Signatures:     make([][]byte, 3),
	}
	if tx.Nonce == nil && rpc != "" {
		conn, safeAbi, err := safeInit(rpc, safeAddress)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		n, err := safeAbi.Nonce(nil)
		if err != nil {
			return nil, err
		}
		tx.Nonce = n
	}
	if tx.Nonce == nil {
		return nil, fmt.Errorf("Invalid ethereum transaction nonce")
	}
	if enableGuardTx {
		tx.Data = tx.GetEnableGuradData(EthereumSafeGuardAddress)
	}
	tx.Message = tx.GetTransactionHash()
	return tx, nil
}

func (tx *SafeTransaction) Hash(id string) string {
	var txData []byte
	txData = append(txData, []byte(id)...)
	txData = append(txData, tx.Message...)
	hash := crypto.Keccak256(txData)
	return hex.EncodeToString(hash)
}

func (tx *SafeTransaction) Marshal() []byte {
	enc := mixinCommon.NewEncoder()
	enc.WriteUint64(uint64(tx.ChainID))
	apps.WriteBytes(enc, []byte(tx.SafeAddress))
	apps.WriteBytes(enc, tx.Destination.Bytes())
	apps.WriteBytes(enc, []byte(UnitWei(tx.Value)))
	apps.WriteBytes(enc, tx.Data)
	enc.WriteUint64(uint64(tx.Nonce.Uint64()))
	apps.WriteBytes(enc, tx.Message)

	var signatures []string
	for _, sig := range tx.Signatures {
		signatures = append(signatures, hex.EncodeToString(sig))
	}
	sigs := strings.Join(signatures, ",")
	apps.WriteBytes(enc, []byte(sigs))
	return enc.Bytes()
}

func UnmarshalSafeTransaction(b []byte) (*SafeTransaction, error) {
	dec := mixinCommon.NewDecoder(b)
	chainID, err := dec.ReadUint64()
	if err != nil {
		return nil, err
	}
	safeAddress, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	destination, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	valueByte, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	data, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	nonce, err := dec.ReadUint64()
	if err != nil {
		return nil, err
	}
	msg, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	signature, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	sigsStr := strings.Split(string(signature), ",")

	signatures := make([][]byte, 3)
	for i, s := range sigsStr {
		if s == "" {
			continue
		}
		sig, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		signatures[i] = sig
	}

	return &SafeTransaction{
		ChainID:        int64(chainID),
		SafeAddress:    string(safeAddress),
		Destination:    common.BytesToAddress(destination),
		Value:          new(big.Int).SetInt64(ParseWei(string(valueByte))),
		Data:           data,
		Operation:      operationTypeCall,
		SafeTxGas:      new(big.Int).SetInt64(0),
		BaseGas:        new(big.Int).SetInt64(0),
		GasPrice:       new(big.Int).SetInt64(0),
		GasToken:       common.HexToAddress(EthereumEmptyAddress),
		RefundReceiver: common.HexToAddress(EthereumEmptyAddress),
		Nonce:          new(big.Int).SetUint64(nonce),
		Message:        msg,
		Signatures:     signatures,
	}, nil
}

func (tx *SafeTransaction) ValidTransaction(rpc string) (bool, error) {
	conn, abi, err := safeInit(rpc, tx.SafeAddress)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	var signature []byte
	count := 0
	for _, sig := range tx.Signatures {
		if sig == nil {
			continue
		}
		signature = append(signature, sig...)
		count += 1
	}
	if count < 2 {
		return false, fmt.Errorf("SafeTransaction has insufficient signatures")
	}

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
		signature,
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

	var signature []byte
	count := 0
	for _, sig := range tx.Signatures {
		if sig == nil {
			continue
		}
		signature = append(signature, sig...)
		count += 1
	}
	if count < 2 {
		return "", fmt.Errorf("SafeTransaction has insufficient signatures")
	}

	txResponse, err := safeAbi.ExecTransaction(
		signer,
		tx.Destination,
		tx.Value,
		tx.Data,
		tx.Operation,
		tx.SafeTxGas,
		tx.BaseGas,
		tx.GasPrice,
		tx.GasToken,
		tx.RefundReceiver,
		signature,
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
