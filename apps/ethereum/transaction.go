package ethereum

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum/abi"
	ca "github.com/MixinNetwork/safe/common/abi"
	"github.com/ethereum/go-ethereum"
	ga "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/crypto/sha3"
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
	Wei         *big.Int
	Nonce       int64
}

func CreateTransaction(ctx context.Context, typ int, chainID int64, safeAddress, destination, tokenAddress, amount string, nonce *big.Int) (*SafeTransaction, error) {
	if nonce == nil {
		return nil, fmt.Errorf("Invalid ethereum transaction nonce")
	}
	value, ok := new(big.Int).SetString(amount, 10)
	if !ok {
		return nil, fmt.Errorf("Fail to parse value to big.Int")
	}
	tx := &SafeTransaction{
		ChainID:        chainID,
		SafeAddress:    safeAddress,
		Destination:    common.HexToAddress(destination),
		Value:          value,
		Operation:      operationTypeCall,
		SafeTxGas:      big.NewInt(0),
		BaseGas:        big.NewInt(0),
		GasPrice:       big.NewInt(0),
		GasToken:       common.HexToAddress(EthereumEmptyAddress),
		RefundReceiver: common.HexToAddress(EthereumEmptyAddress),
		Nonce:          nonce,
		Signatures:     make([][]byte, 3),
	}
	switch typ {
	case TypeETHTx:
	case TypeInitGuardTx:
		tx.Destination = common.HexToAddress(safeAddress)
		tx.Value = big.NewInt(0)
		tx.Data = tx.GetEnableGuradData(EthereumSafeGuardAddress)
	case TypeERC20Tx:
		norm := NormalizeAddress(tokenAddress)
		if norm == "" {
			return nil, fmt.Errorf("invalid ERC20 address %s for TypeERC20Tx", tokenAddress)
		}
		tx.Destination = common.HexToAddress(norm)
		tx.Value = big.NewInt(0)
		tx.Data = tx.GetERC20TxData(destination, value)
	case TypeMultiSendTx:
		tx.Operation = operationTypeDelegateCall
	default:
		return nil, fmt.Errorf("invalid safe transaction type: %d", typ)
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
	enc := mc.NewEncoder()
	enc.WriteUint64(uint64(tx.ChainID))
	bitcoin.WriteBytes(enc, []byte(tx.SafeAddress))
	bitcoin.WriteBytes(enc, tx.Destination.Bytes())
	bitcoin.WriteBytes(enc, tx.Value.Bytes())
	bitcoin.WriteBytes(enc, tx.Data)
	enc.WriteUint64(uint64(tx.Nonce.Uint64()))
	bitcoin.WriteBytes(enc, tx.Message)

	var signatures []string
	for _, sig := range tx.Signatures {
		signatures = append(signatures, hex.EncodeToString(sig))
	}
	sigs := strings.Join(signatures, ",")
	bitcoin.WriteBytes(enc, []byte(sigs))
	return enc.Bytes()
}

func UnmarshalSafeTransaction(b []byte) (*SafeTransaction, error) {
	dec := mc.NewDecoder(b)
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
		Value:          new(big.Int).SetBytes(valueByte),
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
	signer, err := ca.SignerInit(key)
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
	safeAbi, err := ga.JSON(strings.NewReader(abi.GnosisSafeMetaData.ABI))
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

func (tx *SafeTransaction) GetERC20TxData(receiver string, amount *big.Int) []byte {
	transferFnSignature := []byte("transfer(address,uint256)")
	hash := sha3.NewLegacyKeccak256()
	hash.Write(transferFnSignature)
	methodID := hash.Sum(nil)[:4]

	paddedAddress := common.LeftPadBytes(common.HexToAddress(receiver).Bytes(), 32)
	paddedAmount := common.LeftPadBytes(amount.Bytes(), 32)

	var data []byte
	data = append(data, methodID...)
	data = append(data, paddedAddress...)
	data = append(data, paddedAmount...)
	return data
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

func GetNonceAtBlock(rpc, address string, blockNumber *big.Int) (*big.Int, error) {
	data, err := hex.DecodeString("affed0e0")
	if err != nil {
		return nil, err
	}
	addr := common.HexToAddress(address)
	callMsg := ethereum.CallMsg{
		To:   &addr,
		Data: data,
	}
	conn, err := ethclient.Dial(rpc)
	defer conn.Close()
	if err != nil {
		return nil, err
	}
	response, err := conn.CallContract(context.Background(), callMsg, blockNumber)
	n := new(big.Int).SetBytes(response)
	return new(big.Int).Sub(n, big.NewInt(1)), nil
}
