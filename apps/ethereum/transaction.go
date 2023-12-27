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
	ga "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

// gnosis safe
// https://github.com/safe-global/safe-core-sdk/blob/main/guides/integrating-the-safe-core-sdk.md
// execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)

type SafeTransaction struct {
	TxHash         string
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
	TokenAddress string
	Destination  string
	Amount       *big.Int
}

func CreateTransactionFromOutputs(ctx context.Context, typ int, chainId int64, id, safeAddress string, outputs []*Output, nonce *big.Int) (*SafeTransaction, error) {
	switch {
	case len(outputs) > 1 && typ == TypeMultiSendTx:
		return CreateMultiSendTransaction(ctx, chainId, id, safeAddress, outputs, nonce)
	case len(outputs) == 1:
		o := outputs[0]
		return CreateTransaction(ctx, typ, chainId, id, safeAddress, o.Destination, o.TokenAddress, o.Amount.String(), nonce)
	default:
		return nil, fmt.Errorf("invalid outputs to create safe transaction")
	}
}

func CreateTransaction(ctx context.Context, typ int, chainID int64, id, safeAddress, destination, tokenAddress, amount string, nonce *big.Int) (*SafeTransaction, error) {
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
	case TypeERC20Tx:
		norm := NormalizeAddress(tokenAddress)
		if norm == "" {
			return nil, fmt.Errorf("invalid ERC20 address %s for TypeERC20Tx", tokenAddress)
		}
		tx.Destination = common.HexToAddress(norm)
		tx.Value = big.NewInt(0)
		tx.Data = GetERC20TxData(destination, value)
	default:
		return nil, fmt.Errorf("invalid safe transaction type: %d", typ)
	}
	tx.Message = tx.GetTransactionHash()
	tx.TxHash = tx.Hash(id)
	return tx, nil
}

func CreateMultiSendTransaction(ctx context.Context, chainID int64, id, safeAddress string, outputs []*Output, nonce *big.Int) (*SafeTransaction, error) {
	if nonce == nil {
		return nil, fmt.Errorf("Invalid ethereum transaction nonce")
	}
	tx := &SafeTransaction{
		ChainID:        chainID,
		SafeAddress:    safeAddress,
		Destination:    common.HexToAddress(EthereumMultiSendAddress),
		Value:          big.NewInt(0),
		Data:           GetMultiSendData(outputs),
		Operation:      operationTypeDelegateCall,
		SafeTxGas:      big.NewInt(0),
		BaseGas:        big.NewInt(0),
		GasPrice:       big.NewInt(0),
		GasToken:       common.HexToAddress(EthereumEmptyAddress),
		RefundReceiver: common.HexToAddress(EthereumEmptyAddress),
		Nonce:          nonce,
		Signatures:     make([][]byte, 3),
	}
	tx.Message = tx.GetTransactionHash()
	tx.TxHash = tx.Hash(id)
	return tx, nil
}

func CreateEnableGuardTransaction(ctx context.Context, chainID int64, id, safeAddress, observerAddress string, timelock *big.Int) (*SafeTransaction, error) {
	if timelock == nil {
		return nil, fmt.Errorf("invalid timelock: %d", timelock)
	}
	zero := big.NewInt(0)
	tx := &SafeTransaction{
		ChainID:        chainID,
		SafeAddress:    safeAddress,
		Destination:    common.HexToAddress(EthereumMultiSendAddress),
		Value:          zero,
		Operation:      operationTypeDelegateCall,
		SafeTxGas:      zero,
		BaseGas:        zero,
		GasPrice:       zero,
		GasToken:       common.HexToAddress(EthereumEmptyAddress),
		RefundReceiver: common.HexToAddress(EthereumEmptyAddress),
		Nonce:          zero,
		Signatures:     make([][]byte, 3),
	}
	tx.Data = tx.GetEnableGuradData(observerAddress, timelock)
	tx.Message = tx.GetTransactionHash()
	tx.TxHash = tx.Hash(id)
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
	enc.WriteUint64(uint64(tx.Operation))
	bitcoin.WriteBytes(enc, []byte(tx.TxHash))
	bitcoin.WriteBytes(enc, []byte(tx.SafeAddress))
	bitcoin.WriteBytes(enc, tx.Destination.Bytes())
	bitcoin.WriteBytes(enc, tx.Value.Bytes())
	bitcoin.WriteBytes(enc, tx.Data)
	bitcoin.WriteBytes(enc, tx.Nonce.Bytes())
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
	operation, err := dec.ReadUint64()
	if err != nil {
		return nil, err
	}
	hash, err := dec.ReadBytes()
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
	nonce, err := dec.ReadBytes()
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
		TxHash:         string(hash),
		ChainID:        int64(chainID),
		SafeAddress:    string(safeAddress),
		Destination:    common.BytesToAddress(destination),
		Value:          new(big.Int).SetBytes(valueByte),
		Data:           data,
		Operation:      uint8(operation),
		SafeTxGas:      new(big.Int).SetInt64(0),
		BaseGas:        new(big.Int).SetInt64(0),
		GasPrice:       new(big.Int).SetInt64(0),
		GasToken:       common.HexToAddress(EthereumEmptyAddress),
		RefundReceiver: common.HexToAddress(EthereumEmptyAddress),
		Nonce:          new(big.Int).SetBytes(nonce),
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
		tx.Operation,
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

func (tx *SafeTransaction) ExecTransaction(ctx context.Context, rpc, key string) (string, error) {
	signer, err := signerInit(key, tx.ChainID)
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

	t, err := safeAbi.ExecTransaction(
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
	_, err = bind.WaitMined(ctx, conn, t)
	if err != nil {
		return "", err
	}
	return t.Hash().Hex(), nil
}

func (tx *SafeTransaction) ExtractOutputs() []*Output {
	outputs, err := tx.ParseMultiSendData()
	if err == nil {
		return outputs
	}
	switch {
	case len(tx.Data) == 0:
		return []*Output{{
			Destination: tx.Destination.Hex(),
			Amount:      tx.Value,
		}}
	default:
		method := hex.EncodeToString(tx.Data[0:4])
		if method != "a9059cbb" || len(tx.Data) != 68 {
			panic("invalid safe transaction data")
		}
		destination := tx.Data[4:36]
		value := tx.Data[36:68]
		return []*Output{{
			TokenAddress: tx.Destination.Hex(),
			Destination:  common.BytesToAddress(destination).Hex(),
			Amount:       new(big.Int).SetBytes(value),
		}}
	}
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

func (tx *SafeTransaction) ParseMultiSendData() ([]*Output, error) {
	if tx.Operation != operationTypeDelegateCall {
		return nil, fmt.Errorf("invalid tx operation: %d", tx.Operation)
	}
	abi, err := ga.JSON(strings.NewReader(abi.MultiSendMetaData.ABI))
	if err != nil {
		panic(err)
	}
	args, err := abi.Methods["multiSend"].Inputs.Unpack(
		tx.Data[4:],
	)
	if err != nil || len(args) != 1 {
		return nil, err
	}
	multiSendData := args[0].([]byte)

	var os []*Output
	offset := 0
	for {
		if offset == len(multiSendData) {
			break
		}

		offset += 1
		bytesTo := multiSendData[offset : offset+20]
		to := common.BytesToAddress(bytesTo)
		offset += 20
		bytesAmount := multiSendData[offset : offset+32]
		amount := new(big.Int).SetBytes(bytesAmount)
		offset += 32
		bytesLen := multiSendData[offset : offset+32]
		dataLen := new(big.Int).SetBytes(bytesLen).Uint64()
		offset += 32

		o := &Output{
			Destination: to.Hex(),
			Amount:      amount,
		}
		switch {
		case dataLen == 0:
		case int(dataLen) == 68:
			metaData := multiSendData[offset : offset+int(dataLen)]
			strData := hex.EncodeToString(metaData)
			method := strData[0:8]
			switch method {
			case "59335aa2": // guardSafe
				offset += int(dataLen)
			case "a9059cbb": // erc20 transfer
				bytesTo := metaData[4:36]
				bytesAmount := metaData[36:68]
				o.TokenAddress = o.Destination
				o.Destination = common.BytesToAddress(bytesTo).Hex()
				o.Amount = new(big.Int).SetBytes(bytesAmount)
				offset += int(dataLen)
			default:
				return nil, fmt.Errorf("invalid meta tx data: %x", metaData)
			}
		default:
			offset += int(dataLen)
		}
		os = append(os, o)
	}
	return os, nil
}

func (tx *SafeTransaction) GetEnableGuradData(observer string, timelock *big.Int) []byte {
	safeAbi, err := ga.JSON(strings.NewReader(abi.GnosisSafeMetaData.ABI))
	if err != nil {
		panic(err)
	}
	args, err := safeAbi.Pack(
		"setGuard",
		common.HexToAddress(EthereumSafeGuardAddress),
	)
	if err != nil {
		panic(err)
	}
	setGuardData := GetMetaTxData(common.HexToAddress(tx.SafeAddress), big.NewInt(0), args)

	guardAbi, err := ga.JSON(strings.NewReader(abi.MixinSafeGuardMetaData.ABI))
	if err != nil {
		panic(err)
	}
	args, err = guardAbi.Pack(
		"guardSafe",
		common.HexToAddress(observer),
		timelock,
	)
	if err != nil {
		panic(err)
	}
	guardSafeData := GetMetaTxData(common.HexToAddress(EthereumSafeGuardAddress), big.NewInt(0), args)

	data := []byte{}
	data = append(data, setGuardData...)
	data = append(data, guardSafeData...)
	abi, err := ga.JSON(strings.NewReader(abi.MultiSendMetaData.ABI))
	if err != nil {
		panic(err)
	}
	args, err = abi.Pack(
		"multiSend",
		data,
	)
	if err != nil {
		panic(err)
	}
	return args
}

func GetERC20TxData(receiver string, amount *big.Int) []byte {
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

func GetMultiSendData(outputs []*Output) []byte {
	metaTxsData := []byte{}
	for _, o := range outputs {
		destination, amount, data := o.Destination, o.Amount, []byte{}
		norm := NormalizeAddress(o.TokenAddress)
		if norm != "" {
			destination = norm
			amount = big.NewInt(0)
			data = GetERC20TxData(o.Destination, o.Amount)
		}
		data = GetMetaTxData(common.HexToAddress(destination), amount, data)
		metaTxsData = append(metaTxsData, data...)
	}

	abi, err := ga.JSON(strings.NewReader(abi.MultiSendMetaData.ABI))
	if err != nil {
		panic(err)
	}
	args, err := abi.Pack(
		"multiSend",
		metaTxsData,
	)
	if err != nil {
		panic(err)
	}
	return args
}

func GetMetaTxData(to common.Address, amount *big.Int, data []byte) []byte {
	dataLen := big.NewInt(int64(len(data)))

	var meta []byte
	meta = append(meta, byte(operationTypeCall))
	meta = append(meta, to.Bytes()...)
	meta = append(meta, common.LeftPadBytes(amount.Bytes(), 32)...)
	meta = append(meta, common.LeftPadBytes(dataLen.Bytes(), 32)...)
	meta = append(meta, data...)
	return meta
}

func ProcessSignature(signature []byte) []byte {
	// Golang returns the recovery ID in the last byte instead of v
	// v = 27 + rid
	signature[64] += 27
	// Sign with prefix
	signature[64] += 4
	return signature
}

func CheckTransactionPartiallySignedBy(raw, public string) bool {
	b, _ := hex.DecodeString(raw)
	st, _ := UnmarshalSafeTransaction(b)

	for _, sig := range st.Signatures {
		if sig != nil {
			err := VerifyMessageSignature(public, st.Message, sig)
			if err == nil {
				return true
			}
		}
	}
	return false
}
