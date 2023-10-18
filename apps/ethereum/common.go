package ethereum

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/apps/ethereum/abi"
	ga "github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/shopspring/decimal"
)

const (
	ChainEthereum = 2
	ChainMVM      = 4

	ValuePrecision = 18
	ValueDust      = 100000000000000

	TimeLockMinimum = time.Hour * 1
	TimeLockMaximum = time.Hour * 24 * 365

	EthereumEmptyAddress                        = "0x0000000000000000000000000000000000000000"
	EthereumSafeProxyFactoryAddress             = "0xC00abA7FbB0d1e7f02082E346fe1B80EFA16Dc5D"
	EthereumSafeL2Address                       = "0x9eA0fCa659336872d47dF0FbE21575BeE1a56eff"
	EthereumCompatibilityFallbackHandlerAddress = "0x52Bb11433e9C993Cc320B659bdd3F0699AEa678d"
	EthereumSafeGuardAddress                    = "0x29e29a21B51Bb5B7a3b5F813687514D17140Ba2d"

	predeterminedSaltNonce  = "0xb1073742015cbcf5a3a4d9d1ae33ecf619439710b89475f92e2abd2117e90f90"
	accountContractCode     = "0x608060405234801561001057600080fd5b506040516101e63803806101e68339818101604052602081101561003357600080fd5b8101908080519060200190929190505050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156100ca576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260228152602001806101c46022913960400191505060405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505060ab806101196000396000f3fe608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea264697066735822122003d1488ee65e08fa41e58e888a9865554c535f2c77126a82cb4c0f917f31441364736f6c63430007060033496e76616c69642073696e676c65746f6e20616464726573732070726f7669646564"
	operationTypeCall       = 0
	safeTxTypehash          = "0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8"
	domainSeparatorTypehash = "0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218"
	guardStorageSlot        = "0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8"
)

func HashMessageForSignature(msg string) ([]byte, error) {
	msgB, err := hex.DecodeString(msg)
	if err != nil {
		return nil, err
	}
	hash := crypto.Keccak256Hash([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msgB), msgB)))
	return hash.Bytes(), nil
}

func ParseWei(amount string) *big.Int {
	amt, err := decimal.NewFromString(amount)
	if err != nil {
		panic(amount)
	}
	amt = amt.Mul(decimal.New(1, ValuePrecision))
	if !amt.IsInteger() {
		panic(amount)
	}
	return amt.BigInt()
}

func UnitWei(amount *big.Int) string {
	amt := decimal.NewFromBigInt(amount, 0)
	amt = amt.Div(decimal.New(1, ValuePrecision))
	return amt.String()
}

func ParseSequence(lock time.Duration, chain byte) int64 {
	if lock < TimeLockMinimum || lock > TimeLockMaximum {
		panic(lock.String())
	}
	blockDuration := 12 * time.Second
	switch chain {
	case ChainEthereum:
	case ChainMVM:
		blockDuration = 1 * time.Second
	default:
	}
	// FIXME check litecoin timelock consensus as this may exceed 0xffff
	lock = lock / blockDuration
	if lock >= 0xffff {
		lock = 0xffff
	}
	return int64(lock)
}

func GetEvmChainID(chain int64) int64 {
	switch chain {
	case ChainEthereum:
		return 1
	case ChainMVM:
		return 73927
	default:
		panic(chain)
	}
}

func PrivToAddress(priv string) (*common.Address, error) {
	privateKey, err := crypto.HexToECDSA(priv)
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	addr := crypto.PubkeyToAddress(*publicKeyECDSA)
	return &addr, nil
}

func UnpackSafeTransactionInput(rpc string, tx *RPCTransaction, chain byte) (*SafeTransaction, error) {
	safeAbi, err := ga.JSON(strings.NewReader(abi.GnosisSafeMetaData.ABI))
	if err != nil {
		return nil, err
	}

	input := tx.Input
	if strings.HasPrefix(input, "0x") {
		input = input[2:]
	}
	if !strings.HasPrefix(input, "6a761202") {
		return nil, nil
	}
	raw, err := hex.DecodeString(input[8:])
	if err != nil {
		return nil, err
	}

	method := safeAbi.Methods["execTransaction"]
	v, err := method.Inputs.Unpack(raw)
	if err != nil {
		return nil, err
	}
	n, err := GetNonceAtBlock(rpc, tx.To, new(big.Int).SetUint64(tx.BlockHeight))
	if err != nil {
		return nil, err
	}
	t := &SafeTransaction{
		ChainID:        GetEvmChainID(int64(chain)),
		SafeAddress:    tx.To,
		Destination:    v[0].(common.Address),
		Value:          v[1].(*big.Int),
		Data:           v[2].([]byte),
		Operation:      v[3].(uint8),
		SafeTxGas:      v[4].(*big.Int),
		BaseGas:        v[5].(*big.Int),
		GasPrice:       v[6].(*big.Int),
		GasToken:       v[7].(common.Address),
		RefundReceiver: v[8].(common.Address),
		Nonce:          n,
		Signature:      v[9].([]byte),
	}
	t.Message = t.GetTransactionHash()
	return t, nil
}

func packSetupArguments(ownersAddrs []string, threshold int64, data []byte, to, fallbackHandler, paymentToken, paymentReceiver common.Address, payment *big.Int) []byte {
	safeAbi, err := ga.JSON(strings.NewReader(abi.GnosisSafeMetaData.ABI))
	if err != nil {
		panic(err)
	}

	var owners []common.Address
	for _, a := range ownersAddrs {
		owners = append(owners, common.HexToAddress(a))
	}

	args, err := safeAbi.Pack(
		"setup",
		owners,
		big.NewInt(threshold),
		to,
		data,
		fallbackHandler,
		paymentToken,
		payment,
		paymentReceiver,
	)
	if err != nil {
		panic(err)
	}
	return args
}

func packSafeArguments(address string) []byte {
	addressTy, err := ga.NewType("address", "", nil)
	if err != nil {
		panic(err)
	}

	arguments := ga.Arguments{
		{
			Type: addressTy,
		},
	}

	args, err := arguments.Pack(
		common.HexToAddress(address),
	)
	if err != nil {
		panic(err)
	}
	return args
}

func packSaltArguments(salt *big.Int) []byte {
	uint256Ty, err := ga.NewType("uint256", "", nil)
	if err != nil {
		panic(err)
	}

	arguments := ga.Arguments{
		{
			Type: uint256Ty,
		},
	}

	args, err := arguments.Pack(
		salt,
	)
	if err != nil {
		panic(err)
	}
	return args
}

func packSafeTransactionArguments(tx *SafeTransaction) []byte {
	bytes32Ty, err := ga.NewType("bytes32", "", nil)
	if err != nil {
		panic(err)
	}
	addressTy, err := ga.NewType("address", "", nil)
	if err != nil {
		panic(err)
	}
	uint256Ty, err := ga.NewType("uint256", "", nil)
	if err != nil {
		panic(err)
	}
	arguments := ga.Arguments{
		{
			Type: bytes32Ty,
		},
		{
			Type: addressTy,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: bytes32Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: addressTy,
		},
		{
			Type: addressTy,
		},
		{
			Type: uint256Ty,
		},
	}

	bSafeTxTypehash, err := hex.DecodeString(safeTxTypehash[2:])
	if err != nil {
		panic(err)
	}
	args, err := arguments.Pack(
		toBytes32(bSafeTxTypehash),
		tx.Destination,
		tx.Value,
		toBytes32(crypto.Keccak256(tx.Data)),
		new(big.Int).SetInt64(operationTypeCall),
		tx.SafeTxGas,
		tx.BaseGas,
		tx.GasPrice,
		tx.GasToken,
		tx.RefundReceiver,
		tx.Nonce,
	)
	if err != nil {
		panic(err)
	}
	return args
}

func packDomainSeparatorArguments(chainID int64, safeAddress string) []byte {
	bytes32Ty, err := ga.NewType("bytes32", "", nil)
	if err != nil {
		panic(err)
	}
	addressTy, err := ga.NewType("address", "", nil)
	if err != nil {
		panic(err)
	}
	uint256Ty, err := ga.NewType("uint256", "", nil)
	if err != nil {
		panic(err)
	}
	arguments := ga.Arguments{
		{
			Type: bytes32Ty,
		},
		{
			Type: uint256Ty,
		},
		{
			Type: addressTy,
		},
	}

	bDomainSeparatorTypehash, err := hex.DecodeString(domainSeparatorTypehash[2:])
	if err != nil {
		panic(err)
	}
	args, err := arguments.Pack(
		toBytes32(bDomainSeparatorTypehash),
		new(big.Int).SetInt64(chainID),
		common.HexToAddress(safeAddress),
	)
	if err != nil {
		panic(err)
	}
	return args
}

func safeInit(rpc, address string) (*ethclient.Client, *abi.GnosisSafe, error) {
	conn, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, nil, err
	}

	abi, err := abi.NewGnosisSafe(common.HexToAddress(address), conn)
	if err != nil {
		return nil, nil, err
	}

	return conn, abi, nil
}

func factoryInit(rpc string) (*ethclient.Client, *abi.ProxyFactory, error) {
	conn, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, nil, err
	}

	abi, err := abi.NewProxyFactory(common.HexToAddress(EthereumSafeProxyFactoryAddress), conn)
	if err != nil {
		return nil, nil, err
	}

	return conn, abi, nil
}

func guardInit(rpc string) (*ethclient.Client, *abi.MixinSafeGuard, error) {
	conn, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, nil, err
	}

	abi, err := abi.NewMixinSafeGuard(common.HexToAddress(EthereumSafeGuardAddress), conn)
	if err != nil {
		return nil, nil, err
	}

	return conn, abi, nil
}

func toBytes32(b []byte) [32]byte {
	var b32 [32]byte
	copy(b32[:], b[:32])
	return b32
}
