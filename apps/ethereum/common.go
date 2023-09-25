package ethereum

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	EthereumEmptyAddress                        = "0x0000000000000000000000000000000000000000"
	EthereumSafeProxyFactoryAddress             = "0xC00abA7FbB0d1e7f02082E346fe1B80EFA16Dc5D"
	EthereumSafeL2Address                       = "0x9eA0fCa659336872d47dF0FbE21575BeE1a56eff"
	EthereumCompatibilityFallbackHandlerAddress = "0x52Bb11433e9C993Cc320B659bdd3F0699AEa678d"

	predeterminedSaltNonce = "0xb1073742015cbcf5a3a4d9d1ae33ecf619439710b89475f92e2abd2117e90f90"
	accountContractCode    = "0x608060405234801561001057600080fd5b506040516101e63803806101e68339818101604052602081101561003357600080fd5b8101908080519060200190929190505050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614156100ca576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260228152602001806101c46022913960400191505060405180910390fd5b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505060ab806101196000396000f3fe608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e0000000000000000000000000000000000000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e60008114156070573d6000fd5b3d6000f3fea264697066735822122003d1488ee65e08fa41e58e888a9865554c535f2c77126a82cb4c0f917f31441364736f6c63430007060033496e76616c69642073696e676c65746f6e20616464726573732070726f7669646564"
)

func packSetupArguments(ownersAddrs []string, threshold int64, data []byte, to, fallbackHandler, paymentToken, paymentReceiver common.Address, payment *big.Int) []byte {
	safeAbi, err := abi.JSON(strings.NewReader(GnosisSafeMetaData.ABI))
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
	addressTy, err := abi.NewType("address", "", nil)
	if err != nil {
		panic(err)
	}

	arguments := abi.Arguments{
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
	uint256Ty, err := abi.NewType("uint256", "", nil)
	if err != nil {
		panic(err)
	}

	arguments := abi.Arguments{
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

func safeInit(rpc, address string) (*ethclient.Client, *GnosisSafe, error) {
	conn, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, nil, err
	}

	abi, err := NewGnosisSafe(common.HexToAddress(address), conn)
	if err != nil {
		return nil, nil, err
	}

	return conn, abi, nil
}

func factoryInit(rpc string) (*ethclient.Client, *ProxyFactory, error) {
	conn, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, nil, err
	}

	abi, err := NewProxyFactory(common.HexToAddress(EthereumSafeProxyFactoryAddress), conn)
	if err != nil {
		return nil, nil, err
	}

	return conn, abi, nil
}
