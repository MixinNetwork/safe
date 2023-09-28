package ethereum

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/MixinNetwork/safe/apps/ethereum/abi"
	commonAbi "github.com/MixinNetwork/safe/common/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/exp/slices"
)

// create a gnosis safe contract with 2/3 multisig
// with safe guard to do time lock of observer
// with deploy2 to determine exact contract address

func GetOrDeploySafeAccount(rpc, key string, owners []string, threshold int64) error {
	addr := GetSafeAccountAddress(owners, threshold)

	os, thres, err := CheckSafeAccountDeployed(rpc, addr.String())
	if err != nil {
		return err
	}
	if os != nil && thres != nil {
		if thres.Int64() != threshold {
			return fmt.Errorf("Predict safe address %s has invalid threshold %d", addr, thres.Int64())
		}
		if len(os) != len(owners) {
			return fmt.Errorf("Predict safe address %s has invalid owners length %d", addr, len(os))
		}
		for _, o := range os {
			address := o.Hex()
			if !slices.Contains(owners, address) {
				return fmt.Errorf("Predict safe address %s has invalid threshold %s", addr, address)
			}
		}
		return nil
	}

	initializer := getInitializer(owners, threshold)
	nonce := new(big.Int)
	nonce.SetString(predeterminedSaltNonce[2:], 16)

	conn, factoryAbi, err := factoryInit(rpc)
	if err != nil {
		return err
	}
	defer conn.Close()

	signer, err := commonAbi.SignerInit(key)
	if err != nil {
		return err
	}

	_, err = factoryAbi.CreateProxyWithNonce(signer, common.HexToAddress(EthereumSafeL2Address), initializer, nonce)
	return err
}

func CheckSafeAccountDeployed(rpc, address string) ([]common.Address, *big.Int, error) {
	conn, abi, err := safeInit(rpc, address)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	threshold, err := abi.GetThreshold(nil)
	if err != nil {
		if strings.Contains(err.Error(), "no contract code at given address") {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	owners, err := abi.GetOwners(nil)
	if err != nil {
		return nil, nil, err
	}
	return owners, threshold, nil
}

func GetSafeAccountAddress(owners []string, threshold int64) common.Address {
	this, err := hex.DecodeString(EthereumSafeProxyFactoryAddress[2:])
	if err != nil {
		panic(err)
	}

	initializer := getInitializer(owners, threshold)
	nonce := new(big.Int)
	nonce.SetString(predeterminedSaltNonce[2:], 16)
	encodedNonce := packSaltArguments(nonce)
	salt := crypto.Keccak256(initializer)
	salt = append(salt, encodedNonce...)
	salt = crypto.Keccak256(salt)

	code, err := hex.DecodeString(accountContractCode[2:])
	if err != nil {
		panic(err)
	}
	code = append(code, packSafeArguments(EthereumSafeL2Address)...)

	input := []byte{0xff}
	input = append(input, this...)
	input = append(input, math.U256Bytes(new(big.Int).SetBytes(salt))...)
	input = append(input, crypto.Keccak256(code)...)
	return common.BytesToAddress(crypto.Keccak256(input))
}

func DeploySafeGuard(signer *bind.TransactOpts, conn *ethclient.Client, observer string, timelock int64) (*common.Address, error) {
	address, _, _, err := abi.DeploySafeTimelockGuard(signer, conn, common.HexToAddress(observer), new(big.Int).SetInt64(timelock))
	if err != nil {
		return nil, err
	}
	return &address, nil
}

func getInitializer(owners []string, threshold int64) []byte {
	blankAddress := common.HexToAddress(EthereumEmptyAddress)
	handlerAddress := common.HexToAddress(EthereumCompatibilityFallbackHandlerAddress)
	initializer := packSetupArguments(
		owners, threshold, nil, blankAddress, handlerAddress, blankAddress, blankAddress, big.NewInt(0),
	)
	return initializer
}
