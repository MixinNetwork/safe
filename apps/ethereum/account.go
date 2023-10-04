package ethereum

import (
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/MixinNetwork/safe/common/abi"
	commonAbi "github.com/MixinNetwork/safe/common/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

// create a gnosis safe contract with 2/3 multisig
// with safe guard to do time lock of observer
// with deploy2 to determine exact contract address

// owners should be in the order of hold, signer and observer
func GetOrDeploySafeAccount(rpc, key string, owners []string, threshold int64, timelock int64, tx *SafeTransaction) (*common.Address, error) {
	addr := GetSafeAccountAddress(owners, threshold)

	isGuarded, isDeployed, err := CheckSafeAccountDeployed(rpc, addr.String())
	if err != nil {
		return nil, err
	}
	if !isDeployed {
		err = DeploySafeAccount(rpc, key, owners, threshold)
		if err != nil {
			return nil, err
		}
	}
	if !isGuarded {
		err = EnableGuard(rpc, key, timelock, owners[2], addr.Hash().String(), tx)
		if err != nil {
			return nil, err
		}
	}
	return &addr, nil
}

func CheckSafeAccountDeployed(rpc, address string) (bool, bool, error) {
	conn, abi, err := safeInit(rpc, address)
	if err != nil {
		return false, false, err
	}
	defer conn.Close()

	bGuardOffet, err := hex.DecodeString(guardStorageSlot[2:])
	if err != nil {
		return false, false, err
	}
	bGuard, err := abi.GetStorageAt(nil, new(big.Int).SetBytes(bGuardOffet), new(big.Int).SetInt64(1))
	if err != nil {
		if strings.Contains(err.Error(), "no contract code at given address") {
			return false, false, nil
		}
		return false, false, err
	}
	guardAddress := common.BytesToAddress(bGuard)
	if guardAddress.Hex() == EthereumEmptyAddress {
		return false, true, nil
	}
	return true, true, nil
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

func DeploySafeAccount(rpc, key string, owners []string, threshold int64) error {
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

func EnableGuard(rpc, key string, timelock int64, observer, safeAddress string, tx *SafeTransaction) error {
	_, err := tx.ExecTransaction(rpc, key)
	if err != nil {
		return err
	}

	conn, guardAbi, err := guardInit(rpc)
	if err != nil {
		return err
	}
	defer conn.Close()
	signer, err := abi.SignerInit(key)
	if err != nil {
		return err
	}
	_, err = guardAbi.GuardSafe(signer, common.HexToAddress(safeAddress), common.HexToAddress(observer), new(big.Int).SetInt64(timelock))
	if err != nil {
		return err
	}
	return nil
}

func getInitializer(owners []string, threshold int64) []byte {
	blankAddress := common.HexToAddress(EthereumEmptyAddress)
	handlerAddress := common.HexToAddress(EthereumCompatibilityFallbackHandlerAddress)
	initializer := packSetupArguments(
		owners, threshold, nil, blankAddress, handlerAddress, blankAddress, blankAddress, big.NewInt(0),
	)
	return initializer
}
