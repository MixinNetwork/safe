package ethereum

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// create a gnosis safe contract with 2/3 multisig
// with safe guard to do time lock of observer
// with deploy2 to determine exact contract address

type GnosisSafe struct {
	Sequence uint32
	Address  string
	TxHash   string
}

func (gs *GnosisSafe) Marshal() []byte {
	enc := mc.NewEncoder()
	enc.WriteUint32(gs.Sequence)
	bitcoin.WriteBytes(enc, []byte(gs.Address))
	bitcoin.WriteBytes(enc, []byte(gs.TxHash))
	return enc.Bytes()
}

func UnmarshalGnosisSafe(extra []byte) (*GnosisSafe, error) {
	dec := mc.NewDecoder(extra)
	sequence, err := dec.ReadUint32()
	if err != nil {
		return nil, err
	}
	addr, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	hash, err := dec.ReadBytes()
	if err != nil {
		return nil, err
	}
	return &GnosisSafe{
		Sequence: sequence,
		Address:  string(addr),
		TxHash:   string(hash),
	}, nil
}

func BuildGnosisSafe(ctx context.Context, rpc, holder, signer, observer, rid string, lock time.Duration, chain byte) (*GnosisSafe, *SafeTransaction, error) {
	owners, _ := GetSortedSafeOwners(holder, signer, observer)
	safeAddress := GetSafeAccountAddress(owners, 2).Hex()

	if lock < TimeLockMinimum || lock > TimeLockMaximum {
		return nil, nil, fmt.Errorf("time lock out of range %s", lock.String())
	}
	sequence := lock / time.Hour

	chainID := GetEvmChainID(int64(chain))
	t, err := CreateTransaction(ctx, TypeInitGuardTx, chainID, rid, safeAddress, safeAddress, "", "0", new(big.Int).SetUint64(0))
	logger.Printf("CreateTransaction(%d, %d, %s, %s, %s, %d) => %v", TypeInitGuardTx, chainID, rid, safeAddress, safeAddress, 0, err)
	if err != nil {
		return nil, nil, err
	}

	return &GnosisSafe{
		Sequence: uint32(sequence),
		Address:  safeAddress,
		TxHash:   t.TxHash,
	}, t, nil
}

func GetSortedSafeOwners(holder, signer, observer string) ([]string, []string) {
	var owners []string
	var pubs []string
	for _, public := range []string{holder, signer, observer} {
		pub, err := parseEthereumCompressedPublicKey(public)
		if err != nil {
			panic(public)
		}
		owners = append(owners, pub.Hex())
		pubs = append(pubs, public)
	}
	sort.Slice(owners, func(i, j int) bool { return owners[i] < owners[j] })
	return owners, pubs
}

func GetOrDeploySafeAccount(rpc, key string, chainId int64, owners []string, threshold int64, timelock, observerIndex int64, tx *SafeTransaction) (*common.Address, error) {
	addr := GetSafeAccountAddress(owners, threshold)

	isGuarded, isDeployed, err := CheckSafeAccountDeployed(rpc, addr.String())
	if err != nil {
		return nil, err
	}
	if !isDeployed {
		err = DeploySafeAccount(rpc, key, chainId, owners, threshold)
		if err != nil {
			return nil, err
		}
	}
	if !isGuarded {
		err = EnableGuard(rpc, key, chainId, timelock, owners[observerIndex], addr.Hex(), tx)
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

func DeploySafeAccount(rpc, key string, chainId int64, owners []string, threshold int64) error {
	initializer := getInitializer(owners, threshold)
	nonce := new(big.Int)
	nonce.SetString(predeterminedSaltNonce[2:], 16)

	conn, factoryAbi, err := factoryInit(rpc)
	if err != nil {
		return err
	}
	defer conn.Close()

	signer, err := signerInit(key, chainId)
	if err != nil {
		return err
	}

	_, err = factoryAbi.CreateProxyWithNonce(signer, common.HexToAddress(EthereumSafeL2Address), initializer, nonce)
	return err
}

func EnableGuard(rpc, key string, chainId, timelock int64, observer, safeAddress string, tx *SafeTransaction) error {
	_, err := tx.ExecTransaction(rpc, key)
	if err != nil {
		return err
	}

	conn, guardAbi, err := guardInit(rpc)
	if err != nil {
		return err
	}
	defer conn.Close()

	signer, err := signerInit(key, chainId)
	if err != nil {
		return err
	}
	_, err = guardAbi.GuardSafe(signer, common.HexToAddress(safeAddress), common.HexToAddress(observer), new(big.Int).SetInt64(timelock))
	return err
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

func GetTokenBalanceAtBlock(rpc, tokenAddress, address string, blockNumber *big.Int) (*big.Int, error) {
	tokenAddr := common.HexToAddress(tokenAddress)
	addr := common.HexToAddress(address)

	data, err := hex.DecodeString("70a08231")
	if err != nil {
		return nil, err
	}
	data = append(data, common.LeftPadBytes(addr.Bytes(), 32)...)
	callMsg := ethereum.CallMsg{
		To:   &tokenAddr,
		Data: data,
	}
	conn, err := ethclient.Dial(rpc)
	defer conn.Close()
	if err != nil {
		return nil, err
	}
	response, err := conn.CallContract(context.Background(), callMsg, blockNumber)
	n := new(big.Int).SetBytes(response)
	return n, nil
}

func GetSafeLastTxTime(rpc, address string) (time.Time, error) {
	conn, abi, err := guardInit(rpc)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	addr := common.HexToAddress(address)
	timestamp, err := abi.SafeLastTxTime(nil, addr)
	if err != nil {
		return time.Time{}, err
	}
	t := time.Unix(timestamp.Int64(), 0)
	return t, nil
}

func VerifyHolderKey(public string) error {
	_, err := parseEthereumCompressedPublicKey(public)
	return err
}

func VerifyMessageSignature(public string, msg, sig []byte) error {
	hash := HashMessageForSignature(hex.EncodeToString(msg))
	return VerifyHashSignature(public, hash, sig)
}

func VerifyHashSignature(public string, hash, sig []byte) error {
	pub, err := hex.DecodeString(public)
	if err != nil {
		panic(public)
	}
	signed := crypto.VerifySignature(pub, hash, sig[:64])
	if signed {
		return nil
	}
	return fmt.Errorf("crypto.VerifySignature(%s, %x, %x)", public, hash, sig)
}

func parseEthereumCompressedPublicKey(public string) (*common.Address, error) {
	pub, err := hex.DecodeString(public)
	if err != nil {
		return nil, err
	}

	publicKey, err := crypto.DecompressPubkey(pub)
	if err != nil {
		return nil, err
	}

	addr := crypto.PubkeyToAddress(*publicKey)
	return &addr, nil
}

func getInitializer(owners []string, threshold int64) []byte {
	blankAddress := common.HexToAddress(EthereumEmptyAddress)
	handlerAddress := common.HexToAddress(EthereumCompatibilityFallbackHandlerAddress)
	initializer := packSetupArguments(
		owners, threshold, nil, blankAddress, handlerAddress, blankAddress, blankAddress, big.NewInt(0),
	)
	return initializer
}
