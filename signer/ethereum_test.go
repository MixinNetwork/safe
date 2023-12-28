package signer

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

const (
	testEthereumAddress = "0xF05C33aA6D2026AD675CAdB73648A9A0Ff279B65"

	testEthereumKeyHolder   = "4cb7437a31a724c7231f83c01f865bf13fc65725cb6219ac944321f484bf80a2"
	testEthereumKeySigner   = "ff29332c230fdd78cfee84e10bc5edc9371a6a593ccafaf08e115074e7de2b89"
	testEthereumKeyObserver = "6421d5ce0fd415397fdd2978733852cee7ad44f28d87cd96038460907e2ffb18"
)

var (
	big8           = big.NewInt(8)
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))

	mvmChainConfig = &params.ChainConfig{
		ChainID:        big.NewInt(73927),
		HomesteadBlock: big.NewInt(0),
		DAOForkBlock:   nil,
		DAOForkSupport: true,
		EIP150Block:    big.NewInt(0),
		EIP155Block:    big.NewInt(0),
		EIP158Block:    big.NewInt(0),
		ByzantiumBlock: big.NewInt(0),
	}

	rpc      = "https://geth.mvm.dev"
	chainID  = 73927
	timelock = 1
)

func TestCMPEthereumERC20Transaction(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	accountAddress := testPrepareEthereumAccount(ctx, require)

	assetAddress := "0x910Fb1751B946C7D691905349eC5dD250EFBF40a"
	destination := "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055"
	value := "100000000"
	n, err := ethereum.GetNonce(rpc, accountAddress)
	require.Nil(err)
	id := uuid.Must(uuid.NewV4()).String()
	tx, err := ethereum.CreateTransaction(ctx, ethereum.TypeERC20Tx, int64(chainID), id, accountAddress, destination, assetAddress, value, new(big.Int).SetInt64(int64(n)))
	require.Nil(err)

	outputs := tx.ExtractOutputs()
	require.Len(outputs, 1)
	require.Equal(assetAddress, outputs[0].TokenAddress)
	require.Equal(destination, outputs[0].Destination)
	require.Equal(value, outputs[0].Amount.String())

	sigHolder, err := testEthereumSignMessage(testEthereumKeyHolder, tx.Message)
	require.Nil(err)
	sigSigner, err := testEthereumSignMessage(testEthereumKeySigner, tx.Message)
	require.Nil(err)
	tx.Signatures[1] = sigHolder
	tx.Signatures[2] = sigSigner

	success, err := tx.ValidTransaction(rpc)
	require.Nil(err)
	require.True(success)
}

func TestCMPEthereumMultiSendTransaction(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	accountAddress := testPrepareEthereumAccount(ctx, require)

	var outputs []*ethereum.Output
	outputs = append(outputs, &ethereum.Output{
		Destination: "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055",
		Amount:      big.NewInt(10000000000000),
	})
	outputs = append(outputs, &ethereum.Output{
		TokenAddress: "0x910Fb1751B946C7D691905349eC5dD250EFBF40a",
		Destination:  "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055",
		Amount:       big.NewInt(100000000),
	})
	n, err := ethereum.GetNonce(rpc, accountAddress)
	require.Nil(err)
	id := uuid.Must(uuid.NewV4()).String()
	tx, err := ethereum.CreateTransactionFromOutputs(ctx, ethereum.TypeMultiSendTx, int64(chainID), id, accountAddress, outputs, new(big.Int).SetInt64(int64(n)))
	require.Nil(err)

	parsedOutputs := tx.ExtractOutputs()
	require.Len(parsedOutputs, 2)
	for i, po := range parsedOutputs {
		o := outputs[i]
		require.True(po.Amount.Cmp(o.Amount) == 0)
		require.Equal(po.Destination, o.Destination)
		require.Equal(po.TokenAddress, o.TokenAddress)
	}

	sigHolder, err := testEthereumSignMessage(testEthereumKeyHolder, tx.Message)
	require.Nil(err)
	sigSigner, err := testEthereumSignMessage(testEthereumKeySigner, tx.Message)
	require.Nil(err)
	tx.Signatures[1] = sigHolder
	tx.Signatures[2] = sigSigner

	success, err := tx.ValidTransaction(rpc)
	require.Nil(err)
	require.True(success)
}

func TestCMPEthereumTransaction(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	accountAddress := testPrepareEthereumAccount(ctx, require)

	destination := "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055"
	value := "10000000000"
	n := 6
	id := uuid.Must(uuid.NewV4()).String()
	tx, err := ethereum.CreateTransaction(ctx, ethereum.TypeETHTx, int64(chainID), id, accountAddress, destination, "", value, new(big.Int).SetInt64(int64(n)))
	require.Nil(err)

	outputs := tx.ExtractOutputs()
	require.Len(outputs, 1)
	require.Equal("", outputs[0].TokenAddress)
	require.Equal(destination, outputs[0].Destination)
	require.Equal(value, outputs[0].Amount.String())

	sigHolder, err := testEthereumSignMessage(testEthereumKeyHolder, tx.Message)
	require.Nil(err)
	sigSigner, err := testEthereumSignMessage(testEthereumKeySigner, tx.Message)
	require.Nil(err)
	tx.Signatures[1] = sigHolder
	tx.Signatures[2] = sigSigner

	currentNonce, err := ethereum.GetNonce(rpc, accountAddress)
	require.Nil(err)
	if currentNonce == int64(n) {
		isValid, err := tx.ValidTransaction(rpc)
		require.Nil(err)
		require.True(isValid)

		_, err = tx.ExecTransaction(ctx, rpc, os.Getenv("MVM_DEPLOYER"))
		require.Nil(err)

		time.Sleep(1 * time.Minute)
		tx, err := ethereum.CreateTransaction(ctx, ethereum.TypeETHTx, int64(chainID), id, accountAddress, destination, "", value, new(big.Int).SetInt64(int64(n+1)))
		require.Nil(err)

		// signatures should follow the asc order of addresses of owners
		sigObserver, err := testEthereumSignMessage(testEthereumKeyObserver, tx.Message)
		require.Nil(err)
		sigHolder, err := testEthereumSignMessage(testEthereumKeyHolder, tx.Message)
		require.Nil(err)
		tx.Signatures[0] = sigObserver
		tx.Signatures[1] = sigHolder

		_, err = tx.ValidTransaction(rpc)
		require.NotNil(err)
	}
}

func testPrepareEthereumAccount(ctx context.Context, require *require.Assertions) string {
	ah, err := ethereumAddressFromPriv(testEthereumKeyHolder)
	require.Nil(err)
	require.Equal("0xC698197Dd0B0c24438a2508E464Fc5814A6cd512", ah)
	as, err := ethereumAddressFromPriv(testEthereumKeySigner)
	require.Nil(err)
	require.Equal("0xf78409F2c9Ffe7e697f9F463890889287a06B4Ad", as)
	ao, err := ethereumAddressFromPriv(testEthereumKeyObserver)
	require.Nil(err)
	require.Equal("0x09084B528F2AB737FF8A55a51ee6d8939da82F20", ao)
	owners := []string{ah, as, ao}
	threshold := 2
	timelock := 2

	addr := ethereum.GetSafeAccountAddress(owners, int64(threshold))
	addrStr := addr.Hex()
	require.Equal("0x0385B11Cfe2C529DE68E045C9E7708BA1a446432", addrStr)

	id := uuid.Must(uuid.NewV4()).String()
	tx, err := ethereum.CreateEnableGuardTransaction(ctx, int64(chainID), id, addrStr, ao, new(big.Int).SetUint64(uint64(timelock)))
	require.Nil(err)

	sigHolder, err := testEthereumSignMessage(testEthereumKeyHolder, tx.Message)
	require.Nil(err)
	sigSigner, err := testEthereumSignMessage(testEthereumKeySigner, tx.Message)
	require.Nil(err)
	tx.Signatures[1] = sigHolder
	tx.Signatures[2] = sigSigner

	testSafeTransactionMarshal(require, tx)

	safeaddress, err := ethereum.GetOrDeploySafeAccount(ctx, rpc, os.Getenv("MVM_DEPLOYER"), int64(chainID), owners, int64(threshold), int64(timelock), 2, tx)
	require.Nil(err)
	require.Equal("0x0385B11Cfe2C529DE68E045C9E7708BA1a446432", addrStr)
	return safeaddress.String()
}

func testSafeTransactionMarshal(require *require.Assertions, tx *ethereum.SafeTransaction) {
	extra := tx.Marshal()
	txDuplicate, err := ethereum.UnmarshalSafeTransaction(extra)
	require.Nil(err)
	require.Equal(tx.ChainID, txDuplicate.ChainID)
	require.Equal(tx.SafeAddress, txDuplicate.SafeAddress)
	require.Equal(tx.Destination.Hex(), txDuplicate.Destination.Hex())
	require.Equal(tx.Value.Int64(), txDuplicate.Value.Int64())
	require.Equal(hex.EncodeToString(tx.Data), hex.EncodeToString(txDuplicate.Data))
	require.Equal(tx.Nonce.Int64(), txDuplicate.Nonce.Int64())
	require.Equal(hex.EncodeToString(tx.Message), hex.EncodeToString(txDuplicate.Message))
	require.Equal(hex.EncodeToString(tx.Signatures[0]), hex.EncodeToString(txDuplicate.Signatures[0]))
	require.Equal(hex.EncodeToString(tx.Signatures[1]), hex.EncodeToString(txDuplicate.Signatures[1]))
	require.Equal(hex.EncodeToString(tx.Signatures[2]), hex.EncodeToString(txDuplicate.Signatures[2]))
}

func testEthereumSignMessage(priv string, message []byte) ([]byte, error) {
	private, err := crypto.HexToECDSA(priv)
	if err != nil {
		return nil, err
	}

	hash := crypto.Keccak256Hash([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)))
	signature, err := crypto.Sign(hash.Bytes(), private)
	if err != nil {
		return nil, err
	}
	// Golang returns the recovery ID in the last byte instead of v
	// v = 27 + rid
	signature[64] += 27
	hasPrefix := testIsTxHashSignedWithPrefix(priv, hash.Bytes(), signature)
	if hasPrefix {
		signature[64] += 4
	}
	return signature, nil
}

func testIsTxHashSignedWithPrefix(priv string, hash, signature []byte) bool {
	recoveredData, err := crypto.Ecrecover(hash, signature)
	if err != nil {
		return params.TestRules.IsEIP150
	}
	recoveredPub, err := crypto.UnmarshalPubkey(recoveredData)
	if err != nil {
		return true
	}
	recoveredAddress := crypto.PubkeyToAddress(*recoveredPub).Hex()
	address, err := ethereumAddressFromPriv(priv)
	if err != nil {
		return true
	}
	return recoveredAddress != address
}

func TestCMPEthereumSign(t *testing.T) {
	require := require.New(t)
	ctx, nodes := TestPrepare(require)

	public, _ := TestCMPPrepareKeys(ctx, require, nodes, 2)

	addr := ethereumAddressFromPub(require, public)
	require.Equal(testEthereumAddress, addr.Hex())

	hash, raw, err := ethereumSignTransaction(ctx, require, nodes, public, 2, "0x3c84B6C98FBeB813e05a7A7813F0442883450B1F", big.NewInt(1000000000000000), 250000, big.NewInt(100000000), nil)
	logger.Println(hash, raw, err)
	require.Nil(err)
	require.Len(hash, 66)

	var tx types.Transaction
	b, _ := hex.DecodeString(raw[2:])
	tx.UnmarshalBinary(b)
	signer := types.MakeSigner(mvmChainConfig, mvmChainConfig.ByzantiumBlock, 0)
	verify, _ := signer.Sender(&tx)
	require.Equal(testEthereumAddress, verify.String())
	require.Equal(hash, tx.Hash().Hex())
}

func ethereumAddressFromPriv(priv string) (string, error) {
	privateKey, err := crypto.HexToECDSA(priv)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)

	addr := crypto.PubkeyToAddress(*publicKeyECDSA)
	return addr.String(), nil
}

func ethereumAddressFromPub(require *require.Assertions, public string) common.Address {
	mpc, err := hex.DecodeString(public)
	require.Nil(err)

	var sp curve.Secp256k1Point
	err = sp.UnmarshalBinary(mpc)
	require.Nil(err)

	xb := sp.XScalar().Bytes()
	yb := sp.YScalar().Bytes()
	require.Nil(err)

	pub := append(xb, yb...)
	addr := common.BytesToAddress(crypto.Keccak256(pub)[12:])
	return addr
}

func ethereumSignTransaction(ctx context.Context, require *require.Assertions, nodes []*Node, mpc string, nonce uint64, to string, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) (string, string, error) {
	tb, _ := hex.DecodeString(to[2:])
	receiver := common.BytesToAddress(tb)
	tx := types.NewTransaction(nonce, receiver, amount, gasLimit, gasPrice, data)

	signer := types.MakeSigner(mvmChainConfig, mvmChainConfig.ByzantiumBlock, 0)
	hash := signer.Hash(tx)

	sig := testCMPSign(ctx, require, nodes, mpc, hash[:], 2)
	require.Len(sig, 65)
	tx, err := tx.WithSignature(signer, sig)
	require.Nil(err)
	rb, err := tx.MarshalBinary()
	require.Nil(err)
	raw := fmt.Sprintf("0x%x", rb)

	verify, err := ethereumVerifyTransaction(signer, tx)
	require.Nil(err)
	require.Equal(testEthereumAddress, verify.String())
	verify, err = types.MakeSigner(mvmChainConfig, mvmChainConfig.ByzantiumBlock, 0).Sender(tx)
	require.Nil(err)
	require.Equal(testEthereumAddress, verify.String())

	return tx.Hash().Hex(), raw, nil
}

func ethereumVerifyTransaction(s types.Signer, tx *types.Transaction) (common.Address, error) {
	chainIdMul := new(big.Int).Mul(mvmChainConfig.ChainID, big.NewInt(2))

	if tx.Type() != types.LegacyTxType {
		return common.Address{}, fmt.Errorf("ErrTxTypeNotSupported")
	}
	if !tx.Protected() {
		panic("protected")
	}
	if tx.ChainId().Cmp(mvmChainConfig.ChainID) != 0 {
		return common.Address{}, fmt.Errorf("ErrInvalidChainId")
	}
	V, R, S := tx.RawSignatureValues()
	V = new(big.Int).Sub(V, chainIdMul)
	V.Sub(V, big8)
	return recoverPlain(s.Hash(tx), R, S, V, true)
}

func recoverPlain(sighash common.Hash, R, S, Vb *big.Int, homestead bool) (common.Address, error) {
	if Vb.BitLen() > 8 {
		return common.Address{}, fmt.Errorf("ErrInvalidSig 0")
	}
	V := byte(Vb.Uint64() - 27)
	if !validateSignatureValues(V, R, S, homestead) {
		return common.Address{}, fmt.Errorf("ErrInvalidSig 1")
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.Address{}, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return common.Address{}, errors.New("invalid public key")
	}
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pub[1:])[12:])
	return addr, nil
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
func validateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		panic(r.String())
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(secp256k1halfN) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
}
