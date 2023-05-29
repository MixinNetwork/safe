package signer

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/test-go/testify/require"
)

const (
	testEthereumAddress = "0xF05C33aA6D2026AD675CAdB73648A9A0Ff279B65"
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
)

func TestCMPEthereumSign(t *testing.T) {
	require := require.New(t)
	ctx, nodes := TestPrepare(require)

	public := TestCMPPrepareKeys(ctx, require, nodes, 2)

	addr := ethereumAddressFromPub(require, public)
	require.Equal(testEthereumAddress, addr.Hex())

	hash, raw, err := ethereumSignTransaction(ctx, require, nodes, public, 2, "0x3c84B6C98FBeB813e05a7A7813F0442883450B1F", big.NewInt(1000000000000000), 250000, big.NewInt(100000000), nil)
	logger.Println(hash, raw, err)
	require.Nil(err)
	require.Len(hash, 66)

	var tx types.Transaction
	b, _ := hex.DecodeString(raw[2:])
	tx.UnmarshalBinary(b)
	signer := types.MakeSigner(mvmChainConfig, mvmChainConfig.ByzantiumBlock)
	verify, _ := signer.Sender(&tx)
	require.Equal(testEthereumAddress, verify.String())
	require.Equal(hash, tx.Hash().Hex())
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

	signer := types.MakeSigner(mvmChainConfig, mvmChainConfig.ByzantiumBlock)
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
	verify, err = types.MakeSigner(mvmChainConfig, mvmChainConfig.ByzantiumBlock).Sender(tx)
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
