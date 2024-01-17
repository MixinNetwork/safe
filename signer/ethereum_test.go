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

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/multi-party-sig/pkg/math/curve"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/btcsuite/btcd/btcec/v2"
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

	rpc       = "https://polygon-rpc.com"
	chainID   = 137
	threshold = 2
	timelock  = 1
)

func TestCMPEthereumERC20Transaction(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	accountAddress := testPrepareEthereumAccount(ctx, require)

	assetAddress := "0xc2132D05D31c914a87C6611C10748AEb04B58e8F"
	destination := "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055"
	value := "100"
	n := 1
	id := "b231eebd-78ec-44f7-aeeb-7cf0b73ed070"
	tx, err := ethereum.CreateTransaction(ctx, ethereum.TypeERC20Tx, int64(chainID), id, accountAddress, destination, assetAddress, value, new(big.Int).SetInt64(int64(n)))
	require.Nil(err)

	outputs := tx.ExtractOutputs()
	require.Len(outputs, 1)
	require.Equal(assetAddress, outputs[0].TokenAddress)
	require.Equal(destination, outputs[0].Destination)
	require.Equal(value, outputs[0].Amount.String())

	signedTx := testEthereumSignTx(require, tx)
	raw := "00000000000000890000000000000000004065356638323935633932656233613163363362393665333534613333373466643662303239643932613738633665303962666133326264633230623362393930002a3078346635393734613035363032394546413765344237623531613742626362384645633645383937300014c2132d05d31c914a87c6611c10748aeb04b58e8f00000044a9059cbb000000000000000000000000a03a8590bb3a2ca5c747c8b99c63da399424a05500000000000000000000000000000000000000000000000000000000000000640001010020f80c82722e761b28156b6047833b254e38a47761bb7993a7a87917205ef3dac301062c383464353164666561643339653331393636646233613239376331653765616637323131336433646466623132376234303838306638333663623035613339643537353638343464393563653536306538626364323337666133616332373837313839343034383364383763623633616466333864323930323333663838343431662c36393535366661306562376265366233386435316537643236373233323462633632353465656638393465346264666263313235653231643230653764376461366436386265386237333930623531663532346433303366313234376631346137653836303961353666646332306332363065663364653939613130623036643166"
	require.Equal(raw, hex.EncodeToString(signedTx.Marshal()))
}

func TestCMPEthereumMultiSendTransaction(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	accountAddress := testPrepareEthereumAccount(ctx, require)

	var outputs []*ethereum.Output
	outputs = append(outputs, &ethereum.Output{
		Destination: "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055",
		Amount:      big.NewInt(100000000000000),
	})
	outputs = append(outputs, &ethereum.Output{
		TokenAddress: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
		Destination:  "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055",
		Amount:       big.NewInt(200),
	})
	n := 1
	id := "b231eebd-78ec-44f7-aeeb-7cf0b73ed070"
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

	signedTx := testEthereumSignTx(require, tx)
	raw := "00000000000000890000000000000001004066336238653462336561303462303137636630383961323039363962323661333264353232333836636331343064663734343435383535376133373065636431002a307834663539373461303536303239454641376534423762353161374262636238464563364538393730001438869bf66a61cf6bdb996a6ae40d5853fd43b526000001448d80ff0a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000ee00a03a8590bb3a2ca5c747c8b99c63da399424a05500000000000000000000000000000000000000000000000000005af3107a4000000000000000000000000000000000000000000000000000000000000000000000c2132d05d31c914a87c6611c10748aeb04b58e8f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000a03a8590bb3a2ca5c747c8b99c63da399424a05500000000000000000000000000000000000000000000000000000000000000c80000000000000000000000000000000000000001010020288302032801fdd390a9714e4c2b8421658c9d4723bfcc8b4431b0aae098452101062c656535306539386661396337333238633361323262653965386636666131633362323738303537313836613761353031343961643366613334346638353932613532376634353865656362336132373732623161373131303562663032373730373063373737373964323365666630303537383637326236366666613533653631662c64653233326436643732663235313834333531303739666135393630336332643533316432343433393930393634323132393635333662633034326533623666323961396134303339313866343163323131376366613632393564383630656662613263393734393666316366353939383535343437376266643165353833613166"
	require.Equal(raw, hex.EncodeToString(signedTx.Marshal()))
}

func TestCMPEthereumTransaction(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	accountAddress := testPrepareEthereumAccount(ctx, require)

	destination := "0xA03A8590BB3A2cA5c747c8b99C63DA399424a055"
	value := "100000000000000"
	n := 1
	id := "b231eebd-78ec-44f7-aeeb-7cf0b73ed070"
	tx, err := ethereum.CreateTransaction(ctx, ethereum.TypeETHTx, int64(chainID), id, accountAddress, destination, "", value, new(big.Int).SetInt64(int64(n)))
	require.Nil(err)

	outputs := tx.ExtractOutputs()
	require.Len(outputs, 1)
	require.Equal("", outputs[0].TokenAddress)
	require.Equal(destination, outputs[0].Destination)
	require.Equal(value, outputs[0].Amount.String())

	signedTx := testEthereumSignTx(require, tx)
	raw := "00000000000000890000000000000000004064663561343035633130346465633863623364346533333630656562313638663732333463623730366436343239373735343563303239636464323264633965002a3078346635393734613035363032394546413765344237623531613742626362384645633645383937300014a03a8590bb3a2ca5c747c8b99c63da399424a05500065af3107a4000000000010100209cbd585d2fc1c757ad354f0bbd0e2550eee2a33f751ac86a7bd7d2ed1b2a42b301062c366130316538343764333964386437393561386434653039633665383031316661336565366636323562363031393638363564323732346533313364643737373233646134656430363436343536653063323633306566616233623565383966303232303435353132353333353861393431666637666563623266366630313232302c33346639303533653861313564666538393037626431316133396637393461366266356161346631356565316438343532316230346465383764303231356132313632646363323966306137333534356333623937373838303134333036346535636635346663346137323838653863643730343131353662316364353865373230"
	require.Equal(raw, hex.EncodeToString(signedTx.Marshal()))
}

func testPrepareEthereumAccount(ctx context.Context, require *require.Assertions) string {
	ah, err := ethereumAddressFromPriv(testEthereumKeyHolder)
	require.Nil(err)
	require.Equal("0xC698197Dd0B0c24438a2508E464Fc5814A6cd512", ah)
	ph := ethereumCompressPubFromPriv(testEthereumKeyHolder)
	address, err := ethereum.ParseEthereumCompressedPublicKey(ph)
	require.Nil(err)
	require.Equal(ah, address.Hex())
	as, err := ethereumAddressFromPriv(testEthereumKeySigner)
	require.Nil(err)
	require.Equal("0xf78409F2c9Ffe7e697f9F463890889287a06B4Ad", as)
	ps := ethereumCompressPubFromPriv(testEthereumKeySigner)
	address, err = ethereum.ParseEthereumCompressedPublicKey(ps)
	require.Nil(err)
	require.Equal(as, address.Hex())
	ao, err := ethereumAddressFromPriv(testEthereumKeyObserver)
	require.Nil(err)
	require.Equal("0x09084B528F2AB737FF8A55a51ee6d8939da82F20", ao)
	po := ethereumCompressPubFromPriv(testEthereumKeyObserver)
	address, err = ethereum.ParseEthereumCompressedPublicKey(po)
	require.Nil(err)
	require.Equal(ao, address.Hex())

	addr := ethereum.GetSafeAccountAddress([]string{ah, as, ao}, int64(threshold))
	addrStr := addr.Hex()
	require.Equal("0x4f5974a056029EFA7e4B7b51a7Bbcb8FEc6E8970", addrStr)
	addr2 := ethereum.GetSafeAccountAddress([]string{ao, ah, as}, int64(threshold))
	addrStr2 := addr2.Hex()
	require.Equal(addrStr, addrStr2)
	owners, pubs := ethereum.GetSortedSafeOwners(ph, ps, po)
	addr3 := ethereum.GetSafeAccountAddress(owners, int64(threshold))
	addrStr3 := addr3.Hex()
	require.Equal(addrStr, addrStr3)

	id := uuid.Must(uuid.NewV4()).String()
	tx, err := ethereum.CreateEnableGuardTransaction(ctx, int64(chainID), id, addrStr, ao, new(big.Int).SetUint64(uint64(timelock)))
	require.Nil(err)
	for _, key := range []string{testEthereumKeyHolder, testEthereumKeySigner} {
		sig, err := testEthereumSignMessage(key, tx.Message)
		require.Nil(err)

		for i, p := range pubs {
			pub := ethereumCompressPubFromPriv(key)
			if pub == p {
				tx.Signatures[i] = sig
			}
		}
	}
	testSafeTransactionMarshal(require, tx)

	safeAddress, err := ethereum.GetOrDeploySafeAccount(ctx, rpc, os.Getenv("MVM_DEPLOYER"), int64(chainID), owners, int64(threshold), int64(timelock), 2, tx)
	require.Nil(err)
	require.Equal("0x4f5974a056029EFA7e4B7b51a7Bbcb8FEc6E8970", safeAddress.Hex())
	return safeAddress.Hex()
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

func testEthereumSignTx(require *require.Assertions, tx *ethereum.SafeTransaction) *ethereum.SafeTransaction {
	ph := ethereumCompressPubFromPriv(testEthereumKeyHolder)
	ps := ethereumCompressPubFromPriv(testEthereumKeySigner)
	po := ethereumCompressPubFromPriv(testEthereumKeyObserver)
	_, pubs := ethereum.GetSortedSafeOwners(ph, ps, po)

	for _, key := range []string{testEthereumKeyHolder, testEthereumKeySigner} {
		sig, err := testEthereumSignMessage(key, tx.Message)
		require.Nil(err)

		for i, p := range pubs {
			pub := ethereumCompressPubFromPriv(key)
			if pub == p {
				tx.Signatures[i] = sig
			}
		}
	}
	return tx
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

func ethereumCompressPubFromPriv(priv string) string {
	seed, _ := hex.DecodeString(priv)
	_, dk := btcec.PrivKeyFromBytes(seed)
	return hex.EncodeToString(dk.SerializeCompressed())
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
