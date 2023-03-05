package common

import (
	"bytes"
	"math/big"

	"github.com/MixinNetwork/safe/common/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

const (
	mvmChainId         = 73927
	mvmStorageContract = "0xef241988D19892fE4efF4935256087F4fdc5ecAa"
)

func MVMHash(b []byte) []byte {
	return crypto.Keccak256(b)
}

func MVMStorageWrite(rpc, key string, msg []byte) ([]byte, error) {
	signer, err := mvmSignerInit(key)
	if err != nil {
		return nil, err
	}
	conn, abi, err := mvmStorageInit(rpc)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	k := new(big.Int).SetBytes(MVMHash(msg))
	o, err := abi.Read(nil, k)
	if err != nil {
		return nil, err
	}
	if bytes.Compare(o, msg) == 0 {
		return MVMHash(msg), nil
	}

	_, err = abi.Write(signer, k, msg)
	return MVMHash(msg), err
}

func MVMStorageRead(rpc string, msg []byte) ([]byte, error) {
	conn, abi, err := mvmStorageInit(rpc)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	k := new(big.Int).SetBytes(msg)
	return abi.Read(nil, k)
}

func mvmSignerInit(key string) (*bind.TransactOpts, error) {
	chainId := new(big.Int).SetInt64(mvmChainId)
	priv, err := crypto.HexToECDSA(key)
	if err != nil {
		return nil, err
	}
	return bind.NewKeyedTransactorWithChainID(priv, chainId)
}

func mvmStorageInit(rpc string) (*ethclient.Client, *abi.StorageContract, error) {
	conn, err := ethclient.Dial(rpc)
	if err != nil {
		return nil, nil, err
	}

	abi, err := abi.NewStorageContract(common.HexToAddress(mvmStorageContract), conn)
	if err != nil {
		return nil, nil, err
	}

	return conn, abi, nil
}
