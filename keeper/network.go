package keeper

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/gofrs/uuid/v5"
	"github.com/shopspring/decimal"
)

const (
	bitcoinMinimumFeeRate = 10
	bitcoinMaximumFeeRate = 1000
)

func (node *Node) writeNetworkInfo(ctx context.Context, req *common.Request) error {
	logger.Printf("node.writeNetworkInfo(%v)", req)
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) < 17 {
		return node.store.FailRequest(ctx, req.Id)
	}

	info := &store.NetworkInfo{
		RequestId: req.Id,
		CreatedAt: req.CreatedAt,
	}
	info.Chain = extra[0]
	info.Fee = binary.BigEndian.Uint64(extra[1:9])
	info.Height = binary.BigEndian.Uint64(extra[9:17])

	old, err := node.store.ReadLatestNetworkInfo(ctx, info.Chain, req.CreatedAt)
	if err != nil {
		return fmt.Errorf("store.ReadLatestNetworkInfo(%d) => %v", info.Chain, err)
	} else if old != nil && old.RequestId == req.Id {
		return node.store.FailRequest(ctx, req.Id)
	} else if old != nil && old.Height > info.Height {
		return node.store.FailRequest(ctx, req.Id)
	}

	if info.Chain != SafeCurveChain(req.Curve) {
		panic(req.Id)
	}
	info.Hash = hex.EncodeToString(extra[17:])
	switch info.Chain {
	case SafeChainBitcoin, SafeChainLitecoin:
		valid, err := node.verifyBitcoinNetworkInfo(ctx, info)
		if err != nil {
			return fmt.Errorf("node.verifyBitcoinNetworkInfo(%v) => %v", info, err)
		} else if !valid {
			return node.store.FailRequest(ctx, req.Id)
		}
	case SafeChainEthereum, SafeChainMVM:
		valid, err := node.verifyEthereumNetworkInfo(ctx, info)
		if err != nil {
			return fmt.Errorf("node.verifyEthereumNetworkInfo(%v) => %v", info, err)
		} else if !valid {
			return node.store.FailRequest(ctx, req.Id)
		}
	default:
		return node.store.FailRequest(ctx, req.Id)
	}

	return node.store.WriteNetworkInfoFromRequest(ctx, info)
}

func (node *Node) writeOperationParams(ctx context.Context, req *common.Request) error {
	logger.Printf("node.writeOperationParams(%v)", req)
	if req.Role != common.RequestRoleObserver {
		panic(req.Role)
	}
	extra, _ := hex.DecodeString(req.Extra)
	if len(extra) != 33 {
		return node.store.FailRequest(ctx, req.Id)
	}

	chain := extra[0]
	if chain != SafeCurveChain(req.Curve) {
		panic(req.Id)
	}
	var precision int64
	switch chain {
	case SafeChainBitcoin, SafeChainLitecoin:
		precision = bitcoin.ValuePrecision
	case SafeChainEthereum, SafeChainMVM:
		precision = ethereum.ValuePrecision
	default:
		return node.store.FailRequest(ctx, req.Id)
	}

	assetId := uuid.Must(uuid.FromBytes(extra[1:17]))
	abu := new(big.Int).SetUint64(binary.BigEndian.Uint64(extra[17:25]))
	amount := decimal.NewFromBigInt(abu, -int32(precision))
	mbu := new(big.Int).SetUint64(binary.BigEndian.Uint64(extra[25:33]))
	minimum := decimal.NewFromBigInt(mbu, -int32(precision))
	params := &store.OperationParams{
		RequestId:            req.Id,
		Chain:                chain,
		OperationPriceAsset:  assetId.String(),
		OperationPriceAmount: amount,
		TransactionMinimum:   minimum,
		CreatedAt:            req.CreatedAt,
	}
	return node.store.WriteOperationParamsFromRequest(ctx, params)
}

func (node *Node) verifyBitcoinNetworkInfo(ctx context.Context, info *store.NetworkInfo) (bool, error) {
	if len(info.Hash) != 64 {
		return false, nil
	}
	rpc, _ := node.bitcoinParams(info.Chain)
	block, err := bitcoin.RPCGetBlock(rpc, info.Hash)
	if err != nil || block == nil {
		return false, fmt.Errorf("malicious bitcoin block or node not in sync? %s %v", info.Hash, err)
	}
	if block.Height != info.Height {
		return false, fmt.Errorf("malicious bitcoin block %s", info.Hash)
	}
	if info.Fee < bitcoinMinimumFeeRate || info.Fee > bitcoinMaximumFeeRate {
		return false, nil
	}
	return true, nil
}

func (node *Node) verifyEthereumNetworkInfo(ctx context.Context, info *store.NetworkInfo) (bool, error) {
	if len(info.Hash) != 64 {
		return false, nil
	}
	rpc, _ := node.ethereumParams(info.Chain)
	block, err := ethereum.RPCGetBlock(rpc, info.Hash)
	if err != nil || block == nil {
		return false, fmt.Errorf("malicious ethereum block or node not in sync? %s %v", info.Hash, err)
	}
	if block.Height != info.Height {
		return false, fmt.Errorf("malicious ethereum block %s", info.Hash)
	}
	return true, nil
}

func (node *Node) bitcoinParams(chain byte) (string, string) {
	switch chain {
	case SafeChainBitcoin:
		return node.conf.BitcoinRPC, SafeBitcoinChainId
	case SafeChainLitecoin:
		return node.conf.LitecoinRPC, SafeLitecoinChainId
	default:
		panic(chain)
	}
}

func (node *Node) ethereumParams(chain byte) (string, string) {
	switch chain {
	case SafeChainEthereum:
		return node.conf.EthereumRPC, SafeEthereumChainId
	case SafeChainMVM:
		return node.conf.MVMRPC, SafeMVMChainId
	default:
		panic(chain)
	}
}

func (node *Node) fetchAssetMeta(ctx context.Context, id string) (*store.Asset, error) {
	meta, err := node.store.ReadAssetMeta(ctx, id)
	if err != nil || meta != nil {
		return meta, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	path := node.conf.MixinMessengerAPI + "/network/assets/" + id
	resp, err := client.Get(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body struct {
		Data *struct {
			AssetId   string      `json:"asset_id"`
			MixinId   crypto.Hash `json:"mixin_id"`
			AssetKey  string      `json:"asset_key"`
			Symbol    string      `json:"symbol"`
			Name      string      `json:"name"`
			Precision uint32      `json:"precision"`
			ChainId   string      `json:"chain_id"`
		} `json:"data"`
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return nil, err
	}
	asset := body.Data

	var chain byte
	switch asset.ChainId {
	case SafeBitcoinChainId:
		chain = SafeChainBitcoin
	case SafeLitecoinChainId:
		chain = SafeChainLitecoin
	case SafeEthereumChainId:
		chain = SafeChainEthereum
	case SafeMVMChainId:
		chain = SafeChainMVM
	default:
		panic(asset.ChainId)
	}

	meta = &store.Asset{
		AssetId:   asset.AssetId,
		MixinId:   asset.MixinId.String(),
		AssetKey:  asset.AssetKey,
		Symbol:    asset.Symbol,
		Name:      asset.Name,
		Decimals:  asset.Precision,
		Chain:     chain,
		CreatedAt: time.Now().UTC(),
	}
	return meta, node.store.WriteAssetMeta(ctx, meta)
}
