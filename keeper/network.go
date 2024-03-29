package keeper

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
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
	switch info.Chain {
	case SafeChainBitcoin, SafeChainLitecoin:
		info.Hash = hex.EncodeToString(extra[17:])
		valid, err := node.verifyBitcoinNetworkInfo(ctx, info)
		if err != nil {
			return fmt.Errorf("node.verifyBitcoinNetworkInfo(%v) => %v", info, err)
		} else if !valid {
			return node.store.FailRequest(ctx, req.Id)
		}
	case SafeChainEthereum, SafeChainMVM, SafeChainPolygon:
		info.Hash = "0x" + hex.EncodeToString(extra[17:])
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
	switch chain {
	case SafeChainBitcoin:
	case SafeChainLitecoin:
	case SafeChainEthereum:
	case SafeChainMVM:
	case SafeChainPolygon:
	default:
		return node.store.FailRequest(ctx, req.Id)
	}

	assetId := uuid.Must(uuid.FromBytes(extra[1:17]))
	abu := new(big.Int).SetUint64(binary.BigEndian.Uint64(extra[17:25]))
	amount := decimal.NewFromBigInt(abu, -8)
	mbu := new(big.Int).SetUint64(binary.BigEndian.Uint64(extra[25:33]))
	minimum := decimal.NewFromBigInt(mbu, -8)
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

func (node *Node) checkNetworkInfoForkTimestamp(info *store.NetworkInfo) bool {
	genesis := time.Unix(0, node.conf.MTG.Genesis.Timestamp)
	if info.CreatedAt.Before(genesis) {
		panic(info.RequestId)
	}
	forkAt := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	return info.CreatedAt.Before(forkAt)
}

func (node *Node) verifyBitcoinNetworkInfo(ctx context.Context, info *store.NetworkInfo) (bool, error) {
	if node.checkNetworkInfoForkTimestamp(info) {
		return true, nil
	}
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
	if block.Confirmations == -1 {
		return false, fmt.Errorf("malicious bitcoin fork %s", info.Hash)
	}
	if info.Fee < bitcoinMinimumFeeRate || info.Fee > bitcoinMaximumFeeRate {
		return false, nil
	}
	return true, nil
}

func (node *Node) verifyEthereumNetworkInfo(ctx context.Context, info *store.NetworkInfo) (bool, error) {
	if len(info.Hash) != 66 {
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
	case SafeChainPolygon:
		return node.conf.PolygonRPC, SafePolygonChainId
	default:
		panic(chain)
	}
}

func (node *Node) fetchAssetMetaFromMessengerOrEthereum(ctx context.Context, id, assetContract string, chain byte) (*store.Asset, error) {
	meta, err := node.fetchAssetMeta(ctx, id)
	if err != nil || meta != nil {
		return meta, err
	}
	switch chain {
	case SafeChainEthereum:
	case SafeChainMVM:
	case SafeChainPolygon:
	default:
		panic(chain)
	}
	rpc, _ := node.ethereumParams(chain)
	token, err := ethereum.FetchAsset(chain, rpc, assetContract)
	if err != nil {
		return nil, err
	}
	asset := &store.Asset{
		AssetId:   token.Id,
		MixinId:   crypto.NewHash([]byte(token.Id)).String(),
		AssetKey:  token.Address,
		Symbol:    token.Symbol,
		Name:      token.Name,
		Decimals:  token.Decimals,
		Chain:     token.Chain,
		CreatedAt: time.Now().UTC(),
	}
	return asset, node.store.WriteAssetMeta(ctx, asset)
}

func (node *Node) fetchMixinAsset(ctx context.Context, id string) (*store.Asset, error) {
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
	case SafePolygonChainId:
		chain = SafeChainPolygon
	default:
		panic(asset.ChainId)
	}

	meta := &store.Asset{
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

func (node *Node) fetchAssetMeta(ctx context.Context, id string) (*store.Asset, error) {
	meta, err := node.store.ReadAssetMeta(ctx, id)
	if err != nil || meta != nil {
		return meta, err
	}

	for {
		meta, err = node.fetchMixinAsset(ctx, id)
		if err != nil {
			reason := strings.ToLower(err.Error())
			switch {
			case strings.Contains(reason, "timeout"):
			case strings.Contains(reason, "eof"):
			case strings.Contains(reason, "handshake"):
			default:
				return meta, err
			}
			time.Sleep(2 * time.Second)
			continue
		}
		return meta, err
	}
}
