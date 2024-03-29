package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/domains/mvm"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper"
)

func (node *Node) deployBitcoinSafeBond(ctx context.Context, data []byte) error {
	logger.Printf("node.deployBitcoinSafeBond(%x)", data)
	wsa, err := bitcoin.UnmarshalWitnessScriptAccount(data)
	if err != nil {
		return fmt.Errorf("bitcoin.UnmarshalWitnessScriptAccount(%x) => %v", data, err)
	}
	safe, err := node.keeperStore.ReadSafeByAddress(ctx, wsa.Address)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v", wsa.Address, err)
	}
	_, bitcoinAssetId := node.bitcoinParams(safe.Chain)
	_, err = node.checkOrDeployKeeperBond(ctx, safe.Chain, bitcoinAssetId, "", safe.Holder)
	logger.Printf("node.checkOrDeployKeeperBond(%s, %s) => %v", bitcoinAssetId, safe.Holder, err)
	return err
}

func (node *Node) checkOrDeployKeeperBond(ctx context.Context, chain byte, assetId, assetAddress, holder string) (bool, error) {
	asset, bond, _, err := node.fetchBondAsset(ctx, chain, assetId, assetAddress, holder)
	if err != nil {
		return false, fmt.Errorf("node.fetchBondAsset(%s, %s) => %v", assetId, holder, err)
	}
	if bond != nil {
		return true, nil
	}
	rpc, key := node.conf.MVMRPC, node.conf.MVMKey
	return false, abi.GetOrDeployFactoryAsset(rpc, key, assetId, asset.Symbol, asset.Name, holder)
}

func (node *Node) fetchBondAsset(ctx context.Context, chain byte, assetId, assetAddress, holder string) (*Asset, *Asset, string, error) {
	asset, err := node.fetchAssetMetaFromMessengerOrEthereum(ctx, assetId, assetAddress, chain)
	if err != nil {
		return nil, nil, "", fmt.Errorf("node.fetchAssetMeta(%s) => %v", assetId, err)
	}

	addr := abi.GetFactoryAssetAddress(assetId, asset.Symbol, asset.Name, holder)
	assetKey := strings.ToLower(addr.String())
	err = mvm.VerifyAssetKey(assetKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("mvm.VerifyAssetKey(%s) => %v", assetKey, err)
	}

	bondId := mvm.GenerateAssetId(assetKey)
	bond, err := node.fetchAssetMeta(ctx, bondId.String())
	return asset, bond, bondId.String(), err
}

func (node *Node) fetchAssetMetaFromMessengerOrEthereum(ctx context.Context, id, assetContract string, chain byte) (*Asset, error) {
	meta, err := node.fetchAssetMeta(ctx, id)
	if err != nil || meta != nil {
		return meta, err
	}
	switch chain {
	case keeper.SafeChainEthereum:
	case keeper.SafeChainMVM:
	case keeper.SafeChainPolygon:
	default:
		panic(chain)
	}
	rpc, _ := node.ethereumParams(chain)
	token, err := ethereum.FetchAsset(chain, rpc, assetContract)
	if err != nil {
		return nil, err
	}
	asset := &Asset{
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

func (node *Node) fetchMixinAsset(ctx context.Context, id string) (*Asset, error) {
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
	if err != nil || body.Data == nil {
		return nil, err
	}
	asset := body.Data

	var chain byte
	switch asset.ChainId {
	case keeper.SafeBitcoinChainId:
		chain = keeper.SafeChainBitcoin
	case keeper.SafeLitecoinChainId:
		chain = keeper.SafeChainLitecoin
	case keeper.SafeEthereumChainId:
		chain = keeper.SafeChainEthereum
	case keeper.SafeMVMChainId:
		chain = keeper.SafeChainMVM
	case keeper.SafePolygonChainId:
		chain = keeper.SafeChainPolygon
	default:
		panic(asset.ChainId)
	}

	meta := &Asset{
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

func (node *Node) fetchAssetMeta(ctx context.Context, id string) (*Asset, error) {
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
