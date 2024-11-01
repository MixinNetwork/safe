package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	mc "github.com/MixinNetwork/mixin/common"
	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
)

type MixinNetworkAsset struct {
	AssetId   string      `json:"asset_id"`
	MixinId   crypto.Hash `json:"mixin_id"`
	AssetKey  string      `json:"asset_key"`
	Symbol    string      `json:"symbol"`
	Name      string      `json:"name"`
	Precision uint32      `json:"precision"`
	ChainId   string      `json:"chain_id"`
}

func (node *Node) deployBitcoinSafeBond(ctx context.Context, data []byte) error {
	logger.Printf("node.deployBitcoinSafeBond(%x)", data)
	wsa, err := bitcoin.UnmarshalWitnessScriptAccount(data)
	if err != nil {
		return fmt.Errorf("bitcoin.UnmarshalWitnessScriptAccount(%x) => %v", data, err)
	}
	safe, err := node.keeperStore.ReadSafeByAddress(ctx, wsa.Address)
	if err != nil || safe == nil || safe.State != common.RequestStateDone {
		return fmt.Errorf("keeperStore.ReadSafeByAddress(%s) => %v %v", wsa.Address, safe, err)
	}
	_, bitcoinAssetId := node.bitcoinParams(safe.Chain)
	_, err = node.checkOrDeployKeeperBond(ctx, safe.Chain, bitcoinAssetId, "", safe.Holder, safe.Address)
	logger.Printf("node.checkOrDeployKeeperBond(%s, %s) => %v", bitcoinAssetId, safe.Holder, err)
	if err != nil {
		return fmt.Errorf("node.checkOrDeployKeeperBond(%s, %s) => %v", bitcoinAssetId, safe.Holder, err)
	}
	err = node.store.MarkAccountDeployed(ctx, safe.Address)
	logger.Printf("store.MarkAccountDeployed(%s) => %v", safe.Address, err)
	return err
}

func (node *Node) fetchBondAssetReceiver(ctx context.Context, address, assetId string) string {
	migrated, err := node.keeperStore.CheckMigrateAsset(ctx, address, assetId)
	if err != nil {
		panic(err)
	}

	if migrated {
		return node.conf.PolygonObserverDepositEntry
	}
	return node.conf.PolygonKeeperDepositEntry
}

func (node *Node) checkOrDeployKeeperBond(ctx context.Context, chain byte, assetId, assetAddress, holder, address string) (bool, error) {
	asset, bond, _, err := node.fetchBondAsset(ctx, chain, assetId, assetAddress, holder, address)
	logger.Printf("node.fetchBondAsset(%d, %s, %s, %s, %s) => %v %v %v",
		chain, assetId, assetAddress, holder, address, asset, bond, err)
	if err != nil {
		return false, fmt.Errorf("node.fetchBondAsset(%s, %s) => %v", assetId, holder, err)
	}
	if bond != nil {
		return true, nil
	}
	entry := node.fetchBondAssetReceiver(ctx, address, assetId)
	logger.Printf("node.fetchBondAssetReceiver(%s, %s) => %s", address, assetId, entry)
	rpc, key := node.conf.PolygonRPC, node.conf.EVMKey
	return false, abi.GetOrDeployFactoryAsset(ctx, rpc, key, assetId, asset.Symbol, asset.Name, entry, holder)
}

func (node *Node) fetchBondAsset(ctx context.Context, chain byte, assetId, assetAddress, holder, address string) (*Asset, *Asset, string, error) {
	asset, err := node.fetchAssetMetaFromMessengerOrEthereum(ctx, assetId, assetAddress, chain)
	if err != nil {
		return nil, nil, "", fmt.Errorf("node.fetchAssetMeta(%s) => %v", assetId, err)
	}
	entry := node.fetchBondAssetReceiver(ctx, address, assetId)

	addr := abi.GetFactoryAssetAddress(entry, assetId, asset.Symbol, asset.Name, holder)
	assetKey := strings.ToLower(addr.String())
	logger.Printf("GetFactoryAssetAddress(%s %s %s %s %s) => %s", entry, assetId, asset.Symbol, asset.Name, holder, assetKey)
	err = ethereum.VerifyAssetKey(assetKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("mvm.VerifyAssetKey(%s) => %v", assetKey, err)
	}

	bondId := ethereum.GenerateAssetId(common.SafeChainPolygon, assetKey)
	logger.Printf("GenerateAssetId() => %s", bondId)
	bond, err := node.fetchAssetMeta(ctx, bondId)
	return asset, bond, bondId, err
}

func (node *Node) fetchAssetMetaFromMessengerOrEthereum(ctx context.Context, id, assetContract string, chain byte) (*Asset, error) {
	meta, err := node.fetchAssetMeta(ctx, id)
	if err != nil || meta != nil {
		return meta, err
	}
	switch chain {
	case common.SafeChainEthereum:
	case common.SafeChainPolygon:
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
		MixinId:   crypto.Sha256Hash([]byte(token.Id)).String(),
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
		Data *MixinNetworkAsset `json:"data"`
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil || body.Data == nil {
		return nil, err
	}
	asset := body.Data

	return &Asset{
		AssetId:   asset.AssetId,
		MixinId:   asset.MixinId.String(),
		AssetKey:  asset.AssetKey,
		Symbol:    asset.Symbol,
		Name:      asset.Name,
		Decimals:  asset.Precision,
		Chain:     common.SafeAssetIdChainNoPanic(asset.ChainId),
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (node *Node) fetchAssetMeta(ctx context.Context, id string) (*Asset, error) {
	meta, err := node.store.ReadAssetMeta(ctx, id)
	if err != nil || meta != nil {
		return meta, err
	}

	for {
		meta, err = node.fetchMixinAsset(ctx, id)
		if err == nil {
			if meta == nil {
				return nil, nil
			}
			if meta.Chain == 0 {
				panic(id)
			}
			return meta, node.store.WriteAssetMeta(ctx, meta)
		}
		reason := strings.ToLower(err.Error())
		switch {
		case strings.Contains(reason, "timeout"):
		case strings.Contains(reason, "eof"):
		case strings.Contains(reason, "handshake"):
		default:
			return nil, err
		}
		time.Sleep(2 * time.Second)
	}
}

func (node *Node) checkKeeperHasSufficientBond(ctx context.Context, bondId string, deposit *Deposit) (bool, error) {
	balance, err := common.SafeAssetBalance(ctx, node.mixin, node.GetKeepers(), node.keeper.Genesis.Threshold, bondId)
	if err != nil {
		return false, fmt.Errorf("mixin.SafeAssetBalance(%s) => %v", bondId, err)
	}
	amt := mc.NewIntegerFromString(deposit.Amount)
	return balance.Cmp(amt) >= 0, nil
}
