package observer

import (
	"context"
	"encoding/hex"
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

func (node *Node) deployEthereumSafeBond(ctx context.Context, data []byte) error {
	logger.Printf("node.deployEthereumSafeBond(%x)", data)
	gs, err := ethereum.UnmarshalGnosisSafe(data)
	if err != nil {
		return fmt.Errorf("ethereum.UnmarshalGnosisSafe(%x) => %v", data, err)
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, gs.Address)
	if err != nil {
		return fmt.Errorf("keeperStore.ReadSafeProposalByAddress(%s) => %v", gs.Address, err)
	}
	safe, err := node.keeperStore.ReadSafe(ctx, sp.Holder)
	if err != nil || safe == nil {
		return fmt.Errorf("keeperStore.ReadSafe(%s) => %v", gs.Address, err)
	}
	owners, pubs, err := ethereum.GetSortedSafeOwners(safe.Holder, safe.Signer, safe.Observer)
	logger.Printf("ethereum.GetSortedSafeOwners(%s, %s, %s) => %v %v %v", safe.Holder, safe.Signer, safe.Observer, owners, pubs, err)
	if err != nil {
		return err
	}
	rpc, ethereumAssetId := node.ethereumParams(safe.Chain)
	_, err = node.checkOrDeployKeeperBond(ctx, ethereumAssetId, sp.Holder)
	logger.Printf("node.checkOrDeployKeeperBond(%s, %s) => %v", ethereumAssetId, sp.Holder, err)
	if err != nil {
		return err
	}

	tx, err := node.keeperStore.ReadTransaction(ctx, gs.TxHash)
	if err != nil || tx == nil {
		return fmt.Errorf("keeperStore.ReadTransaction(%s) => %v %v", gs.TxHash, tx, err)
	}
	raw, err := hex.DecodeString(tx.RawTransaction)
	if err != nil {
		return err
	}
	t, err := ethereum.UnmarshalSafeTransaction(raw)
	logger.Printf("ethereum.UnmarshalSafeTransaction(%s) => %v %v", tx.RawTransaction, t, err)
	if err != nil {
		return err
	}
	var index int64
	for i, pub := range pubs {
		if pub == safe.Observer {
			index = int64(i)
		}
	}
	safeaddress, err := ethereum.GetOrDeploySafeAccount(rpc, node.conf.EVMKey, owners, 2, int64(safe.Timelock/time.Hour), index, t)
	logger.Printf("ethereum.GetOrDeploySafeAccount(%s, %v, %d, %d, %v) => %s %v", rpc, owners, 2, int64(safe.Timelock/time.Hour), t, safeaddress.Hex(), err)
	return err
}

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
	_, err = node.checkOrDeployKeeperBond(ctx, bitcoinAssetId, safe.Holder)
	logger.Printf("node.checkOrDeployKeeperBond(%s, %s) => %v", bitcoinAssetId, safe.Holder, err)
	return err
}

func (node *Node) checkOrDeployKeeperBond(ctx context.Context, assetId, holder string) (bool, error) {
	asset, bond, _, err := node.fetchBondAsset(ctx, assetId, holder)
	if err != nil {
		return false, fmt.Errorf("node.fetchBondAsset(%s, %s) => %v", assetId, holder, err)
	}
	if bond != nil {
		return true, nil
	}
	rpc, key := node.conf.MVMRPC, node.conf.MVMKey
	return false, abi.GetOrDeployFactoryAsset(rpc, key, assetId, asset.Symbol, asset.Name, holder)
}

func (node *Node) fetchBondAsset(ctx context.Context, assetId, holder string) (*Asset, *Asset, string, error) {
	asset, err := node.fetchAssetMeta(ctx, assetId)
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

func (node *Node) fetchAssetMeta(ctx context.Context, id string) (*Asset, error) {
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
	default:
		panic(asset.ChainId)
	}

	meta = &Asset{
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
