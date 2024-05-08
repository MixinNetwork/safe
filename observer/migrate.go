package observer

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/common/abi"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	gc "github.com/ethereum/go-ethereum/common"
	"github.com/fox-one/mixin-sdk-go/v2"
	"github.com/shopspring/decimal"
)

func (node *Node) listOutputs(ctx context.Context, asset string, state mixin.SafeUtxoState) ([]*mixin.SafeUtxo, error) {
	for {
		outputs, err := node.mixin.SafeListUtxos(ctx, mixin.SafeListUtxoOption{
			Members:   []string{node.mixin.ClientID},
			Threshold: 1,
			Asset:     asset,
			State:     state,
		})
		if err != nil {
			reason := strings.ToLower(err.Error())
			switch {
			case strings.Contains(reason, "timeout"):
			case strings.Contains(reason, "eof"):
			case strings.Contains(reason, "handshake"):
			default:
				return nil, err
			}
			time.Sleep(2 * time.Second)
			continue
		}
		return outputs, nil
	}
}

func (node *Node) fetchDepositEntry(ctx context.Context) (string, error) {
	for {
		addrs, err := node.mixin.SafeCreateDepositEntries(ctx, []string{node.mixin.ClientID}, 1, keeper.SafePolygonChainId)
		if err != nil {
			reason := strings.ToLower(err.Error())
			switch {
			case strings.Contains(reason, "timeout"):
			case strings.Contains(reason, "eof"):
			case strings.Contains(reason, "handshake"):
			default:
				return "", err
			}
			time.Sleep(2 * time.Second)
			continue
		}
		for _, a := range addrs {
			return a.Destination, nil
		}
	}
}

func (node *Node) fetchPolygonBondAsset(ctx context.Context, entry string, chain byte, assetId, assetAddress, holder string) (*Asset, *Asset, string, error) {
	asset, err := node.fetchAssetMetaFromMessengerOrEthereum(ctx, assetId, assetAddress, chain)
	if err != nil {
		return nil, nil, "", fmt.Errorf("node.fetchAssetMeta(%s) => %v", assetId, err)
	}

	addr := abi.GetFactoryAssetAddress(entry, assetId, asset.Symbol, asset.Name, holder)
	assetKey := strings.ToLower(addr.String())
	err = ethereum.VerifyAssetKey(assetKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("mvm.VerifyAssetKey(%s) => %v", assetKey, err)
	}

	bondId := ethereum.GenerateAssetId(keeper.SafeChainPolygon, assetKey)
	bond, err := node.fetchAssetMeta(ctx, bondId)
	return asset, bond, bondId, err
}

func (node *Node) checkOrDeployPolygonBond(ctx context.Context, entry string, chain byte, assetId, assetAddress, holder string) (bool, error) {
	asset, bond, _, err := node.fetchPolygonBondAsset(ctx, entry, chain, assetId, assetAddress, holder)
	if err != nil {
		return false, fmt.Errorf("node.fetchPolygonBondAsset(%s, %s) => %v", assetId, holder, err)
	}
	if bond != nil {
		return true, nil
	}
	rpc, key := node.conf.PolygonRPC, node.conf.MVMKey
	return false, abi.GetOrDeployFactoryAsset(rpc, key, assetId, asset.Symbol, asset.Name, entry, holder)
}

func (node *Node) deployPolygonBondAssets(ctx context.Context, safes []*store.Safe, receiver string) error {
	for _, safe := range safes {
		switch safe.Chain {
		case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
			_, assetId := node.bitcoinParams(safe.Chain)
			_, err := node.checkOrDeployPolygonBond(ctx, receiver, safe.Chain, assetId, "", safe.Holder)
			if err != nil {
				return err
			}
		case keeper.SafeChainEthereum, keeper.SafeChainPolygon:
			balances, err := node.keeperStore.ReadEthereumAllBalance(ctx, safe.Address)
			if err != nil {
				return err
			}
			for _, balance := range balances {
				_, err = node.checkOrDeployPolygonBond(ctx, receiver, safe.Chain, balance.AssetId, balance.AssetAddress, safe.Holder)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (node *Node) distributePolygonBondAsset(ctx context.Context, receiver string, safe *store.Safe, bond *Asset, amount decimal.Decimal) error {
	inputs, err := node.listOutputs(ctx, bond.AssetId, mixin.SafeUtxoStateUnspent)
	if err != nil || len(inputs) == 0 {
		return err
	}
	total := decimal.NewFromInt(0)
	for _, o := range inputs {
		total = total.Add(o.Amount)
	}

	traceId := common.UniqueId(bond.AssetId, safe.RequestId)
	crv := byte(common.CurveSecp256k1ECDSABitcoin)
	extra := gc.HexToAddress(receiver).Bytes()
	switch safe.Chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
		crv = common.CurveSecp256k1ECDSALitecoin
	case keeper.SafeChainEthereum:
		crv = common.CurveSecp256k1ECDSAEthereum
	case keeper.SafeChainMVM:
		crv = common.CurveSecp256k1ECDSAMVM
	case keeper.SafeChainPolygon:
		crv = common.CurveSecp256k1ECDSAPolygon
	default:
		panic(safe.Chain)
	}
	op := &common.Operation{
		Id:     traceId,
		Type:   common.ActionMigrateSafeToken,
		Curve:  crv,
		Public: safe.Holder,
		Extra:  extra,
	}
	memo := base64.RawURLEncoding.EncodeToString(op.Encode())
	if len(extra) > 160 {
		panic(fmt.Errorf("node.sendKeeperTransaction(%v) omitted %x", op, extra))
	}

	members := node.keeper.Genesis.Members
	threshold := node.keeper.Genesis.Threshold
	traceId = fmt.Sprintf("OBSERVER:%s:KEEPER:%v:%d", node.conf.App.AppId, members, threshold)
	traceId = node.safeTraceId(traceId, op.Id)
	b := mixin.NewSafeTransactionBuilder(inputs)
	b.Memo = memo
	b.Hint = traceId

	keeperShare := total.Sub(amount)
	if !keeperShare.IsPositive() {
		panic(keeperShare)
	}
	outputs := []*mixin.TransactionOutput{
		{
			Address: mixin.RequireNewMixAddress(node.keeper.Genesis.Members, byte(node.keeper.Genesis.Threshold)),
			Amount:  keeperShare,
		},
	}
	if amount.IsPositive() {
		outputs = append(outputs, &mixin.TransactionOutput{
			Address: mixin.RequireNewMixAddress(safe.Receivers, byte(safe.Threshold)),
			Amount:  amount,
		})
	}

	tx, err := node.mixin.MakeTransaction(ctx, b, outputs)
	if err != nil {
		return err
	}
	raw, err := tx.Dump()
	if err != nil {
		return err
	}
	req, err := common.CreateSafeTransactionRequest(ctx, node.mixin, traceId, raw)
	if err != nil {
		return err
	}
	_, err = common.SignMultisigUntilSufficient(ctx, node.mixin, req, []string{node.mixin.ClientID}, node.conf.App.SpendPrivateKey)
	return err
}

func (node *Node) distributePolygonBondAssets(ctx context.Context, safes []*store.Safe, receiver string) error {
	for {
		allHandled := true

		for _, safe := range safes {
			switch safe.Chain {
			case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
				_, assetId := node.bitcoinParams(safe.Chain)
				_, bond, _, err := node.fetchPolygonBondAsset(ctx, receiver, safe.Chain, assetId, "", safe.Holder)
				if err != nil {
					return err
				}
				if bond == nil {
					allHandled = false
					continue
				}
				outputs, err := node.keeperStore.ListAllBitcoinUTXOsForHolder(ctx, safe.Holder)
				if err != nil {
					return err
				}
				var total int64
				for _, o := range outputs {
					total += o.Satoshi
				}
				err = node.distributePolygonBondAsset(ctx, receiver, safe, bond, decimal.NewFromInt(total).Div(decimal.New(1, 8)))
				if err != nil {
					return err
				}
			case keeper.SafeChainEthereum, keeper.SafeChainPolygon:
				balances, err := node.keeperStore.ReadEthereumAllBalance(ctx, safe.Address)
				if err != nil {
					return err
				}
				handled := true
				for _, balance := range balances {
					_, bond, _, err := node.fetchPolygonBondAsset(ctx, receiver, safe.Chain, balance.AssetId, balance.AssetAddress, safe.Holder)
					if err != nil {
						return err
					}
					if bond == nil {
						handled = false
						break
					}
					amt := decimal.NewFromBigInt(balance.Balance, -int32(bond.Decimals))
					err = node.distributePolygonBondAsset(ctx, receiver, safe, bond, amt)
					if err != nil {
						return err
					}
				}
				if !handled {
					allHandled = false
				}
			}
		}

		if allHandled {
			return nil
		}

		time.Sleep(1 * time.Minute)
	}
}

func (s *SQLite3Store) UpdateDb(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	key, val := "SCHEMA:VERSION:migration", ""
	row := tx.QueryRowContext(ctx, "SELECT value FROM properties WHERE key=?", key)
	err = row.Scan(&val)
	if err == nil {
		return nil
	} else if err != sql.ErrNoRows {
		return err
	}

	query := "ALTER TABLE accounts ADD COLUMN approved BOOLEAN;\n"
	query = query + "ALTER TABLE accounts ADD COLUMN signature VARCHAR;\n"
	_, err = tx.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "UPDATE accounts SET approved=?, signature=?", false, "")
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "INSERT INTO properties (key, value, created_at) VALUES (?, ?, ?)", key, query, now)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (node *Node) migrate(ctx context.Context) error {
	err := node.store.UpdateDb(ctx)
	if err != nil {
		return err
	}

	entry, err := node.fetchDepositEntry(ctx)
	if err != nil {
		return fmt.Errorf("node.fetchDepositEntry() => %v", err)
	}
	safes, err := node.keeperStore.ListSafesWithState(ctx, common.RequestStateDone)
	if err != nil {
		return err
	}
	for _, safe := range safes {
		err := node.store.MarkAccountApproved(ctx, safe.Address)
		if err != nil {
			return err
		}
	}

	err = node.deployPolygonBondAssets(ctx, safes, entry)
	if err != nil {
		return err
	}

	return node.distributePolygonBondAssets(ctx, safes, entry)
}
