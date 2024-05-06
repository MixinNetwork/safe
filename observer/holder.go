package observer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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
	"github.com/MixinNetwork/safe/keeper"
	gc "github.com/ethereum/go-ethereum/common"
	"github.com/gofrs/uuid/v5"
)

func (node *Node) getSafeStatus(ctx context.Context, proposalId string) (string, error) {
	sp, err := node.keeperStore.ReadSafeProposal(ctx, proposalId)
	if err != nil || sp == nil {
		return "", err
	}
	safe, err := node.keeperStore.ReadSafeByAddress(ctx, sp.Address)
	if err != nil || safe == nil {
		return "proposed", err
	}
	if int(safe.State) == common.RequestStateFailed {
		return "failed", nil
	}
	return "approved", nil
}

func (node *Node) keeperSaveAccountProposal(ctx context.Context, chain byte, extra []byte, createdAt time.Time) error {
	logger.Printf("node.keeperSaveAccountProposal(%d, %x, %s)", chain, extra, createdAt)
	var address string
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		wsa, err := bitcoin.UnmarshalWitnessScriptAccount(extra)
		if err != nil {
			return err
		}
		address = wsa.Address
	case keeper.SafeChainEthereum, keeper.SafeChainMVM, keeper.SafeChainPolygon:
		gs, err := ethereum.UnmarshalGnosisSafe(extra)
		if err != nil {
			return err
		}
		address = gs.Address
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, address)
	if err != nil {
		return err
	}
	if sp.Chain != chain {
		return fmt.Errorf("inconsistent chain between SafeProposal and keeper response: %d, %d", sp.Chain, chain)
	}

	var assetId string
	switch sp.Chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		_, assetId = node.bitcoinParams(sp.Chain)
	case keeper.SafeChainEthereum, keeper.SafeChainMVM, keeper.SafeChainPolygon:
		_, assetId = node.ethereumParams(sp.Chain)
	}
	_, err = node.checkOrDeployKeeperBond(ctx, chain, assetId, "", sp.Holder)
	logger.Printf("node.checkOrDeployKeeperBond(%s, %s) => %v", assetId, sp.Holder, err)
	if err != nil {
		return err
	}
	return node.store.WriteAccountProposalIfNotExists(ctx, sp.Address, createdAt)
}

func (node *Node) keeperSaveTransactionProposal(ctx context.Context, chain byte, extra []byte, createdAt time.Time) error {
	logger.Printf("node.keeperSaveTransactionProposal(%x, %s)", extra, createdAt)
	var txHash string
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		psbt, _ := bitcoin.UnmarshalPartiallySignedTransaction(extra)
		txHash = psbt.UnsignedTx.TxHash().String()
	case keeper.SafeChainEthereum, keeper.SafeChainMVM, keeper.SafeChainPolygon:
		t, _ := ethereum.UnmarshalSafeTransaction(extra)
		txHash = t.TxHash
	}
	tx, err := node.keeperStore.ReadTransaction(ctx, txHash)
	if err != nil {
		return err
	}
	safe, err := node.keeperStore.ReadSafe(ctx, tx.Holder)
	if err != nil {
		return err
	}
	approval := &Transaction{
		TransactionHash: txHash,
		RawTransaction:  hex.EncodeToString(extra),
		Chain:           safe.Chain,
		Holder:          tx.Holder,
		Signer:          safe.Signer,
		State:           common.RequestStateInitial,
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}
	return node.store.WriteTransactionApprovalIfNotExists(ctx, approval)
}

func (node *Node) httpApproveSafeAccount(ctx context.Context, addr, signature string) error {
	logger.Printf("node.httpApproveSafeAccount(%s, %s)", addr, signature)
	proposed, err := node.store.CheckAccountProposed(ctx, addr)
	if err != nil || !proposed {
		return err
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, addr)
	if err != nil {
		return err
	}

	var sig []byte
	switch sp.Chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		sig, err = base64.RawURLEncoding.DecodeString(signature)
		if err != nil {
			return err
		}
		ms := fmt.Sprintf("APPROVE:%s:%s", sp.RequestId, sp.Address)
		hash := bitcoin.HashMessageForSignature(ms, sp.Chain)
		err = bitcoin.VerifySignatureDER(sp.Holder, hash, sig)
		logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", sp, err)
		if err != nil {
			return err
		}
	case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
		sig, err = hex.DecodeString(signature)
		if err != nil {
			return err
		}
		gs, err := ethereum.UnmarshalGnosisSafe(sp.Extra)
		logger.Printf("ethereum.UnmarshalGnosisSafe(%s) => %v %v", hex.EncodeToString(sp.Extra), gs, err)
		if err != nil {
			return err
		}
		tx, err := node.keeperStore.ReadTransaction(ctx, gs.TxHash)
		logger.Printf("keeperStore.ReadTransaction(%s) => %v %v", gs.TxHash, tx, err)
		if err != nil {
			return err
		}
		raw, err := hex.DecodeString(tx.RawTransaction)
		if err != nil {
			return err
		}
		st, err := ethereum.UnmarshalSafeTransaction(raw)
		logger.Printf("ethereum.UnmarshalSafeTransaction(%s) => %v %v", tx.RawTransaction, st, err)
		if err != nil {
			return err
		}
		err = ethereum.VerifyMessageSignature(sp.Holder, st.Message, sig)
		logger.Printf("ethereum.VerifyMessageSignature(%s %s %s) => %v", sp.Holder, hex.EncodeToString(st.Message), hex.EncodeToString(sig), err)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	return node.saveAccountApprovalSignature(ctx, sp.Address, signature)
}

func (node *Node) httpCreateSafeAccountRecoveryRequest(ctx context.Context, addr, raw, hash string) error {
	logger.Printf("node.httpCreateAccountRecoveryRequest(%s, %s, %s)", addr, raw, hash)
	if hash == "" || raw == "" {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	proposed, err := node.store.CheckAccountProposed(ctx, addr)
	if err != nil || !proposed {
		return err
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, addr)
	if err != nil {
		return err
	}
	safe, err := node.keeperStore.ReadSafe(ctx, sp.Holder)
	if err != nil {
		return err
	}
	if safe == nil || safe.State != common.RequestStateDone {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	switch safe.Chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		return node.httpCreateBitcoinAccountRecoveryRequest(ctx, safe, raw, hash)
	case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
		return node.httpCreateEthereumAccountRecoveryRequest(ctx, safe, raw, hash)
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
}

func (node *Node) httpSignAccountRecoveryRequest(ctx context.Context, addr, raw, hash string) error {
	logger.Printf("node.httpSignAccountRecoveryRequest(%s, %s, %s)", addr, raw, hash)
	proposed, err := node.store.CheckAccountProposed(ctx, addr)
	if err != nil || !proposed {
		return err
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, addr)
	if err != nil {
		return err
	}
	safe, err := node.keeperStore.ReadSafe(ctx, sp.Holder)
	if err != nil {
		return err
	}
	if safe == nil || safe.State != common.RequestStateDone {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	r, err := node.store.ReadRecovery(ctx, safe.Address)
	if err != nil {
		return err
	}
	if r == nil || r.State != common.RequestStateInitial {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
	if r.TransactionHash != hash {
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}

	switch safe.Chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		return node.httpSignBitcoinAccountRecoveryRequest(ctx, safe, raw, hash)
	case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
		return node.httpSignEthereumAccountRecoveryRequest(ctx, safe, raw, hash)
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
}

func (node *Node) httpApproveSafeTransaction(ctx context.Context, chain byte, raw string) error {
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		return node.httpApproveBitcoinTransaction(ctx, raw)
	case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
		return node.httpApproveEthereumTransaction(ctx, raw)
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
}

func (node *Node) httpRevokeSafeTransaction(ctx context.Context, chain byte, hash, sig string) error {
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		return node.httpRevokeBitcoinTransaction(ctx, hash, sig)
	case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
		return node.httpRevokeEthereumTransaction(ctx, hash, sig)
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
}

func (node *Node) holderPayTransactionApproval(ctx context.Context, chain byte, hash string) error {
	logger.Printf("node.holderPayTransactionApproval(%s)", hash)
	approval, err := node.store.ReadTransactionApproval(ctx, hash)
	logger.Printf("store.ReadTransactionApproval(%s) => %v %v", hash, approval, err)
	if err != nil || approval == nil {
		return err
	}
	if approval.State != common.RequestStateInitial {
		return nil
	}
	safe, err := node.keeperStore.ReadSafe(ctx, approval.Holder)
	logger.Printf("store.ReadSafe(%s) => %v %v", approval.Holder, safe, err)
	if err != nil {
		return err
	}
	var signedByHolder, signedByObserver bool
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		signedByHolder = bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, safe.Holder)
		opk, err := node.deriveBIP32WithKeeperPath(ctx, safe.Observer, safe.Path)
		if err != nil {
			panic(err)
		}
		signedByObserver = bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, opk)
	case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
		signedByHolder = ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, safe.Holder)
		signedByObserver = ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, safe.Observer)
	}
	if !signedByHolder && !signedByObserver {
		return nil
	}
	return node.store.MarkTransactionApprovalPaid(ctx, hash)
}

func (deposit *Deposit) encodeKeeperExtra(decimals int32) []byte {
	txHash := strings.TrimPrefix(deposit.TransactionHash, "0x")
	hash, err := crypto.HashFromString(txHash)
	if err != nil {
		panic(txHash)
	}

	extra := []byte{deposit.Chain}
	extra = append(extra, uuid.Must(uuid.FromString(deposit.AssetId)).Bytes()...)
	extra = append(extra, hash[:]...)
	switch deposit.Chain {
	case keeper.SafeChainEthereum, keeper.SafeChainMVM, keeper.SafeChainPolygon:
		extra = append(extra, gc.HexToAddress(deposit.AssetAddress).Bytes()...)
	}
	extra = binary.BigEndian.AppendUint64(extra, uint64(deposit.OutputIndex))
	extra = append(extra, deposit.bigAmount(decimals).Bytes()...)
	return extra
}

func (d *Deposit) bigAmount(decimals int32) *big.Int {
	switch d.Chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		if decimals != bitcoin.ValuePrecision {
			panic(decimals)
		}
		satoshi := bitcoin.ParseSatoshi(d.Amount)
		return new(big.Int).SetInt64(satoshi)
	case keeper.SafeChainMVM, keeper.SafeChainPolygon, keeper.SafeChainEthereum:
		return ethereum.ParseAmount(d.Amount, decimals)
	}
	panic(0)
}
