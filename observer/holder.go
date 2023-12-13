package observer

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	gc "github.com/ethereum/go-ethereum/common"
	"github.com/fox-one/mixin-sdk-go"
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
	case keeper.SafeChainEthereum, keeper.SafeChainMVM:
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
	case keeper.SafeChainEthereum, keeper.SafeChainMVM:
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
	case keeper.SafeChainEthereum, keeper.SafeChainMVM:
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

func (node *Node) httpApproveSafeAccount(ctx context.Context, addr, sigBase64 string) error {
	logger.Printf("node.httpApproveSafeAccount(%s, %s)", addr, sigBase64)
	proposed, err := node.store.CheckAccountProposed(ctx, addr)
	if err != nil || !proposed {
		return err
	}
	sp, err := node.keeperStore.ReadSafeProposalByAddress(ctx, addr)
	if err != nil {
		return err
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		return err
	}
	var action int
	switch sp.Chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		action = common.ActionBitcoinSafeApproveAccount
		ms := fmt.Sprintf("APPROVE:%s:%s", sp.RequestId, sp.Address)
		hash := bitcoin.HashMessageForSignature(ms, sp.Chain)
		err = bitcoin.VerifySignatureDER(sp.Holder, hash, sig)
		logger.Printf("bitcoin.VerifySignatureDER(%v) => %v", sp, err)
		if err != nil {
			return err
		}
	case keeper.SafeChainMVM:
		action = common.ActionEthereumSafeApproveAccount
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

	id := mixin.UniqueConversationID(addr, sigBase64)
	rid := uuid.Must(uuid.FromString(sp.RequestId))
	extra := append(rid.Bytes(), sig...)
	return node.sendKeeperResponse(ctx, sp.Holder, byte(action), sp.Chain, id, extra)
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
	case keeper.SafeChainMVM:
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
	case keeper.SafeChainMVM:
		return node.httpSignEthereumAccountRecoveryRequest(ctx, safe, raw, hash)
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
}

func (node *Node) httpApproveSafeTransaction(ctx context.Context, chain byte, raw string) error {
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		return node.httpApproveBitcoinTransaction(ctx, raw)
	case keeper.SafeChainMVM:
		return node.httpApproveEthereumTransaction(ctx, raw)
	default:
		return fmt.Errorf("HTTP: %d", http.StatusNotAcceptable)
	}
}

func (node *Node) httpRevokeSafeTransaction(ctx context.Context, chain byte, hash, sigBase64 string) error {
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		return node.httpRevokeBitcoinTransaction(ctx, hash, sigBase64)
	case keeper.SafeChainMVM:
		return node.httpRevokeEthereumTransaction(ctx, hash, sigBase64)
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
	switch chain {
	case keeper.SafeChainBitcoin, keeper.SafeChainLitecoin:
		if !bitcoin.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
			return nil
		}
	case keeper.SafeChainMVM:
		if !ethereum.CheckTransactionPartiallySignedBy(approval.RawTransaction, approval.Holder) {
			return nil
		}
	}
	return node.store.MarkTransactionApprovalPaid(ctx, hash)
}

func (deposit *Deposit) encodeKeeperExtra(decimals int32) []byte {
	hash, err := crypto.HashFromString(deposit.TransactionHash)
	if err != nil {
		panic(deposit.TransactionHash)
	}

	extra := []byte{deposit.Chain}
	extra = append(extra, uuid.Must(uuid.FromString(deposit.AssetId)).Bytes()...)
	extra = append(extra, hash[:]...)
	extra = append(extra, gc.HexToAddress(deposit.AssetAddress).Bytes()...)
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
	case keeper.SafeChainMVM, keeper.SafeChainEthereum:
		return ethereum.ParseAmount(d.Amount, decimals)
	}
	panic(0)
}
