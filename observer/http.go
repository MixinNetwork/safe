package observer

// FIXME do rate limit based on IP

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/apps/ethereum"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/dimfeld/httptreemux/v5"
)

//go:embed assets/favicon.ico
var FAVICON []byte

var GUIDE = `
<!DOCTYPE html>
<html class="layout">
  <head>
    <meta charset="utf-8" />
    <title>Mixin Safe Developers</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="description" content="Mixin Safe is an advanced non-custody solution for securing BTC using the native Bitcoin multisig and timelock script. The 2/3 multisig comprises three keys: the holder, signer, and observer. The BTC locked in the script can only be spent when the holder and signer keys sign a transaction, provided that the timelock of one year is in effect. In the event of key loss by the holder or signer, the observer can act as rescuer after one year.">
    <link href="/favicon.ico" rel="shortcut icon" type="image/vnd.microsoft.icon" />
		<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
      body {
        margin: 0;
        padding: 8px 16px;
      }
      article {
        max-width: 960px;
        margin: 32px auto 64px;
        font-family: sans-serif;
        font-size: 1em;
        font-weight: 300;
      }
      h1 {
        font-size: 2em;
        font-weight: 500;
      }
      h2 {
        font-size: 1.5em;
        font-weight: 500;
        margin: 24px 0 16px;
      }
      img {
        max-width: 100%;
      }
      pre, code {
        background: #F4F4F4;
        font-family: monospace;
        font-size: 1em;
      }
      pre {
        padding: 8px;
        border-radius: 4px;
      }
      pre code {
        overflow-wrap: break-word;
        white-space: pre-wrap;
      }
      p {
        overflow-wrap: break-word;
        line-height: 1.4em;
      }
    </style>
  </head>
  <body>
    <article style="display:none">README</article>
    <script>
      var article = document.getElementsByTagName('article')[0];
      article.innerHTML = marked.parse(article.childNodes[0].nodeValue);
      article.style="display:block";
    </script>
  </body>
</html>
`

func (node *Node) StartHTTP(readme string) {
	GUIDE = strings.TrimSpace(strings.Replace(GUIDE, "README", readme, -1))

	router := httptreemux.New()
	router.PanicHandler = common.HandlePanic
	router.NotFoundHandler = common.HandleNotFound

	router.GET("/", node.httpIndex)
	router.GET("/favicon.ico", node.httpFavicon)
	router.GET("/chains", node.httpListChains)
	router.GET("/deposits", node.httpListDeposits)
	router.GET("/recoveries", node.httpListRecoveries)
	router.GET("/recoveries/:id", node.httpGetRecovery)
	router.POST("/recoveries/:id", node.httpSignRecovery)
	router.GET("/accounts/:id", node.httpGetAccount)
	router.POST("/accounts/:id", node.httpApproveAccount)
	router.GET("/transactions/:id", node.httpGetTransaction)
	router.POST("/transactions/:id", node.httpApproveTransaction)
	router.GET("/keys/:public", node.httpGetCustomKey)
	handler := common.HandleCORS(router)
	err := http.ListenAndServe(fmt.Sprintf(":%d", 7080), handler)
	if err != nil {
		panic(err)
	}
}

func (node *Node) httpIndex(w http.ResponseWriter, r *http.Request, params map[string]string) {
	if r.Host == "safe.mixin.dev" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(GUIDE))
		return
	}

	plan, err := node.keeperStore.ReadLatestOperationParams(r.Context(), common.SafeChainBitcoin, time.Now())
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	common.RenderJSON(w, r, http.StatusOK, map[string]any{
		"version":  "0.12.1",
		"observer": node.conf.App.AppId,
		"bond": map[string]any{
			"chain":    137,
			"contract": node.conf.PolygonFactoryAddress,
		},
		"keeper": map[string]any{
			"members":   node.keeper.Genesis.Members,
			"threshold": node.keeper.Genesis.Threshold,
		},
		"params": map[string]any{
			"operation": map[string]any{
				"asset": plan.OperationPriceAsset,
				"price": plan.OperationPriceAmount.String(),
			},
			"transaction": map[string]any{
				"minimum": plan.TransactionMinimum.String(),
			},
		},
	})
}

func (node *Node) httpFavicon(w http.ResponseWriter, r *http.Request, params map[string]string) {
	w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
	w.WriteHeader(http.StatusOK)
	w.Write(FAVICON)
}

func (node *Node) httpListChains(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var cs []map[string]any
	for _, c := range []byte{common.SafeChainBitcoin, common.SafeChainLitecoin, common.SafeChainPolygon, common.SafeChainEthereum} {
		info, err := node.keeperStore.ReadLatestNetworkInfo(r.Context(), c, time.Now())
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
		if info == nil {
			continue
		}
		ckp, err := node.readDepositCheckpoint(r.Context(), c)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
		id := common.SafeChainAssetId(c)
		head := make(map[string]any)
		head["id"] = info.RequestId
		head["height"] = info.Height
		head["fee"] = info.Fee
		head["hash"] = info.Hash
		head["created_at"] = info.CreatedAt
		chain := make(map[string]any)
		chain["id"] = id
		chain["chain"] = c
		chain["head"] = head
		chain["deposit"] = map[string]any{
			"checkpoint": ckp,
		}
		switch c {
		case common.SafeChainBitcoin, common.SafeChainLitecoin:
			c, s, err := node.readChainAccountantBalance(r.Context(), int(c))
			if err != nil {
				common.RenderError(w, r, err)
				return
			}
			outputs := make(map[string]any)
			outputs["count"] = c
			outputs["satoshi"] = s
			accountant := make(map[string]any)
			accountant["outputs"] = outputs
			chain["accountant"] = accountant
		case common.SafeChainEthereum, common.SafeChainPolygon:
			addr, err := ethereum.PrivToAddress(node.conf.EVMKey)
			if err != nil {
				common.RenderError(w, r, err)
				return
			}
			chain["sender"] = addr
		}
		cs = append(cs, chain)
	}
	common.RenderJSON(w, r, http.StatusOK, cs)
}

func (node *Node) httpListDeposits(w http.ResponseWriter, r *http.Request, params map[string]string) {
	holder := r.URL.Query().Get("holder")
	chain, _ := strconv.ParseInt(r.URL.Query().Get("chain"), 10, 64)
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	deposits, err := node.store.ListDeposits(r.Context(), int(chain), holder, common.RequestStateDone, offset)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	sent, err := node.store.QueryDepositSentHashes(r.Context(), deposits)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}

	common.RenderJSON(w, r, http.StatusOK, node.viewDeposits(r.Context(), deposits, sent))
}

func (node *Node) httpListRecoveries(w http.ResponseWriter, r *http.Request, params map[string]string) {
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	rs, err := node.store.ListInitialRecoveries(r.Context(), offset)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}

	common.RenderJSON(w, r, http.StatusOK, node.viewRecoveries(r.Context(), rs))
}

func (node *Node) httpGetRecovery(w http.ResponseWriter, r *http.Request, params map[string]string) {
	safe, _, err := node.readSafeProposalOrRequest(r.Context(), params["id"])
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if safe == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "safe"})
		return
	}
	recovery, err := node.store.ReadRecovery(r.Context(), safe.Address)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if recovery == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "recovery"})
		return
	}

	resp := map[string]any{
		"address":    recovery.Address,
		"chain":      recovery.Chain,
		"holder":     recovery.Holder,
		"observer":   recovery.Observer,
		"raw":        recovery.RawTransaction,
		"hash":       recovery.TransactionHash,
		"state":      recovery.getState(),
		"created_at": recovery.CreatedAt,
		"updated_at": recovery.UpdatedAt,
	}

	approval, err := node.store.ReadTransactionApproval(r.Context(), recovery.TransactionHash)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if approval != nil && approval.SpentRaw.Valid {
		resp["hash"] = approval.SpentHash.String
		resp["raw"] = approval.SpentRaw.String
		resp["state"] = "spent"
	}

	common.RenderJSON(w, r, http.StatusOK, resp)
}

func (node *Node) httpGetAccount(w http.ResponseWriter, r *http.Request, params map[string]string) {
	safe, req, err := node.readSafeProposalOrRequest(r.Context(), params["id"])
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if req != nil && req.State == common.RequestStateFailed {
		common.RenderJSON(w, r, http.StatusOK, map[string]any{
			"id":    req.Id,
			"state": common.StateName(int(req.State)),
		})
		return
	}
	if safe == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "safe"})
		return
	}
	proposed, err := node.store.CheckAccountProposed(r.Context(), safe.Address)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if !proposed {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "proposed"})
		return
	}

	node.renderAccount(r.Context(), w, r, safe)
}

func (node *Node) httpApproveAccount(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var body struct {
		Action    string `json:"action"`
		Address   string `json:"address"`
		Signature string `json:"signature"`
		Raw       string `json:"raw"`
		Hash      string `json:"hash"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	safe, err := node.keeperStore.ReadSafeProposal(r.Context(), params["id"])
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if safe == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "safe"})
		return
	}
	if safe.Address != body.Address {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": "address"})
		return
	}

	switch body.Action {
	case "approve":
		proposed, err := node.store.CheckAccountProposed(r.Context(), safe.Address)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
		if !proposed {
			common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "proposed"})
			return
		}
		err = node.httpApproveSafeAccount(r.Context(), body.Address, body.Signature)
		if err != nil {
			common.RenderJSON(w, r, http.StatusUnprocessableEntity, map[string]any{"error": err})
			return
		}
	case "close":
		err = node.httpCreateSafeAccountRecoveryRequest(r.Context(), body.Address, body.Raw, body.Hash)
		if err != nil {
			common.RenderJSON(w, r, http.StatusUnprocessableEntity, map[string]any{"error": err})
			return
		}
	default:
		common.RenderJSON(w, r, http.StatusUnprocessableEntity, map[string]any{"error": "action"})
		return
	}

	node.renderAccount(r.Context(), w, r, safe)
}

func (node *Node) httpSignRecovery(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var body struct {
		Raw  string `json:"raw"`
		Hash string `json:"hash"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	safe, err := node.keeperStore.ReadSafeProposalByAddress(r.Context(), params["id"])
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if safe == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "safe"})
		return
	}
	if body.Hash == "" {
		common.RenderJSON(w, r, http.StatusNotAcceptable, map[string]any{"error": "hash"})
		return
	}
	if body.Raw == "" {
		common.RenderJSON(w, r, http.StatusNotAcceptable, map[string]any{"error": "raw"})
		return
	}

	err = node.httpSignAccountRecoveryRequest(r.Context(), safe.Address, body.Raw, body.Hash)
	if err != nil {
		common.RenderJSON(w, r, http.StatusUnprocessableEntity, map[string]any{"error": err})
		return
	}

	node.renderAccount(r.Context(), w, r, safe)
}

func (node *Node) httpGetTransaction(w http.ResponseWriter, r *http.Request, params map[string]string) {
	tx, req, err := node.readTransactionOrRequest(r.Context(), params["id"])
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if req != nil && req.State == common.RequestStateFailed {
		common.RenderJSON(w, r, http.StatusOK, map[string]any{
			"id":    req.Id,
			"state": common.StateName(int(req.State)),
		})
		return
	}
	if tx == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "transaction"})
		return
	}
	approval, err := node.store.ReadTransactionApproval(r.Context(), tx.TransactionHash)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if approval == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "approval"})
		return
	}
	safe, err := node.keeperStore.ReadSafe(r.Context(), tx.Holder)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if safe == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "safe"})
		return
	}

	data := map[string]any{
		"chain":   tx.Chain,
		"id":      tx.RequestId,
		"hash":    tx.TransactionHash,
		"raw":     approval.RawTransaction,
		"signers": approval.Signers(r.Context(), node, safe),
		"state":   common.StateName(tx.State),
	}
	if approval.SpentRaw.Valid {
		data["hash"] = approval.SpentHash.String
		data["raw"] = approval.SpentRaw.String
		data["state"] = "spent"
	}
	common.RenderJSON(w, r, http.StatusOK, data)
}

func (node *Node) httpApproveTransaction(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var body struct {
		Chain     int    `json:"chain"`
		Action    string `json:"action"`
		Raw       string `json:"raw"`
		Signature string `json:"signature"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	tx, err := node.keeperStore.ReadTransactionByRequestId(r.Context(), params["id"])
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if tx == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "transaction"})
		return
	}
	approval, err := node.store.ReadTransactionApproval(r.Context(), tx.TransactionHash)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if approval == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "approval"})
		return
	}
	if approval.State != common.RequestStateInitial {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": "state"})
		return
	}
	safe, err := node.keeperStore.ReadSafe(r.Context(), tx.Holder)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if safe == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "safe"})
		return
	}

	switch body.Action {
	case "approve":
		err = node.httpApproveSafeTransaction(r.Context(), byte(body.Chain), body.Raw)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
	case "revoke":
		err = node.httpRevokeSafeTransaction(r.Context(), byte(body.Chain), tx.TransactionHash, body.Signature)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
	default:
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": "chain"})
		return
	}

	data := map[string]any{
		"chain":   tx.Chain,
		"id":      tx.RequestId,
		"hash":    tx.TransactionHash,
		"raw":     approval.RawTransaction,
		"signers": approval.Signers(r.Context(), node, safe),
		"state":   common.StateName(tx.State),
	}
	if approval.SpentRaw.Valid {
		data["hash"] = approval.SpentHash.String
		data["raw"] = approval.SpentRaw.String
		data["state"] = "spent"
	}
	common.RenderJSON(w, r, http.StatusOK, data)
}

func (node *Node) httpGetCustomKey(w http.ResponseWriter, r *http.Request, params map[string]string) {
	key, err := node.keeperStore.ReadKey(r.Context(), params["public"])
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if key == nil || key.Role != common.RequestRoleObserver || key.Flags != common.RequestFlagCustomObserverKey {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "key"})
		return
	}
	data := map[string]any{
		"id":         key.RequestId,
		"public":     key.Public,
		"curve":      key.Curve,
		"extra":      key.Extra,
		"holder":     key.Holder.String,
		"created_at": key.CreatedAt,
	}
	switch key.Role {
	case common.RequestRoleObserver:
		data["role"] = "observer"
	default:
		panic(key.Role)
	}
	common.RenderJSON(w, r, http.StatusOK, data)
}

func (node *Node) viewSafeXPubs(ctx context.Context, safe *store.SafeProposal) []string {
	pubs := make([]string, 2)
	for i, k := range []string{safe.Signer, safe.Observer} {
		key, _ := node.keeperStore.ReadKey(ctx, k)
		chainCode := common.DecodeHexOrPanic(key.Extra)
		xpub, pub, err := bitcoin.DeriveBIP32(key.Public, chainCode)
		if err != nil || pub != key.Public {
			panic(k)
		}
		finger := btcutil.Hash160(common.DecodeHexOrPanic(key.Public))[:4]
		pubs[i] = fmt.Sprintf("[%x]%s", finger, xpub)
	}
	return pubs
}

func (node *Node) buildBitcoinWitnessAccountWithDerivation(ctx context.Context, safe *store.SafeProposal) (*bitcoin.WitnessScriptAccount, error) {
	sdk, err := node.deriveBIP32WithKeeperPath(ctx, safe.Signer, safe.Path)
	if err != nil {
		return nil, fmt.Errorf("bitcoin.DeriveBIP32(%s) => %v", safe.Signer, err)
	}
	odk, err := node.deriveBIP32WithKeeperPath(ctx, safe.Observer, safe.Path)
	if err != nil {
		return nil, fmt.Errorf("bitcoin.DeriveBIP32(%s) => %v", safe.Observer, err)
	}
	return bitcoin.BuildWitnessScriptAccount(safe.Holder, sdk, odk, safe.Timelock, safe.Chain)
}

func (node *Node) readChainAccountantBalance(ctx context.Context, chain int) (uint64, uint64, error) {
	query := "SELECT SUM(satoshi),COUNT(*) FROM bitcoin_outputs WHERE chain=? AND state=?"
	row := node.store.db.QueryRowContext(ctx, query, chain, common.RequestStateInitial)

	var count, satoshi sql.NullInt64
	err := row.Scan(&satoshi, &count)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return uint64(count.Int64), uint64(satoshi.Int64), err
}

func (node *Node) readSafeProposalOrRequest(ctx context.Context, id string) (*store.SafeProposal, *common.Request, error) {
	sp, err := node.keeperStore.ReadSafeProposal(ctx, id)
	if err != nil || sp != nil {
		return sp, nil, err
	}
	req, err := node.keeperStore.ReadRequest(ctx, id)
	return nil, req, err
}

func (node *Node) readTransactionOrRequest(ctx context.Context, id string) (*store.Transaction, *common.Request, error) {
	tx, err := node.keeperStore.ReadTransactionByRequestId(ctx, id)
	if err != nil || tx != nil {
		return tx, nil, err
	}
	req, err := node.keeperStore.ReadRequest(ctx, id)
	return nil, req, err
}

func (node *Node) listAllBitcoinUTXOsForHolder(ctx context.Context, holder string) ([]*bitcoin.Input, error) {
	safe, err := node.keeperStore.ReadSafe(ctx, holder)
	if err != nil || safe == nil {
		return nil, err
	}
	return node.keeperStore.ListAllBitcoinUTXOsForHolder(ctx, holder)
}

func (node *Node) listPendingBitcoinUTXOsForHolder(ctx context.Context, holder string) ([]*bitcoin.Input, error) {
	safe, err := node.keeperStore.ReadSafe(ctx, holder)
	if err != nil || safe == nil {
		return nil, err
	}
	return node.keeperStore.ListPendingBitcoinUTXOsForHolder(ctx, holder)
}

func (node *Node) viewDeposits(ctx context.Context, deposits []*Deposit, sent map[string]string) []map[string]any {
	view := make([]map[string]any, 0)
	for _, d := range deposits {
		dm := map[string]any{
			"transaction_hash": d.TransactionHash,
			"output_index":     d.OutputIndex,
			"asset_id":         d.AssetId,
			"amount":           d.Amount,
			"sender":           d.Sender,
			"receiver":         d.Receiver,
			"sent_hash":        sent[d.TransactionHash],
			"chain":            d.Chain,
			"change":           false,
			"updated_at":       d.UpdatedAt,
			"created_at":       d.CreatedAt,
		}
		if dm["sent_hash"] == "" {
			dm["sent_hash"] = d.TransactionHash
		} else {
			switch d.Chain {
			case common.SafeChainBitcoin, common.SafeChainLitecoin:
				dm["change"] = node.bitcoinCheckDepositChange(ctx, d.TransactionHash, d.OutputIndex, sent[d.TransactionHash])
			}
		}
		view = append(view, dm)
	}
	return view
}

func (node *Node) viewRecoveries(ctx context.Context, recoveries []*Recovery) []map[string]any {
	view := make([]map[string]any, 0)
	for _, r := range recoveries {
		rm := map[string]any{
			"address":    r.Address,
			"chain":      r.Chain,
			"holder":     r.Holder,
			"observer":   r.Observer,
			"raw":        r.RawTransaction,
			"hash":       r.TransactionHash,
			"state":      r.getState(),
			"created_at": r.CreatedAt,
			"updated_at": r.UpdatedAt,
		}
		view = append(view, rm)
	}
	return view
}

func viewOutputs(outputs []*bitcoin.Input) []map[string]any {
	view := make([]map[string]any, 0)
	for _, out := range outputs {
		view = append(view, map[string]any{
			"transaction_hash": out.TransactionHash,
			"output_index":     out.Index,
			"satoshi":          out.Satoshi,
			"script":           hex.EncodeToString(out.Script),
			"sequence":         out.Sequence,
		})
	}
	return view
}

type AssetBalance struct {
	AssetAddress string `json:"asset_address"`
	Amount       string `json:"amount"`
	SafeAssetId  string `json:"safe_asset_id"`
}

func viewBalances(bs []*store.SafeBalance, txs []*store.Transaction) (map[string]*AssetBalance, map[string]*AssetBalance) {
	pendingBalances := viewPendingBalances(txs)

	assetBalance := make(map[string]*AssetBalance, 0)
	for _, b := range bs {
		amount := b.BigBalance()
		balance := pendingBalances[b.AssetId]
		if balance != nil {
			pending, _ := new(big.Int).SetString(balance.Amount, 10)
			amount = new(big.Int).Sub(amount, pending)
			pendingBalances[b.AssetId].SafeAssetId = b.SafeAssetId
		}
		if amount.Cmp(big.NewInt(0)) < 1 {
			continue
		}
		assetBalance[b.AssetId] = &AssetBalance{
			Amount:       amount.String(),
			AssetAddress: b.AssetAddress,
			SafeAssetId:  b.SafeAssetId,
		}
	}
	return assetBalance, pendingBalances
}

func viewPendingBalances(txs []*store.Transaction) map[string]*AssetBalance {
	assetBalance := make(map[string]*AssetBalance)
	for _, tx := range txs {
		raw := common.DecodeHexOrPanic(tx.RawTransaction)
		st, _ := ethereum.UnmarshalSafeTransaction(raw)
		chainAssetId := ethereum.GetMixinChainID(int64(tx.Chain))

		outputs := st.ExtractOutputs()
		for _, out := range outputs {
			assetId := chainAssetId
			if out.TokenAddress != ethereum.EthereumEmptyAddress {
				assetId = ethereum.GenerateAssetId(tx.Chain, out.TokenAddress)
			}
			amount := out.Amount
			if amount.Cmp(big.NewInt(0)) < 1 {
				continue
			}

			balance := assetBalance[assetId]
			if balance != nil {
				old, _ := new(big.Int).SetString(balance.Amount, 10)
				amount = new(big.Int).Add(amount, old)
			}
			assetBalance[assetId] = &AssetBalance{
				Amount:       amount.String(),
				AssetAddress: out.TokenAddress,
			}
		}
	}

	return assetBalance
}

func (node *Node) renderAccount(ctx context.Context, w http.ResponseWriter, r *http.Request, sp *store.SafeProposal) {
	status, err := node.getSafeStatus(ctx, sp.RequestId)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	safe, err := node.keeperStore.ReadSafe(r.Context(), sp.Holder)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	safeAssetId := ""
	if safe != nil {
		safeAssetId = safe.SafeAssetId
	}
	switch sp.Chain {
	case common.SafeChainBitcoin, common.SafeChainLitecoin:
		wsa, err := node.buildBitcoinWitnessAccountWithDerivation(r.Context(), sp)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
		if wsa.Address != sp.Address {
			common.RenderError(w, r, fmt.Errorf("buildBitcoinWitnessAccountWithDerivation(%v) => %v", sp, wsa))
			return
		}
		mainInputs, err := node.listAllBitcoinUTXOsForHolder(r.Context(), sp.Holder)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
		pendings, err := node.listPendingBitcoinUTXOsForHolder(r.Context(), sp.Holder)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
		common.RenderJSON(w, r, http.StatusOK, map[string]any{
			"chain":         sp.Chain,
			"id":            sp.RequestId,
			"address":       sp.Address,
			"outputs":       viewOutputs(mainInputs),
			"pendings":      viewOutputs(pendings),
			"script":        hex.EncodeToString(wsa.Script),
			"keys":          node.viewSafeXPubs(r.Context(), sp),
			"safe_asset_id": safeAssetId,
			"state":         status,
		})
	case common.SafeChainPolygon, common.SafeChainEthereum:
		balances, err := node.keeperStore.ReadAllEthereumTokenBalances(r.Context(), sp.Address)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
		pendings, err := node.keeperStore.ReadUnfinishedTransactionsByHolder(r.Context(), sp.Holder)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
		nonce := 0
		if safe != nil {
			nonce = int(safe.Nonce)
		}
		bs, ps := viewBalances(balances, pendings)
		common.RenderJSON(w, r, http.StatusOK, map[string]any{
			"chain":          sp.Chain,
			"id":             sp.RequestId,
			"address":        sp.Address,
			"balances":       bs,
			"pendingbalance": ps,
			"nonce":          nonce,
			"keys":           node.viewSafeXPubs(r.Context(), sp),
			"safe_asset_id":  safeAssetId,
			"state":          status,
		})
	default:
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "chain"})
	}
}
