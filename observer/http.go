package observer

// FIXME do rate limit based on IP

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/MixinNetwork/safe/keeper/store"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/dimfeld/httptreemux"
)

//go:embed assets/favicon.ico
var FAVICON []byte

//go:embed assets/safe-flow.png
var FLOW []byte

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
      var flow = document.createElement('img');
      flow.src = "SAFE-FLOW-BASE64";
      flow.alt = "Mixin Safe Flow";
      article.insertBefore(flow, document.getElementById("prepare-holder-key"));
      article.style="display:block";
    </script>
  </body>
</html>
`

func (node *Node) StartHTTP(readme string) {
	flow := "data:image/png;base64," + base64.StdEncoding.EncodeToString(FLOW)
	GUIDE = strings.TrimSpace(strings.Replace(GUIDE, "README", readme, -1))
	GUIDE = strings.Replace(GUIDE, "SAFE-FLOW-BASE64", flow, -1)

	router := httptreemux.New()
	router.PanicHandler = handlePanic
	router.NotFoundHandler = handleNotFound

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
	handler := handleCORS(router)
	err := http.ListenAndServe(fmt.Sprintf(":%d", 7080), handler)
	if err != nil {
		panic(err)
	}
}

func (node *Node) httpIndex(w http.ResponseWriter, r *http.Request, params map[string]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(GUIDE))
}

func (node *Node) httpFavicon(w http.ResponseWriter, r *http.Request, params map[string]string) {
	w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
	w.WriteHeader(http.StatusOK)
	w.Write(FAVICON)
}

func (node *Node) httpListChains(w http.ResponseWriter, r *http.Request, params map[string]string) {
	bi, err := node.keeperStore.ReadLatestNetworkInfo(r.Context(), keeper.SafeChainBitcoin)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if bi == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	li, err := node.keeperStore.ReadLatestNetworkInfo(r.Context(), keeper.SafeChainLitecoin)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if li == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	bc, bs, err := node.readChainAccountantBalance(r.Context(), keeper.SafeChainBitcoin)
	if err != nil {
		renderError(w, r, err)
		return
	}
	lc, ls, err := node.readChainAccountantBalance(r.Context(), keeper.SafeChainLitecoin)
	if err != nil {
		renderError(w, r, err)
		return
	}

	renderJSON(w, r, http.StatusOK, []map[string]any{{
		"id":    keeper.SafeBitcoinChainId,
		"chain": bi.Chain,
		"head": map[string]any{
			"id":         bi.RequestId,
			"height":     bi.Height,
			"fee":        bi.Fee,
			"hash":       bi.Hash,
			"created_at": bi.CreatedAt,
		},
		"accountant": map[string]any{
			"outputs": map[string]any{
				"count":   bc,
				"satoshi": bs,
			},
		},
	}, {
		"id":    keeper.SafeLitecoinChainId,
		"chain": li.Chain,
		"head": map[string]any{
			"id":         li.RequestId,
			"height":     li.Height,
			"fee":        li.Fee,
			"hash":       li.Hash,
			"created_at": li.CreatedAt,
		},
		"accountant": map[string]any{
			"outputs": map[string]any{
				"count":   lc,
				"satoshi": ls,
			},
		},
	}})
}

func (node *Node) httpListDeposits(w http.ResponseWriter, r *http.Request, params map[string]string) {
	holder := r.URL.Query().Get("holder")
	chain, _ := strconv.ParseInt(r.URL.Query().Get("chain"), 10, 64)
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	deposits, err := node.store.ListDeposits(r.Context(), int(chain), holder, common.RequestStateDone, offset)
	if err != nil {
		renderError(w, r, err)
		return
	}
	sent, err := node.store.QueryDepositSentHashes(r.Context(), deposits)
	if err != nil {
		renderError(w, r, err)
		return
	}

	renderJSON(w, r, http.StatusOK, node.viewDeposits(r.Context(), deposits, sent))
}

func (node *Node) httpListRecoveries(w http.ResponseWriter, r *http.Request, params map[string]string) {
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	rs, err := node.store.ListInitialRecoveries(r.Context(), offset)
	if err != nil {
		renderError(w, r, err)
		return
	}

	renderJSON(w, r, http.StatusOK, node.viewRecoveries(r.Context(), rs))
}

func (node *Node) httpGetRecovery(w http.ResponseWriter, r *http.Request, params map[string]string) {
	safe, _, err := node.readSafeProposalOrRequest(r.Context(), params["id"])
	if err != nil {
		renderError(w, r, err)
		return
	}
	if safe == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	recovery, err := node.store.ReadRecovery(r.Context(), safe.Address)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if safe == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}

	resp := map[string]any{
		"address":    recovery.Address,
		"chain":      recovery.Chain,
		"public_key": recovery.Holder,
		"observer":   recovery.Observer,
		"raw":        recovery.RawTransaction,
		"hash":       recovery.TransactionHash,
		"state":      recovery.getState(),
		"created_at": recovery.CreatedAt,
		"updated_at": recovery.UpdatedAt,
	}

	approval, err := node.store.ReadTransactionApproval(r.Context(), recovery.TransactionHash)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if approval != nil && approval.SpentRaw.Valid {
		resp["hash"] = approval.SpentHash.String
		resp["raw"] = approval.SpentRaw.String
		resp["state"] = "spent"
	}

	renderJSON(w, r, http.StatusOK, resp)
}

func (node *Node) httpGetAccount(w http.ResponseWriter, r *http.Request, params map[string]string) {
	safe, req, err := node.readSafeProposalOrRequest(r.Context(), params["id"])
	if err != nil {
		renderError(w, r, err)
		return
	}
	if req != nil && req.State == common.RequestStateFailed {
		renderJSON(w, r, http.StatusOK, map[string]any{
			"id":    req.Id,
			"state": common.StateName(int(req.State)),
		})
		return
	}
	if safe == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	proposed, err := node.store.CheckAccountProposed(r.Context(), safe.Address)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if !proposed {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	wsa, err := node.buildBitcoinWitnessAccountWithDerivation(r.Context(), safe)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if wsa.Address != safe.Address {
		renderError(w, r, fmt.Errorf("buildBitcoinWitnessAccountWithDerivation(%v) => %v", safe, wsa))
		return
	}
	status, err := node.getSafeStatus(r.Context(), safe.RequestId)
	if err != nil {
		renderError(w, r, err)
		return
	}
	_, bitcoinAssetId := node.bitcoinParams(safe.Chain)
	_, _, bondId, err := node.fetchBondAsset(r.Context(), bitcoinAssetId, safe.Holder)
	if err != nil {
		renderError(w, r, err)
		return
	}
	mainInputs, err := node.listAllBitcoinUTXOsForHolder(r.Context(), safe.Holder)
	if err != nil {
		renderError(w, r, err)
		return
	}
	renderJSON(w, r, http.StatusOK, map[string]any{
		"chain":   safe.Chain,
		"id":      safe.RequestId,
		"address": safe.Address,
		"outputs": viewOutputs(mainInputs),
		"script":  hex.EncodeToString(wsa.Script),
		"keys":    node.viewSafeXPubs(r.Context(), safe),
		"bond": map[string]any{
			"id": bondId,
		},
		"state": status,
	})
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
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	safe, err := node.keeperStore.ReadSafeProposal(r.Context(), params["id"])
	if err != nil {
		renderError(w, r, err)
		return
	}
	if safe == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	if safe.Address != body.Address {
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": "address"})
		return
	}

	switch body.Action {
	case "approve":
		proposed, err := node.store.CheckAccountProposed(r.Context(), safe.Address)
		if err != nil {
			renderError(w, r, err)
			return
		}
		if !proposed {
			renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
			return
		}
		err = node.httpApproveBitcoinAccount(r.Context(), body.Address, body.Signature)
		if err != nil {
			renderJSON(w, r, http.StatusUnprocessableEntity, map[string]any{"error": err})
			return
		}
	case "close":
		err = node.httpCreateBitcoinAccountRecoveryRequest(r.Context(), body.Address, body.Raw, body.Hash)
		if err != nil {
			renderJSON(w, r, http.StatusUnprocessableEntity, map[string]any{"error": err})
			return
		}
	default:
		renderJSON(w, r, http.StatusUnprocessableEntity, map[string]any{"error": "action"})
		return
	}

	wsa, err := node.buildBitcoinWitnessAccountWithDerivation(r.Context(), safe)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if wsa.Address != safe.Address {
		renderError(w, r, fmt.Errorf("buildBitcoinWitnessAccountWithDerivation(%v) => %v", safe, wsa))
		return
	}
	status, err := node.getSafeStatus(r.Context(), safe.RequestId)
	if err != nil {
		renderError(w, r, err)
		return
	}
	_, bitcoinAssetId := node.bitcoinParams(safe.Chain)
	_, _, bondId, err := node.fetchBondAsset(r.Context(), bitcoinAssetId, safe.Holder)
	if err != nil {
		renderError(w, r, err)
		return
	}
	mainInputs, err := node.listAllBitcoinUTXOsForHolder(r.Context(), safe.Holder)
	if err != nil {
		renderError(w, r, err)
		return
	}
	renderJSON(w, r, http.StatusOK, map[string]any{
		"chain":   safe.Chain,
		"id":      safe.RequestId,
		"address": safe.Address,
		"outputs": viewOutputs(mainInputs),
		"script":  hex.EncodeToString(wsa.Script),
		"keys":    node.viewSafeXPubs(r.Context(), safe),
		"bond": map[string]any{
			"id": bondId,
		},
		"state": status,
	})
}

func (node *Node) httpSignRecovery(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var body struct {
		Raw  string `json:"raw"`
		Hash string `json:"hash"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	safe, err := node.keeperStore.ReadSafeProposal(r.Context(), params["id"])
	if err != nil {
		renderError(w, r, err)
		return
	}
	if safe == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	if body.Hash == "" {
		renderJSON(w, r, http.StatusNotAcceptable, map[string]any{"error": "hash"})
		return
	}
	if body.Raw == "" {
		renderJSON(w, r, http.StatusNotAcceptable, map[string]any{"error": "raw"})
		return
	}

	err = node.httpSignBitcoinAccountRecoveryRequest(r.Context(), safe.Address, body.Raw, body.Hash)
	if err != nil {
		renderJSON(w, r, http.StatusUnprocessableEntity, map[string]any{"error": err})
		return
	}

	wsa, err := node.buildBitcoinWitnessAccountWithDerivation(r.Context(), safe)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if wsa.Address != safe.Address {
		renderError(w, r, fmt.Errorf("buildBitcoinWitnessAccountWithDerivation(%v) => %v", safe, wsa))
		return
	}
	status, err := node.getSafeStatus(r.Context(), safe.RequestId)
	if err != nil {
		renderError(w, r, err)
		return
	}
	_, bitcoinAssetId := node.bitcoinParams(safe.Chain)
	_, _, bondId, err := node.fetchBondAsset(r.Context(), bitcoinAssetId, safe.Holder)
	if err != nil {
		renderError(w, r, err)
		return
	}
	mainInputs, err := node.listAllBitcoinUTXOsForHolder(r.Context(), safe.Holder)
	if err != nil {
		renderError(w, r, err)
		return
	}
	renderJSON(w, r, http.StatusOK, map[string]any{
		"chain":   safe.Chain,
		"id":      safe.RequestId,
		"address": safe.Address,
		"outputs": viewOutputs(mainInputs),
		"script":  hex.EncodeToString(wsa.Script),
		"keys":    node.viewSafeXPubs(r.Context(), safe),
		"bond": map[string]any{
			"id": bondId,
		},
		"state": status,
	})
}

func (node *Node) httpGetTransaction(w http.ResponseWriter, r *http.Request, params map[string]string) {
	tx, req, err := node.readTransactionOrRequest(r.Context(), params["id"])
	if err != nil {
		renderError(w, r, err)
		return
	}
	if req != nil && req.State == common.RequestStateFailed {
		renderJSON(w, r, http.StatusOK, map[string]any{
			"id":    req.Id,
			"state": common.StateName(int(req.State)),
		})
		return
	}
	if tx == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	approval, err := node.store.ReadTransactionApproval(r.Context(), tx.TransactionHash)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if approval == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	safe, err := node.keeperStore.ReadSafe(r.Context(), tx.Holder)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if safe == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
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
	renderJSON(w, r, http.StatusOK, data)
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
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	switch body.Chain {
	case keeper.SafeChainBitcoin:
	case keeper.SafeChainLitecoin:
	default:
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": "chain"})
		return
	}
	tx, err := node.keeperStore.ReadTransactionByRequestId(r.Context(), params["id"])
	if err != nil {
		renderError(w, r, err)
		return
	}
	if tx == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	approval, err := node.store.ReadTransactionApproval(r.Context(), tx.TransactionHash)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if approval == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	if approval.State != common.RequestStateInitial {
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": "state"})
		return
	}
	safe, err := node.keeperStore.ReadSafe(r.Context(), tx.Holder)
	if err != nil {
		renderError(w, r, err)
		return
	}
	if safe == nil {
		renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}

	switch body.Action {
	case "approve":
		err = node.httpApproveBitcoinTransaction(r.Context(), body.Raw)
		if err != nil {
			renderError(w, r, err)
			return
		}
	case "revoke":
		err = node.httpRevokeBitcoinTransaction(r.Context(), tx.TransactionHash, body.Signature)
		if err != nil {
			renderError(w, r, err)
			return
		}
	default:
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
	renderJSON(w, r, http.StatusOK, data)
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

	var count, satoshi uint64
	err := row.Scan(&satoshi, &count)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return count, satoshi, err
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
		}
		if dm["sent_hash"] == "" {
			dm["sent_hash"] = d.TransactionHash
		} else {
			dm["change"] = node.bitcoinCheckDepositChange(ctx, d.TransactionHash, d.OutputIndex, sent[d.TransactionHash])
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
			"public_key": r.Holder,
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

func renderError(w http.ResponseWriter, r *http.Request, err error) {
	logger.Verbosef("ERROR (%v) => %v", *r, err)
	renderJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "500"})
}

func renderJSON(w http.ResponseWriter, r *http.Request, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	b, _ := json.Marshal(data)
	size, err := w.Write(b)
	logger.Verbosef("ServeHTTP(%v) => %d %s %d %v", *r, status, string(b), size, err)
}

func handlePanic(w http.ResponseWriter, r *http.Request, rcv any) {
	logger.Verbosef("PANIC (%v) => %v", *r, rcv)
	renderJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "500"})
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	renderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
}

// TODO may consider a whitelist in the case of Ethereum scams
func handleCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			handler.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Access-Control-Allow-Headers", "Content-Type,X-Request-ID")
		w.Header().Set("Access-Control-Allow-Methods", "OPTIONS,GET,POST,DELETE")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == "OPTIONS" {
			renderJSON(w, r, http.StatusOK, map[string]any{})
		} else {
			handler.ServeHTTP(w, r)
		}
	})
}
