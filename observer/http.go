package observer

// FIXME do rate limit based on IP

import (
	"context"
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
	router.GET("/accounts/:id", node.httpGetAccount)
	router.POST("/accounts/:id", node.httpApproveAccount)
	router.GET("/transactions/:id", node.httpGetTransaction)
	router.POST("/transactions/:id", node.httpApproveTransaction)
	handler := handleCORS(router)
	handler = handleLog(handler)
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
	info, err := node.keeperStore.ReadLatestNetworkInfo(r.Context(), keeper.SafeChainBitcoin)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if info == nil {
		renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}

	renderJSON(w, http.StatusOK, []map[string]any{{
		"id":    keeper.SafeBitcoinChainId,
		"chain": info.Chain,
		"head": map[string]any{
			"id":         info.RequestId,
			"height":     info.Height,
			"fee":        info.Fee,
			"hash":       info.Hash,
			"created_at": info.CreatedAt,
		},
	}})
}

func (node *Node) httpListDeposits(w http.ResponseWriter, r *http.Request, params map[string]string) {
	holder := r.URL.Query().Get("holder")
	chain, _ := strconv.ParseInt(r.URL.Query().Get("chain"), 10, 64)
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	deposits, err := node.store.ListDeposits(r.Context(), int(chain), holder, common.RequestStateDone, offset)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}

	renderJSON(w, http.StatusOK, viewDeposits(deposits))
}

func (node *Node) httpGetAccount(w http.ResponseWriter, r *http.Request, params map[string]string) {
	safe, err := node.keeperStore.ReadSafeProposal(r.Context(), params["id"])
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if safe == nil {
		renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	if safe.Chain != keeper.SafeChainBitcoin {
		renderJSON(w, http.StatusBadRequest, map[string]any{"error": "chain"})
		return
	}
	proposed, err := node.store.CheckAccountProposed(r.Context(), safe.Address)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if !proposed {
		renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	wka, err := bitcoin.BuildWitnessKeyAccount(safe.Accountant)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	wsa, err := bitcoin.BuildWitnessScriptAccount(safe.Holder, safe.Signer, safe.Observer, safe.Timelock)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if wsa.Address != safe.Address {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	status, err := node.getSafeStatus(r.Context(), safe.RequestId)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	_, _, bondId, err := node.fetchBondAsset(r.Context(), keeper.SafeBitcoinChainId, safe.Holder)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	mainInputs, feeInputs, err := node.listAllBitcoinUTXOsForHolder(r.Context(), safe.Holder)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	renderJSON(w, http.StatusOK, map[string]any{
		"chain":   safe.Chain,
		"id":      safe.RequestId,
		"address": safe.Address,
		"outputs": viewOutputs(mainInputs),
		"script":  hex.EncodeToString(wsa.Script),
		"accountant": map[string]any{
			"address": wka.Address,
			"script":  hex.EncodeToString(wka.Script),
			"outputs": viewOutputs(feeInputs),
		},
		"bond": map[string]any{
			"id": bondId,
		},
		"status": status,
	})
}

func (node *Node) httpApproveAccount(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var body struct {
		Address   string `json:"address"`
		Signature string `json:"signature"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		renderJSON(w, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	safe, err := node.keeperStore.ReadSafeProposal(r.Context(), params["id"])
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if safe == nil {
		renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	if safe.Address != body.Address {
		renderJSON(w, http.StatusBadRequest, map[string]any{"error": "address"})
		return
	}
	proposed, err := node.store.CheckAccountProposed(r.Context(), safe.Address)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if !proposed {
		renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	err = node.approveBitcoinAccount(r.Context(), body.Address, body.Signature)
	if err != nil {
		renderJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err})
		return
	}
	wka, err := bitcoin.BuildWitnessKeyAccount(safe.Accountant)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	wsa, err := bitcoin.BuildWitnessScriptAccount(safe.Holder, safe.Signer, safe.Observer, safe.Timelock)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if wsa.Address != safe.Address {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	status, err := node.getSafeStatus(r.Context(), safe.RequestId)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	_, _, bondId, err := node.fetchBondAsset(r.Context(), keeper.SafeBitcoinChainId, safe.Holder)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	mainInputs, feeInputs, err := node.listAllBitcoinUTXOsForHolder(r.Context(), safe.Holder)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	renderJSON(w, http.StatusOK, map[string]any{
		"chain":   safe.Chain,
		"id":      safe.RequestId,
		"address": safe.Address,
		"outputs": viewOutputs(mainInputs),
		"script":  hex.EncodeToString(wsa.Script),
		"accountant": map[string]any{
			"address": wka.Address,
			"script":  hex.EncodeToString(wka.Script),
			"outputs": viewOutputs(feeInputs),
		},
		"bond": map[string]any{
			"id": bondId,
		},
		"status": status,
	})
}

func (node *Node) httpGetTransaction(w http.ResponseWriter, r *http.Request, params map[string]string) {
	tx, err := node.keeperStore.ReadTransactionByRequestId(r.Context(), params["id"])
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if tx == nil {
		renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	approval, err := node.store.ReadTransactionApproval(r.Context(), tx.TransactionHash)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if approval == nil {
		renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	renderJSON(w, http.StatusOK, map[string]any{
		"chain":   tx.Chain,
		"id":      tx.RequestId,
		"hash":    tx.TransactionHash,
		"raw":     approval.RawTransaction,
		"fee":     tx.Fee,
		"signers": approval.Signers(),
	})
}

func (node *Node) httpApproveTransaction(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var body struct {
		Chain     int    `json:"chain"`
		Action    string `json:"action"`
		Hash      string `json:"hash"`
		Raw       string `json:"raw"`
		Signature string `json:"signature"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		renderJSON(w, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	if body.Chain != keeper.SafeChainBitcoin {
		renderJSON(w, http.StatusBadRequest, map[string]any{"error": "chain"})
		return
	}
	tx, err := node.keeperStore.ReadTransactionByRequestId(r.Context(), params["id"])
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if tx == nil {
		renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	approval, err := node.store.ReadTransactionApproval(r.Context(), tx.TransactionHash)
	if err != nil {
		renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if approval == nil {
		renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	if approval.State != common.RequestStateInitial {
		renderJSON(w, http.StatusBadRequest, map[string]any{"error": "state"})
		return
	}

	switch body.Action {
	case "approve":
		err = node.approveBitcoinTransaction(r.Context(), body.Raw, body.Signature)
		if err != nil {
			renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
			return
		}
	case "revoke":
		err = node.revokeBitcoinTransaction(r.Context(), body.Hash, body.Signature)
		if err != nil {
			renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
			return
		}
	default:
	}

	renderJSON(w, http.StatusOK, map[string]any{
		"chain":   tx.Chain,
		"id":      tx.RequestId,
		"hash":    tx.TransactionHash,
		"raw":     approval.RawTransaction,
		"fee":     tx.Fee,
		"signers": approval.Signers(),
	})
}

func (node *Node) listAllBitcoinUTXOsForHolder(ctx context.Context, holder string) ([]*bitcoin.Input, []*bitcoin.Input, error) {
	safe, err := node.keeperStore.ReadSafe(ctx, holder)
	if err != nil || safe == nil {
		return nil, nil, err
	}
	return node.keeperStore.ListAllBitcoinUTXOsForHolder(ctx, holder)
}

func viewDeposits(deposits []*Deposit) []map[string]any {
	view := make([]map[string]any, 0)
	for _, d := range deposits {
		view = append(view, map[string]any{
			"transaction_hash": d.TransactionHash,
			"output_index":     d.OutputIndex,
			"asset_id":         d.AssetId,
			"amount":           d.Amount,
			"receiver":         d.Receiver,
			"chain":            d.Chain,
			"updated_at":       d.UpdatedAt,
		})
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
		})
	}
	return view
}

func renderJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	b, _ := json.Marshal(data)
	w.Write(b)
}

func handlePanic(w http.ResponseWriter, r *http.Request, rcv any) {
	logger.Verbosef("PANIC (%v) => %v", *r, rcv)
	renderJSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	renderJSON(w, http.StatusNotFound, map[string]any{"error": "404"})
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
			renderJSON(w, http.StatusOK, map[string]any{})
		} else {
			handler.ServeHTTP(w, r)
		}
	})
}

func handleLog(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Verbosef("ServeHTTP(%v)", *r)
		handler.ServeHTTP(w, r)
	})
}
