package observer

// FIXME do rate limit based on IP

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/apps/bitcoin"
	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/keeper"
	"github.com/dimfeld/httptreemux"
	"github.com/unrolled/render"
)

//go:embed assets/guide.md
var GUIDE string

//go:embed assets/favicon.ico
var FAVICON []byte

func (node *Node) StartHTTP() {
	router := httptreemux.New()
	router.GET("/", node.httpIndex)
	router.GET("/favicon.ico", node.httpFavicon)
	router.GET("/accounts/:id", node.httpGetSafeProposal)
	router.POST("/accounts/:id", node.httpApproveSafeProposal)
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
	render.New().Text(w, http.StatusOK, GUIDE)
}

func (node *Node) httpFavicon(w http.ResponseWriter, r *http.Request, params map[string]string) {
	w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
	render.New().Data(w, http.StatusOK, FAVICON)
}

func (node *Node) httpGetSafeProposal(w http.ResponseWriter, r *http.Request, params map[string]string) {
	safe, err := node.keeperStore.ReadSafeProposal(r.Context(), params["id"])
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if safe == nil {
		render.New().JSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	proposed, err := node.store.CheckAccountProposed(r.Context(), safe.Address)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if !proposed {
		render.New().JSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	wka, err := bitcoin.BuildWitnessKeyAccount(safe.Accountant)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	wsa, err := bitcoin.BuildWitnessScriptAccount(safe.Holder, safe.Signer, safe.Observer, safe.Timelock)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if wsa.Address != safe.Address {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	status, err := node.getSafeStatus(r.Context(), safe.RequestId)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	render.New().JSON(w, http.StatusOK, map[string]string{
		"id":         safe.RequestId,
		"address":    safe.Address,
		"script":     hex.EncodeToString(wsa.Script),
		"accountant": wka.Address,
		"status":     status,
	})
}

func (node *Node) httpApproveSafeProposal(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var body struct {
		Address   string `json:"address"`
		Signature string `json:"signature"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		render.New().JSON(w, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	safe, err := node.keeperStore.ReadSafeProposal(r.Context(), params["id"])
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if safe == nil {
		render.New().JSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	if safe.Address != body.Address {
		render.New().JSON(w, http.StatusBadRequest, map[string]any{"error": "address"})
		return
	}
	proposed, err := node.store.CheckAccountProposed(r.Context(), safe.Address)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if !proposed {
		render.New().JSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	err = node.approveBitcoinAccount(r.Context(), body.Address, body.Signature)
	if err != nil {
		render.New().JSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err})
		return
	}
	wka, err := bitcoin.BuildWitnessKeyAccount(safe.Accountant)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	wsa, err := bitcoin.BuildWitnessScriptAccount(safe.Holder, safe.Signer, safe.Observer, safe.Timelock)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if wsa.Address != safe.Address {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	status, err := node.getSafeStatus(r.Context(), safe.RequestId)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	render.New().JSON(w, http.StatusOK, map[string]string{
		"id":         safe.RequestId,
		"address":    safe.Address,
		"script":     hex.EncodeToString(wsa.Script),
		"accountant": wka.Address,
		"status":     status,
	})
}

func (node *Node) httpGetTransaction(w http.ResponseWriter, r *http.Request, params map[string]string) {
	tx, err := node.keeperStore.ReadTransactionByRequestId(r.Context(), params["id"])
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if tx == nil {
		render.New().JSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	approval, err := node.store.ReadTransactionApproval(r.Context(), tx.TransactionHash)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if approval == nil {
		render.New().JSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	render.New().JSON(w, http.StatusOK, map[string]any{
		"chain":   tx.Chain,
		"id":      tx.RequestId,
		"hash":    tx.TransactionHash,
		"raw":     tx.RawTransaction,
		"fee":     tx.Fee,
		"signers": approval.Signers(),
	})
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
		render.New().JSON(w, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	if body.Chain != keeper.SafeChainBitcoin {
		render.New().JSON(w, http.StatusBadRequest, map[string]any{"error": "chain"})
		return
	}
	tx, err := node.keeperStore.ReadTransactionByRequestId(r.Context(), params["id"])
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if tx == nil {
		render.New().JSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	approval, err := node.store.ReadTransactionApproval(r.Context(), tx.TransactionHash)
	if err != nil {
		render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
		return
	}
	if approval == nil {
		render.New().JSON(w, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	if approval.State != common.RequestStateInitial {
		render.New().JSON(w, http.StatusBadRequest, map[string]any{"error": "state"})
		return
	}

	switch body.Action {
	case "approve":
		err = node.approveBitcoinTransaction(r.Context(), body.Raw, body.Signature)
		if err != nil {
			render.New().JSON(w, http.StatusInternalServerError, map[string]any{"error": "500"})
			return
		}
	case "revoke":
	default:
	}

	render.New().JSON(w, http.StatusOK, map[string]any{
		"chain":   tx.Chain,
		"id":      tx.RequestId,
		"hash":    tx.TransactionHash,
		"raw":     tx.RawTransaction,
		"fee":     tx.Fee,
		"signers": approval.Signers(),
	})
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
			render.New().JSON(w, http.StatusOK, map[string]any{})
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
