package computer

// FIXME do rate limit based on IP

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/MixinNetwork/safe/computer/store"
	"github.com/dimfeld/httptreemux/v5"
	"github.com/shopspring/decimal"
)

//go:embed assets/mark.png
var FOOTMARK []byte

//go:embed assets/favicon.ico
var FAVICON []byte
var VERSION string

func (node *Node) StartHTTP(version string) {
	VERSION = version

	router := httptreemux.New()
	router.PanicHandler = common.HandlePanic
	router.NotFoundHandler = common.HandleNotFound

	router.GET("/", node.httpIndex)
	router.GET("/favicon.ico", node.httpFavicon)
	router.GET("/users/:addr", node.httpGetUser)
	router.GET("/deployed_assets", node.httpGetAssets)
	router.GET("/system_calls/:id", node.httpGetSystemCall)
	router.POST("/deployed_assets", node.httpDeployAssets)
	router.POST("/nonce_accounts", node.httpLockNonce)
	router.POST("/fee", node.httpGetFeeOnXIN)
	handler := common.HandleCORS(router)
	err := http.ListenAndServe(fmt.Sprintf(":%d", 7081), handler)
	if err != nil {
		panic(err)
	}
}

func (node *Node) httpIndex(w http.ResponseWriter, r *http.Request, params map[string]string) {
	plan, err := node.store.ReadLatestOperationParams(r.Context(), time.Now())
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	height, err := node.readSolanaBlockCheckpoint(r.Context())
	if err != nil {
		common.RenderError(w, r, err)
		return
	}

	common.RenderJSON(w, r, http.StatusOK, map[string]any{
		"version":  VERSION,
		"observer": node.conf.ObserverId,
		"payer":    node.SolanaPayer().String(),
		"members": map[string]any{
			"app_id":    node.conf.AppId,
			"members":   node.GetMembers(),
			"threshold": node.conf.MTG.Genesis.Threshold,
		},
		"params": map[string]any{
			"operation": map[string]any{
				"asset": plan.OperationPriceAsset,
				"price": plan.OperationPriceAmount.String(),
			},
		},
		"height": height,
	})
}

func (node *Node) httpFavicon(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
	w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(FAVICON)
}

func (node *Node) httpGetUser(w http.ResponseWriter, r *http.Request, params map[string]string) {
	ctx := r.Context()
	user, err := node.store.ReadUserByMixAddress(ctx, params["addr"])
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if user == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "user"})
		return
	}

	common.RenderJSON(w, r, http.StatusOK, map[string]any{
		"id":            user.UserId,
		"mix_address":   user.MixAddress,
		"chain_address": user.ChainAddress,
	})
}

func (node *Node) httpGetSystemCall(w http.ResponseWriter, r *http.Request, params map[string]string) {
	ctx := r.Context()
	call, err := node.store.ReadSystemCallByRequestId(ctx, params["id"], 0)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if call == nil || call.Type != store.CallTypeMain {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
		return
	}
	var state string
	switch call.State {
	case common.RequestStateInitial:
		state = "initial"
	case common.RequestStatePending:
		state = "pending"
	case common.RequestStateDone:
		state = "done"
	case common.RequestStateFailed:
		state = "failed"
	}

	resp := map[string]any{
		"id":            call.RequestId,
		"user_id":       call.UserIdFromPublicPath(),
		"nonce_account": call.NonceAccount,
		"raw":           call.Raw,
		"state":         state,
		"hash":          call.Hash.String,
	}
	if call.State == common.RequestStateFailed {
		reason, err := node.store.ReadFailReason(ctx, call.RequestId)
		if err != nil {
			common.RenderError(w, r, err)
			return
		}
		resp["reason"] = reason
	}

	common.RenderJSON(w, r, http.StatusOK, resp)
}

func (node *Node) httpGetAssets(w http.ResponseWriter, r *http.Request, params map[string]string) {
	ctx := r.Context()
	as, err := node.store.ListDeployedAssets(ctx)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	um, err := node.store.ListAssetIconUrls(ctx)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}

	view := make([]map[string]any, 0)
	for _, asset := range as {
		view = append(view, map[string]any{
			"asset_id": asset.AssetId,
			"address":  asset.Address,
			"decimals": asset.Decimals,
			"uri":      um[asset.AssetId],
		})
	}
	common.RenderJSON(w, r, http.StatusOK, view)
}

func (node *Node) httpDeployAssets(w http.ResponseWriter, r *http.Request, params map[string]string) {
	ctx := r.Context()
	var body struct {
		Assets []string `json:"assets"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	var assets []*store.ExternalAsset
	now := time.Now().UTC()
	for _, id := range body.Assets {
		old, err := node.store.ReadExternalAsset(ctx, id)
		if err != nil {
			common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		}
		if old != nil {
			assets = append(assets, old)
			continue
		}
		asset, err := common.SafeReadAssetUntilSufficient(ctx, id)
		if err != nil {
			common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
			return
		}
		if asset.ChainID == common.SafeSolanaChainId {
			common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": "chain"})
			return
		}
		assets = append(assets, &store.ExternalAsset{
			AssetId:   id,
			CreatedAt: now,
		})
	}
	err = node.store.WriteExternalAssets(ctx, assets)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	common.RenderJSON(w, r, http.StatusOK, map[string]any{
		"assets": assets,
	})
}

func (node *Node) httpLockNonce(w http.ResponseWriter, r *http.Request, params map[string]string) {
	ctx := r.Context()
	var body struct {
		Mix string `json:"mix"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	user, err := node.store.ReadUserByMixAddress(ctx, body.Mix)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if user == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "user"})
		return
	}
	nonce, err := node.store.ReadSpareNonceAccount(ctx)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if nonce == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "nonce"})
		return
	}
	hash, err := node.solana.GetNonceAccountHash(ctx, nonce.Account().Address)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if hash.String() != nonce.Hash {
		panic(fmt.Errorf("inconsistent nonce hash: %s %s %s", nonce.Address, nonce.Hash, hash.String()))
	}

	err = node.store.LockNonceAccountWithMix(ctx, nonce.Address, body.Mix)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}

	common.RenderJSON(w, r, http.StatusOK, map[string]any{
		"mix":           body.Mix,
		"nonce_address": nonce.Address,
		"nonce_hash":    nonce.Hash,
	})
}

func (node *Node) httpGetFeeOnXIN(w http.ResponseWriter, r *http.Request, params map[string]string) {
	ctx := r.Context()
	var body struct {
		SolAmount decimal.Decimal `json:"sol_amount"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	fee, err := node.store.ReadLatestFeeInfo(ctx)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}
	if fee == nil {
		common.RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "fee"})
		return
	}
	ratio := decimal.RequireFromString(fee.Ratio)
	xinAmount := body.SolAmount.Div(ratio).RoundCeil(8)

	common.RenderJSON(w, r, http.StatusOK, map[string]any{
		"fee_id":     fee.Id,
		"xin_amount": xinAmount,
	})
}
