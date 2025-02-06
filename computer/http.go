package computer

// FIXME do rate limit based on IP

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/dimfeld/httptreemux/v5"
)

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
	router.POST("/nonce_accounts", node.httpLockNonce)
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
		"payer":    node.solanaPayer().String(),
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

func (node *Node) httpGetAssets(w http.ResponseWriter, r *http.Request, params map[string]string) {
	ctx := r.Context()
	as, err := node.store.ListDeployedAssets(ctx)
	if err != nil {
		common.RenderError(w, r, err)
		return
	}

	view := make([]map[string]any, 0)
	for _, asset := range as {
		view = append(view, map[string]any{
			"asset_id": asset.AssetId,
			"address":  asset.Address,
		})
	}
	common.RenderJSON(w, r, http.StatusOK, view)
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
