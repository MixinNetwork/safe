package computer

// FIXME do rate limit based on IP

import (
	_ "embed"
	"fmt"
	"net/http"
	"time"

	"github.com/MixinNetwork/safe/common"
	"github.com/dimfeld/httptreemux/v5"
)

//go:embed assets/favicon.ico
var FAVICON []byte
var VERSION string

func (node *Node) StartHTTP() {
	router := httptreemux.New()
	router.PanicHandler = common.HandlePanic
	router.NotFoundHandler = common.HandleNotFound

	router.GET("/", node.httpIndex)
	handler := common.HandleCORS(router)
	err := http.ListenAndServe(fmt.Sprintf(":%d", 7080), handler)
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
	common.RenderJSON(w, r, http.StatusOK, map[string]any{
		"version":  VERSION,
		"observer": node.conf.ObserverId,
		"keeper": map[string]any{
			"members":   node.GetMembers(),
			"threshold": node.conf.Threshold,
		},
		"params": map[string]any{
			"operation": map[string]any{
				"asset": plan.OperationPriceAsset,
				"price": plan.OperationPriceAmount.String(),
			},
		},
	})
}

func (node *Node) httpFavicon(w http.ResponseWriter, r *http.Request, params map[string]string) {
	w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(FAVICON)
}
