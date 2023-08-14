package saver

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/MixinNetwork/mixin/crypto"
	"github.com/MixinNetwork/safe/common"
	"github.com/dimfeld/httptreemux/v5"
)

func StartHTTP(store *SQLite3Store, port int) error {
	router := httptreemux.New()
	router.PanicHandler = common.HandlePanic
	router.NotFoundHandler = common.HandleNotFound

	router.POST("/", createItem)
	handler := handleSession(router, store)
	listen := fmt.Sprintf(":%d", port)
	return http.ListenAndServe(listen, handler)
}

func createItem(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var body struct {
		Id        string           `json:"id"`
		NodeId    string           `json:"node_id"`
		SessionId string           `json:"session_id"`
		Public    string           `json:"public"`
		Share     string           `json:"share"`
		Signature crypto.Signature `json:"signature"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	store := r.Context().Value("store").(*SQLite3Store)
	pub, err := store.ReadNodePublicKey(r.Context(), body.NodeId)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	msg := body.Id + body.NodeId + body.SessionId + body.Public + body.Share
	if !pub.Verify([]byte(msg), body.Signature) {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": "signature"})
		return
	}

	data := common.MarshalJSONOrPanic(body)
	err = store.WriteItemIfNotExist(r.Context(), body.Id, body.NodeId, string(data))
	if err != nil {
		common.RenderError(w, r, err)
	} else {
		common.RenderJSON(w, r, http.StatusOK, map[string]any{"id": body.Id, "size": len(data)})
	}
}

func handleSession(handler http.Handler, store *SQLite3Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "store", store)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
