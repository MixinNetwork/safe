package saver

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/MixinNetwork/safe/common"
	"github.com/dimfeld/httptreemux"
	"github.com/gofrs/uuid"
)

func StartHTTP(store *SQLite3Store, key string, port int) error {
	router := httptreemux.New()
	router.PanicHandler = common.HandlePanic
	router.NotFoundHandler = common.HandleNotFound

	router.POST("/", createItem)
	handler := handleSession(router, store, key)
	listen := fmt.Sprintf(":%d", port)
	return http.ListenAndServe(listen, handler)
}

func createItem(w http.ResponseWriter, r *http.Request, params map[string]string) {
	var body struct {
		Id        string `json:"id"`
		NodeId    string `json:"node_id"`
		SessionId string `json:"session_id"`
		Public    string `json:"public"`
		Share     string `json:"share"`
	}
	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	public, err := common.Base91Decode(body.Public)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	share, err := common.Base91Decode(body.Share)
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	key := common.DecodeHexOrPanic(r.Context().Value("key").(string))
	op, err := common.DecodeOperation(common.AESDecrypt(key, public))
	if err != nil {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	if op.Id != body.SessionId {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	share = common.AESDecrypt(key, share)
	sid := uuid.Must(uuid.FromBytes(share[:16]))
	if sid.String() != body.Id {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	oid := uuid.Must(uuid.FromBytes(share[16:32]))
	if oid.String() != op.Id {
		common.RenderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	store := r.Context().Value("store").(*SQLite3Store)
	data := common.MarshalJSONOrPanic(body)
	err = store.WriteItemIfNotExist(r.Context(), body.Id, string(data))
	if err != nil {
		common.RenderError(w, r, err)
	} else {
		common.RenderJSON(w, r, http.StatusOK, map[string]any{"id": sid.String()})
	}
}

func handleSession(handler http.Handler, store *SQLite3Store, key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "key", key)
		ctx = context.WithValue(ctx, "store", store)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}
