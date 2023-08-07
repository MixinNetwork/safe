package saver

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/MixinNetwork/mixin/logger"
	"github.com/MixinNetwork/safe/common"
	"github.com/dimfeld/httptreemux"
	"github.com/gofrs/uuid"
)

func StartHTTP(store *SQLite3Store, key string, port int) error {
	router := httptreemux.New()
	router.PanicHandler = handlePanic
	router.NotFoundHandler = handleNotFound

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
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	public, err := common.Base91Decode(body.Public)
	if err != nil {
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	share, err := common.Base91Decode(body.Share)
	if err != nil {
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	key := common.DecodeHexOrPanic(r.Context().Value("key").(string))
	op, err := common.DecodeOperation(common.AESDecrypt(key, public))
	if err != nil {
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	if op.Id != body.SessionId {
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	share = common.AESDecrypt(key, share)
	sid := uuid.Must(uuid.FromBytes(share[:16]))
	if sid.String() != body.Id {
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}
	oid := uuid.Must(uuid.FromBytes(share[16:32]))
	if oid.String() != op.Id {
		renderJSON(w, r, http.StatusBadRequest, map[string]any{"error": err})
		return
	}

	store := r.Context().Value("store").(*SQLite3Store)
	data := common.MarshalJSONOrPanic(body)
	err = store.WriteItemIfNotExist(r.Context(), body.Id, string(data))
	if err != nil {
		renderError(w, r, err)
	} else {
		renderJSON(w, r, http.StatusOK, map[string]any{"id": sid.String()})
	}
}

func handleSession(handler http.Handler, store *SQLite3Store, key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "key", key)
		ctx = context.WithValue(ctx, "store", store)
		handler.ServeHTTP(w, r.WithContext(ctx))
	})
}

func renderError(w http.ResponseWriter, r *http.Request, err error) {
	logger.Verbosef("ERROR (%v) => %v", *r, err)
	renderJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "500"})
}

func renderJSON(w http.ResponseWriter, r *http.Request, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	b := common.MarshalJSONOrPanic(data)
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
