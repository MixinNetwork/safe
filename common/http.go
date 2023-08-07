package common

import (
	"net/http"

	"github.com/MixinNetwork/mixin/logger"
)

func RenderError(w http.ResponseWriter, r *http.Request, err error) {
	logger.Verbosef("ERROR (%v) => %v", *r, err)
	RenderJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "500"})
}

func RenderJSON(w http.ResponseWriter, r *http.Request, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
	b := MarshalJSONOrPanic(data)
	size, err := w.Write(b)
	logger.Verbosef("ServeHTTP(%v) => %d %s %d %v", *r, status, string(b), size, err)
}

func HandlePanic(w http.ResponseWriter, r *http.Request, rcv any) {
	logger.Verbosef("PANIC (%v) => %v", *r, rcv)
	RenderJSON(w, r, http.StatusInternalServerError, map[string]any{"error": "500"})
}

func HandleNotFound(w http.ResponseWriter, r *http.Request) {
	RenderJSON(w, r, http.StatusNotFound, map[string]any{"error": "404"})
}

// TODO may consider a whitelist in the case of Ethereum scams
func HandleCORS(handler http.Handler) http.Handler {
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
			RenderJSON(w, r, http.StatusOK, map[string]any{})
		} else {
			handler.ServeHTTP(w, r)
		}
	})
}
