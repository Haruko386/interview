package api

import (
	"encoding/json"
	"log"
	"net/http"

	"banner-fingerprint/internal/engine"
)

type Server struct {
	engine *engine.Engine
}

func NewServer(e *engine.Engine) *Server {
	return &Server{engine: e}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.recover(s.handleHealth))
	mux.HandleFunc("POST /fingerprint", s.recover(s.handleFingerprint))
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.engine.Ready() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleFingerprint(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req []engine.Input
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON request body"})
		return
	}

	resp := make([]engine.Result, len(req))
	for i, item := range req {
		resp[i] = safeFingerprint(s.engine, item)
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) recover(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("request recovered: %v", rec)
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			}
		}()
		next(w, r)
	}
}

func safeFingerprint(e *engine.Engine, in engine.Input) (out engine.Result) {
	defer func() {
		if recover() != nil {
			out = engine.Result{
				IP:       in.IP,
				Port:     in.Port,
				Protocol: "unknown",
			}
		}
	}()
	return e.Fingerprint(in)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
