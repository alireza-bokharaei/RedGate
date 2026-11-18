package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	internalToken := os.Getenv("REDGATE_INTERNAL_TOKEN")
	if len(internalToken) < 16 {
		log.Fatal("FATAL: REDGATE_INTERNAL_TOKEN must be set (minimum 16 chars); refusing to start unauthenticated sandbox runner")
	}

	listenAddr := os.Getenv("REDGATE_SANDBOX_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8002"
	}

	cfg := DefaultSandboxConfig()
	runner, err := NewRunner(cfg)
	if err != nil {
		log.Fatalf("FATAL: failed to initialize sandbox runner: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":          "ok",
			"service":         "redgate-sandbox-runner",
			"runtime":         "go",
			"workspace_root":  cfg.WorkspaceRoot,
			"max_concurrent":  cfg.MaxConcurrent,
			"max_timeout_sec": cfg.MaxTimeoutSec,
			"max_memory_mb":   cfg.MaxMemoryMB,
			"prlimit_enabled": runner.hasPrlim,
			"languages":       []string{"python", "bash", "go", "javascript"},
		})
	})

	mux.HandleFunc("/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		provided := r.Header.Get("X-Internal-Service-Token")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(internalToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized internal caller"})
			return
		}

		// Bound request body to 128 KB to prevent memory exhaustion.
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
		var req ExecuteRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request payload: " + err.Error()})
			return
		}

		result := runner.Execute(r.Context(), req)
		status := http.StatusOK
		if result.Error != "" && result.ExitCode == -1 {
			status = http.StatusUnprocessableEntity
		}
		writeJSON(w, status, result)
	})

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("[sandbox-runner] listening on %s (root=%s, max_concurrent=%d, prlimit=%v)",
			listenAddr, cfg.WorkspaceRoot, cfg.MaxConcurrent, runner.hasPrlim)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("[sandbox-runner] shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
