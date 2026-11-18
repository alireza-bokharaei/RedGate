package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

var version = "2.1.0"

func main() {
	// A self-contained Docker healthcheck; no curl or shell is needed.
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		addr := os.Getenv("REDGATE_SANDBOX_ADDR")
		if addr == "" || addr == "0.0.0.0:8002" || addr == ":8002" {
			addr = "127.0.0.1:8002"
		}
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://" + addr + "/health")
		if err != nil {
			os.Exit(1)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	internalToken := os.Getenv("REDGATE_INTERNAL_TOKEN")
	if len(internalToken) < 16 {
		log.Fatal("FATAL: REDGATE_INTERNAL_TOKEN must be set (minimum 16 chars); refusing to start unauthenticated sandbox runner")
	}

	listenAddr := os.Getenv("REDGATE_SANDBOX_ADDR")
	if listenAddr == "" {
		listenAddr = "127.0.0.1:8002"
	}

	evidenceOnly := os.Getenv("REDGATE_SANDBOX_EVIDENCE_ONLY") == "true"
	cfg := DefaultSandboxConfig()
	runner, err := NewRunner(cfg)
	if err != nil {
		log.Fatalf("FATAL: failed to initialize sandbox runner: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/http-evidence", NewHTTPProbe().Handler(internalToken))

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		languages := availableLanguages(evidenceOnly)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":                   "ok",
			"service":                  "redgate-sandbox-runner",
			"runtime":                  "go",
			"version":                  version,
			"http_evidence":            true,
			"evidence_only":            evidenceOnly,
			"egress_firewall_enforced": false,
			"workspace_root":           cfg.WorkspaceRoot,
			"max_concurrent":           cfg.MaxConcurrent,
			"max_timeout_sec":          cfg.MaxTimeoutSec,
			"max_memory_mb":            cfg.MaxMemoryMB,
			"prlimit_enabled":          runner.hasPrlim,
			"languages":                languages,
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

		if evidenceOnly {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "script execution is disabled in evidence-only mode"})
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

// Report the binaries actually installed, not a hardcoded full-image promise.
func availableLanguages(evidenceOnly bool) []string {
	languages := []string{}
	if evidenceOnly {
		return languages
	}
	for _, language := range []struct{ name, binary string }{
		{"python", "python3"}, {"bash", "bash"}, {"go", "go"}, {"javascript", "node"},
	} {
		if _, err := exec.LookPath(language.binary); err == nil {
			languages = append(languages, language.name)
		}
	}
	return languages
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
