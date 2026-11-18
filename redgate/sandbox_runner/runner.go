package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ExecuteRequest represents a validated script execution job dispatched by Gateway.
type ExecuteRequest struct {
	JobID           string   `json:"job_id"`
	Language        string   `json:"language"`
	Script          string   `json:"script"`
	ExpectedSHA256  string   `json:"expected_sha256"`
	Target          string   `json:"target"`
	PinnedIPs       []string `json:"pinned_ips"`
	EgressAllowlist []string `json:"egress_allowlist"`
	TimeoutSec      int      `json:"timeout_sec"`
	MemoryLimitMB   int      `json:"memory_limit_mb"`
	MaxOutputBytes  int      `json:"max_output_bytes"`
}

// ExecuteResponse captures bounded execution output and resource telemetry.
type ExecuteResponse struct {
	JobID           string   `json:"job_id"`
	Language        string   `json:"language"`
	ExitCode        int      `json:"exit_code"`
	Stdout          string   `json:"stdout"`
	Stderr          string   `json:"stderr"`
	StdoutTruncated bool     `json:"stdout_truncated"`
	StderrTruncated bool     `json:"stderr_truncated"`
	TimedOut        bool     `json:"timed_out"`
	DurationMs      int64    `json:"duration_ms"`
	SandboxDir      string   `json:"sandbox_dir"`
	EgressMode      string   `json:"egress_mode"`
	EgressRules     []string `json:"egress_rules,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// SandboxConfig holds global hard ceilings that individual requests cannot exceed.
type SandboxConfig struct {
	WorkspaceRoot   string
	MaxTimeoutSec   int
	MaxMemoryMB     int
	MaxFileSizeMB   int
	MaxOpenFiles    int
	MaxOutputBytes  int
	MaxScriptBytes  int
	MaxConcurrent   int
	EnforceIptables bool
}

// DefaultSandboxConfig returns conservative resource limits for untrusted scripts.
func DefaultSandboxConfig() SandboxConfig {
	root := os.Getenv("REDGATE_SANDBOX_ROOT")
	if root == "" {
		root = "/tmp/sandbox"
	}
	return SandboxConfig{
		WorkspaceRoot:   root,
		MaxTimeoutSec:   30,
		MaxMemoryMB:     256,
		MaxFileSizeMB:   8,
		MaxOpenFiles:    128,
		MaxOutputBytes:  65536,
		MaxScriptBytes:  32768,
		MaxConcurrent:   4,
		EnforceIptables: os.Getenv("REDGATE_ENFORCE_IPTABLES") == "true",
	}
}

// limitedBuffer captures at most max bytes and marks truncation without failing writes.
type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	max       int
	truncated bool
}

func newLimitedBuffer(maxBytes int) *limitedBuffer {
	return &limitedBuffer{max: maxBytes}
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	total := len(p)
	remaining := l.max - l.buf.Len()
	if remaining <= 0 {
		l.truncated = true
		return total, nil
	}
	if len(p) > remaining {
		_, _ = l.buf.Write(p[:remaining])
		l.truncated = true
		return total, nil
	}
	_, _ = l.buf.Write(p)
	return total, nil
}

func (l *limitedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Runner executes validated scripts inside ephemeral, resource-bounded workspaces.
type Runner struct {
	cfg       SandboxConfig
	sem       chan struct{}
	hasPrlim  bool
	prlimPath string
}

// NewRunner initializes the workspace root and concurrency limiter.
func NewRunner(cfg SandboxConfig) (*Runner, error) {
	cleanRoot := filepath.Clean(cfg.WorkspaceRoot)
	if !strings.HasPrefix(cleanRoot, "/tmp/") {
		return nil, fmt.Errorf("sandbox workspace root must reside under /tmp, got %q", cleanRoot)
	}
	if err := os.MkdirAll(cleanRoot, 0o700); err != nil {
		return nil, fmt.Errorf("failed to initialize sandbox root %q: %w", cleanRoot, err)
	}
	prlimPath, err := exec.LookPath("prlimit")
	return &Runner{
		cfg:       cfg,
		sem:       make(chan struct{}, cfg.MaxConcurrent),
		hasPrlim:  err == nil,
		prlimPath: prlimPath,
	}, nil
}

// Execute validates integrity, prepares an ephemeral sandbox directory, enforces
// timeout/memory/file/env constraints, runs the script, and cleans up all artifacts.
func (r *Runner) Execute(parentCtx context.Context, req ExecuteRequest) ExecuteResponse {
	start := time.Now()
	jobID := sanitizeJobID(req.JobID)
	resp := ExecuteResponse{
		JobID:    jobID,
		Language: strings.ToLower(strings.TrimSpace(req.Language)),
		ExitCode: -1,
	}

	if len(req.Script) == 0 {
		resp.Error = "empty script payload"
		return resp
	}
	if len(req.Script) > r.cfg.MaxScriptBytes {
		resp.Error = fmt.Sprintf("script exceeds maximum size (%d bytes)", r.cfg.MaxScriptBytes)
		return resp
	}

	// Cryptographic integrity check: guarantees the script executed is byte-for-byte
	// identical to the script approved by the Gateway validation pipeline.
	actualHash := sha256Hex(req.Script)
	if req.ExpectedSHA256 == "" || !strings.EqualFold(actualHash, strings.TrimSpace(req.ExpectedSHA256)) {
		resp.Error = "script SHA-256 mismatch: execution refused (unvalidated payload)"
		return resp
	}

	// Build and verify egress policy (blocks cloud metadata IPs unconditionally).
	candidates := append([]string{}, req.PinnedIPs...)
	candidates = append(candidates, req.EgressAllowlist...)
	egress, err := BuildEgressPolicy(candidates, r.cfg.EnforceIptables)
	if err != nil {
		resp.Error = fmt.Sprintf("egress policy rejected: %v", err)
		return resp
	}
	resp.EgressMode = egress.Mode
	resp.EgressRules = egress.RenderIptablesRules()

	// Acquire bounded concurrency slot.
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-parentCtx.Done():
		resp.Error = "request cancelled while waiting for sandbox slot"
		return resp
	}

	// Clamp resource budgets to hard runner ceilings.
	timeoutSec := clampInt(req.TimeoutSec, 1, r.cfg.MaxTimeoutSec, 10)
	memMB := clampInt(req.MemoryLimitMB, 32, r.cfg.MaxMemoryMB, 128)
	maxOut := clampInt(req.MaxOutputBytes, 1024, r.cfg.MaxOutputBytes, r.cfg.MaxOutputBytes)

	// Create isolated per-job workspace under /tmp/sandbox and ensure deletion.
	jobDir, err := os.MkdirTemp(r.cfg.WorkspaceRoot, "job-"+jobID+"-")
	if err != nil {
		resp.Error = fmt.Sprintf("failed to allocate sandbox directory: %v", err)
		return resp
	}
	_ = os.Chmod(jobDir, 0o700)
	defer func() { _ = os.RemoveAll(jobDir) }()
	resp.SandboxDir = jobDir

	// Construct sanitized environment (zero host secrets inherited).
	safeEnv := buildSanitizedEnv(jobDir, memMB, req.Target, req.PinnedIPs, req.EgressAllowlist)

	// Materialize script and prepare execution command per language.
	execBin, execArgs, prepErr := r.prepareLanguageCommand(parentCtx, resp.Language, req.Script, jobDir, safeEnv, timeoutSec)
	if prepErr != nil {
		resp.DurationMs = time.Since(start).Milliseconds()
		resp.Stderr = truncateString(prepErr.Error(), maxOut)
		resp.Error = "sandbox preparation/compilation failed"
		return resp
	}

	// Wrap with kernel resource limits (prlimit) where available.
	finalBin, finalArgs := r.wrapWithResourceLimits(resp.Language, execBin, execArgs, timeoutSec, memMB)

	execCtx, cancel := context.WithTimeout(parentCtx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	cmd := exec.Command(finalBin, finalArgs...)
	cmd.Dir = jobDir
	cmd.Env = safeEnv
	// Isolate child in a dedicated process group so timeouts terminate all descendants.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutBuf := newLimitedBuffer(maxOut)
	stderrBuf := newLimitedBuffer(maxOut)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	if err := cmd.Start(); err != nil {
		resp.DurationMs = time.Since(start).Milliseconds()
		resp.Error = fmt.Sprintf("failed to start sandboxed process: %v", err)
		return resp
	}

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	var runErr error
	select {
	case runErr = <-waitDone:
	case <-execCtx.Done():
		resp.TimedOut = true
		if cmd.Process != nil {
			// Kill the entire process group (-pgid).
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		runErr = <-waitDone
	}

	resp.DurationMs = time.Since(start).Milliseconds()
	resp.Stdout = stdoutBuf.String()
	resp.Stderr = stderrBuf.String()
	resp.StdoutTruncated = stdoutBuf.truncated
	resp.StderrTruncated = stderrBuf.truncated

	if resp.TimedOut {
		resp.ExitCode = 124
		resp.Error = fmt.Sprintf("execution exceeded timeout of %ds (process group terminated)", timeoutSec)
		return resp
	}

	if runErr == nil {
		resp.ExitCode = 0
		return resp
	}

	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		resp.ExitCode = exitErr.ExitCode()
		return resp
	}

	resp.Error = fmt.Sprintf("sandbox runtime error: %v", runErr)
	return resp
}

func (r *Runner) prepareLanguageCommand(
	ctx context.Context,
	language string,
	script string,
	jobDir string,
	safeEnv []string,
	timeoutSec int,
) (string, []string, error) {
	switch language {
	case "python":
		scriptPath := filepath.Join(jobDir, "script.py")
		if err := os.WriteFile(scriptPath, []byte(script), 0o400); err != nil {
			return "", nil, err
		}
		// -I enables isolated mode (ignores PYTHON* env and user site-packages).
		return "python3", []string{"-I", "-B", scriptPath}, nil

	case "bash":
		scriptPath := filepath.Join(jobDir, "script.sh")
		if err := os.WriteFile(scriptPath, []byte(script), 0o400); err != nil {
			return "", nil, err
		}
		return "bash", []string{"--noprofile", "--norc", scriptPath}, nil

	case "javascript", "js":
		scriptPath := filepath.Join(jobDir, "script.js")
		if err := os.WriteFile(scriptPath, []byte(script), 0o400); err != nil {
			return "", nil, err
		}
		return "node", []string{"--disallow-code-generation-from-strings", scriptPath}, nil

	case "go":
		srcDir := filepath.Join(jobDir, "gosrc")
		// Runner-managed compiler cache stays outside jobDir and is never passed to the executed binary.
		cacheDir := filepath.Join(r.cfg.WorkspaceRoot, ".go-build-cache")
		if err := os.MkdirAll(srcDir, 0o700); err != nil {
			return "", nil, err
		}
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			return "", nil, err
		}
		goMod := "module sandboxjob\n\ngo 1.22\n"
		if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte(goMod), 0o400); err != nil {
			return "", nil, err
		}
		if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(script), 0o400); err != nil {
			return "", nil, err
		}
		binPath := filepath.Join(jobDir, "sandbox_bin")

		compileTimeout := time.Duration(timeoutSec+15) * time.Second
		compileCtx, cancel := context.WithTimeout(ctx, compileTimeout)
		defer cancel()

		buildCmd := exec.CommandContext(compileCtx, "go", "build", "-trimpath", "-buildvcs=false", "-o", binPath, ".")
		buildCmd.Dir = srcDir
		buildCmd.Env = append(append([]string{}, safeEnv...),
			"CGO_ENABLED=0",
			"GOCACHE="+cacheDir,
			"GOPATH="+filepath.Join(jobDir, "gopath"),
			"GOPROXY=off",
		)
		var buildErr bytes.Buffer
		buildCmd.Stderr = &buildErr
		if err := buildCmd.Run(); err != nil {
			return "", nil, fmt.Errorf("go build failed: %v: %s", err, buildErr.String())
		}
		// Remove source before running compiled binary to shrink workspace exposure.
		_ = os.RemoveAll(srcDir)
		_ = os.Chmod(binPath, 0o500)
		return binPath, []string{}, nil

	default:
		return "", nil, fmt.Errorf("unsupported script language %q", language)
	}
}

func (r *Runner) wrapWithResourceLimits(
	language string,
	bin string,
	args []string,
	timeoutSec int,
	memMB int,
) (string, []string) {
	if !r.hasPrlim {
		return bin, args
	}
	fsizeBytes := r.cfg.MaxFileSizeMB * 1024 * 1024
	cpuLimit := timeoutSec + 2

	prArgs := []string{
		fmt.Sprintf("--cpu=%d", cpuLimit),
		fmt.Sprintf("--fsize=%d", fsizeBytes),
		fmt.Sprintf("--nofile=%d", r.cfg.MaxOpenFiles),
		"--core=0",
	}
	// Python and Bash respect RLIMIT_AS tightly; Node (V8) and Go reserve large
	// virtual address ranges without committing RSS, so they use --max-old-space-size
	// and GOMEMLIMIT alongside container cgroup memory limits.
	if language == "python" || language == "bash" {
		asBytes := int64(memMB) * 4 * 1024 * 1024
		prArgs = append(prArgs, fmt.Sprintf("--as=%d", asBytes))
	}
	prArgs = append(prArgs, "--", bin)
	prArgs = append(prArgs, args...)
	return r.prlimPath, prArgs
}

func buildSanitizedEnv(jobDir string, memMB int, target string, pinnedIPs, allowlist []string) []string {
	return []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + jobDir,
		"TMPDIR=" + jobDir,
		"LANG=C.UTF-8",
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONNOUSERSITE=1",
		"NODE_OPTIONS=--max-old-space-size=" + strconv.Itoa(memMB),
		"GOMEMLIMIT=" + strconv.Itoa(memMB) + "MiB",
		"REDGATE_SANDBOX_DIR=" + jobDir,
		"REDGATE_TARGET=" + sanitizeEnvVal(target),
		"REDGATE_PINNED_IPS=" + sanitizeEnvVal(strings.Join(pinnedIPs, ",")),
		"REDGATE_EGRESS_ALLOWLIST=" + sanitizeEnvVal(strings.Join(allowlist, ",")),
	}
}

func sanitizeEnvVal(val string) string {
	val = strings.ReplaceAll(val, "\x00", "")
	val = strings.ReplaceAll(val, "\n", "")
	val = strings.ReplaceAll(val, "\r", "")
	if len(val) > 512 {
		return val[:512]
	}
	return val
}

func sanitizeJobID(raw string) string {
	var out strings.Builder
	for _, ch := range raw {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' {
			out.WriteRune(ch)
		}
		if out.Len() >= 24 {
			break
		}
	}
	if out.Len() > 0 {
		return out.String()
	}
	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	return hex.EncodeToString(rnd)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func clampInt(val, minVal, maxVal, fallback int) int {
	if val <= 0 {
		return fallback
	}
	if val < minVal {
		return minVal
	}
	if val > maxVal {
		return maxVal
	}
	return val
}

func truncateString(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes] + "\n...[truncated]"
}
