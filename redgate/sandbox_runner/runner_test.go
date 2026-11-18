package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

func newTestRunner(t *testing.T) *Runner {
	t.Helper()
	cfg := DefaultSandboxConfig()
	cfg.WorkspaceRoot = "/tmp/sandbox-test"
	r, err := NewRunner(cfg)
	if err != nil {
		t.Fatalf("NewRunner failed: %v", err)
	}
	return r
}

func TestMultiLanguageExecution(t *testing.T) {
	r := newTestRunner(t)
	cases := []struct {
		name     string
		lang     string
		script   string
		expected string
	}{
		{
			name:     "python",
			lang:     "python",
			script:   "import json\nprint(json.dumps({'lang': 'python', 'ok': True}))\n",
			expected: `"lang": "python"`,
		},
		{
			name:     "bash",
			lang:     "bash",
			script:   "#!/usr/bin/env bash\nset -euo pipefail\nprintf 'bash-target=%s\\n' \"$REDGATE_TARGET\"\n",
			expected: "bash-target=198.51.100.10",
		},
		{
			name:     "javascript",
			lang:     "javascript",
			script:   "const crypto = require('node:crypto');\nconsole.log('js-sha=' + crypto.createHash('sha256').update('ok').digest('hex').slice(0,8));\n",
			expected: "js-sha=",
		},
		{
			name:   "go",
			lang:   "go",
			script: "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"go-sandbox-ok\") }\n",
			expected: "go-sandbox-ok",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := r.Execute(context.Background(), ExecuteRequest{
				JobID:           "test-" + tc.name,
				Language:        tc.lang,
				Script:          tc.script,
				ExpectedSHA256:  sha256Hex(tc.script),
				Target:          "198.51.100.10",
				PinnedIPs:       []string{"198.51.100.10"},
				EgressAllowlist: []string{"192.0.2.0/24", "198.51.100.10"},
				TimeoutSec:      10,
				MemoryLimitMB:   128,
				MaxOutputBytes:  8192,
			})
			if res.ExitCode != 0 {
				t.Fatalf("%s exited %d: err=%s stderr=%s", tc.name, res.ExitCode, res.Error, res.Stderr)
			}
			if !strings.Contains(res.Stdout, tc.expected) {
				t.Fatalf("expected stdout containing %q, got %q", tc.expected, res.Stdout)
			}
			// Ephemeral directory must be deleted after completion.
			if _, err := os.Stat(res.SandboxDir); !os.IsNotExist(err) {
				t.Fatalf("expected sandbox directory %s to be removed", res.SandboxDir)
			}
		})
	}
}

func TestHashMismatchRejected(t *testing.T) {
	r := newTestRunner(t)
	res := r.Execute(context.Background(), ExecuteRequest{
		JobID:          "tampered",
		Language:       "python",
		Script:         "print('hi')",
		ExpectedSHA256: "deadbeef",
		Target:         "198.51.100.10",
	})
	if res.ExitCode != -1 || !strings.Contains(res.Error, "SHA-256 mismatch") {
		t.Fatalf("expected SHA-256 mismatch error, got %+v", res)
	}
}

func TestMetadataEgressBlocked(t *testing.T) {
	r := newTestRunner(t)
	script := "print('should never run')"
	res := r.Execute(context.Background(), ExecuteRequest{
		JobID:          "meta-block",
		Language:       "python",
		Script:         script,
		ExpectedSHA256: sha256Hex(script),
		Target:         "169.254.169.254",
		PinnedIPs:      []string{"169.254.169.254"},
	})
	if res.ExitCode != -1 || !strings.Contains(res.Error, "metadata") {
		t.Fatalf("expected cloud metadata rejection, got %+v", res)
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	r := newTestRunner(t)
	script := "import time\ntime.sleep(10)\nprint('late')\n"
	res := r.Execute(context.Background(), ExecuteRequest{
		JobID:          "timeout-test",
		Language:       "python",
		Script:         script,
		ExpectedSHA256: sha256Hex(script),
		Target:         "198.51.100.10",
		PinnedIPs:      []string{"198.51.100.10"},
		TimeoutSec:     1,
	})
	if !res.TimedOut || res.ExitCode != 124 {
		t.Fatalf("expected timeout exit 124, got %+v", res)
	}
}

func TestHostSecretsScrubbed(t *testing.T) {
	t.Setenv("SUPER_SECRET_HOST_KEY", "never-leak-me")
	r := newTestRunner(t)
	script := "#!/usr/bin/env bash\nenv\n"
	res := r.Execute(context.Background(), ExecuteRequest{
		JobID:          "env-scrub",
		Language:       "bash",
		Script:         script,
		ExpectedSHA256: sha256Hex(script),
		Target:         "198.51.100.10",
		PinnedIPs:      []string{"198.51.100.10"},
		TimeoutSec:     5,
	})
	if strings.Contains(res.Stdout, "SUPER_SECRET_HOST_KEY") || strings.Contains(res.Stdout, "never-leak-me") {
		t.Fatalf("host secret leaked into sandbox env: %s", res.Stdout)
	}
}
