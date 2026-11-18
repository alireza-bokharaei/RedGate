package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRequestedInProcessFirewallEnforcementFailsClosed(t *testing.T) {
	if _, err := BuildEgressPolicy([]string{"192.0.2.1"}, true); err == nil {
		t.Fatal("rendered rules must not be advertised as an installed firewall")
	}
	policy, err := BuildEgressPolicy([]string{"192.0.2.1"}, false)
	if err != nil || policy.Mode != "policy_validated_only" {
		t.Fatalf("incorrect firewall status: %v %v", policy, err)
	}
}

func TestAvailableLanguagesReflectInstalledToolsAndEvidenceOnlyMode(t *testing.T) {
	binaries := t.TempDir()
	t.Setenv("PATH", binaries)
	if languages := availableLanguages(false); len(languages) != 0 {
		t.Fatalf("empty PATH advertised adapters: %v", languages)
	}
	for _, name := range []string{"python3", "bash"} {
		if err := os.WriteFile(filepath.Join(binaries, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if languages := availableLanguages(false); !reflect.DeepEqual(languages, []string{"python", "bash"}) {
		t.Fatalf("wrong lite capabilities: %v", languages)
	}
	for _, name := range []string{"go", "node"} {
		if err := os.WriteFile(filepath.Join(binaries, name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if languages := availableLanguages(false); !reflect.DeepEqual(languages, []string{"python", "bash", "go", "javascript"}) {
		t.Fatalf("wrong full capabilities: %v", languages)
	}
	if languages := availableLanguages(true); len(languages) != 0 {
		t.Fatalf("evidence-only mode advertised adapters: %v", languages)
	}
}
