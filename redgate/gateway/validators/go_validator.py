"""Go static validator: gofmt + go list import allowlist + go vet + go build check."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from gateway.validators.base import ValidationResult

FORBIDDEN_GO_DIRECTIVE_RE = re.compile(
    r"//go:(?:linkname|noescape|uintptrescapes|nosplit|cgo_[a-z_]+)", re.IGNORECASE
)
PACKAGE_MAIN_RE = re.compile(r"^\s*package\s+main\b", re.MULTILINE)


def validate_go_script(
    result: ValidationResult,
    script: str,
    policy: dict[str, Any],
) -> None:
    """Validate Go formatting/syntax, strict import allowlist, go vet, and static build."""
    go_bin = shutil.which("go")
    gofmt_bin = shutil.which("gofmt")
    if not go_bin or not gofmt_bin:
        result.add_check(
            "go_toolchain",
            False,
            "Go toolchain (go/gofmt) not installed; refusing unverified Go script.",
        )
        return

    if not PACKAGE_MAIN_RE.search(script):
        result.add_check("go_package_check", False, "Go script must declare 'package main'.")
        return

    if FORBIDDEN_GO_DIRECTIVE_RE.search(script):
        result.add_check(
            "go_directive_check",
            False,
            "Forbidden compiler directive (//go:linkname, //go:cgo_*, etc.) detected.",
        )
        return
    result.add_check("go_directive_check", True, "No unsafe compiler or CGo directives detected.")

    allowed_imports = set(policy.get("allowed_imports", []))
    cache_dir = Path("/tmp/sandbox/.go-build-cache")
    cache_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="redgate-val-go-") as tmpdir:
        tmp = Path(tmpdir)
        # Place module in a child directory so Go never treats cwd as $TMPDIR root.
        src_dir = tmp / "mod"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "go.mod").write_text("module redgateval\n\ngo 1.22\n", encoding="utf-8")
        src_path = src_dir / "main.go"
        src_path.write_text(script, encoding="utf-8")

        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": tmpdir,
            "TMPDIR": tmpdir,
            "GOCACHE": str(cache_dir),
            "GOPATH": str(tmp / "gopath"),
            "CGO_ENABLED": "0",
            "GOPROXY": "off",
            "GOSUMDB": "off",
        }

        # 1. gofmt syntax & formatting verification.
        fmt_proc = subprocess.run(
            [gofmt_bin, "-e", "-d", str(src_path)],
            capture_output=True,
            text=True,
            timeout=10,
            env=safe_env,
            check=False,
        )
        if fmt_proc.returncode != 0:
            result.add_check(
                "go_gofmt",
                False,
                f"gofmt syntax error: {fmt_proc.stderr.strip()[:260]}",
            )
            return
        if fmt_proc.stdout.strip():
            result.warnings.append("Script has minor formatting diffs relative to gofmt.")
            result.add_check("go_gofmt", True, "gofmt syntax check passed (style diff noted).")
        else:
            result.add_check("go_gofmt", True, "gofmt syntax and canonical formatting verified.")

        # 2. Exact compiler-parsed import allowlist via `go list -json -e`.
        list_proc = subprocess.run(
            [go_bin, "list", "-e", "-json", "."],
            cwd=str(src_dir),
            capture_output=True,
            text=True,
            timeout=15,
            env=safe_env,
            check=False,
        )
        if list_proc.returncode != 0 or not list_proc.stdout.strip():
            result.add_check(
                "go_import_allowlist",
                False,
                f"go list failed: {list_proc.stderr.strip()[:240]}",
            )
            return
        pkg_meta = json.loads(list_proc.stdout)
        imports: list[str] = pkg_meta.get("Imports", []) or []
        disallowed = [imp for imp in imports if imp not in allowed_imports]
        if disallowed:
            result.add_check(
                "go_import_allowlist",
                False,
                f"Disallowed Go package import(s): {', '.join(disallowed)}.",
            )
            return
        result.add_check(
            "go_import_allowlist",
            True,
            f"Verified imports: {', '.join(imports) if imports else 'none'}.",
        )

        # 3. go vet static analysis.
        vet_proc = subprocess.run(
            [go_bin, "vet", "./..."],
            cwd=str(src_dir),
            capture_output=True,
            text=True,
            timeout=25,
            env=safe_env,
            check=False,
        )
        if vet_proc.returncode != 0:
            result.add_check(
                "go_vet",
                False,
                f"go vet rejected script: {vet_proc.stderr.strip()[:280]}",
            )
            return
        result.add_check("go_vet", True, "go vet passed with zero diagnostics.")

        # 4. Static compilation check (CGO_ENABLED=0, GOPROXY=off).
        out_bin = tmp / "check_bin"
        build_proc = subprocess.run(
            [go_bin, "build", "-trimpath", "-buildvcs=false", "-o", str(out_bin), "."],
            cwd=str(src_dir),
            capture_output=True,
            text=True,
            timeout=30,
            env=safe_env,
            check=False,
        )
        if build_proc.returncode != 0:
            result.add_check(
                "go_build",
                False,
                f"go build failed: {build_proc.stderr.strip()[:280]}",
            )
            return
        result.add_check("go_build", True, "Static build check passed (CGO_ENABLED=0, offline).")
