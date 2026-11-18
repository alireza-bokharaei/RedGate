"""Python static validator: ast.parse + import allowlist + dangerous AST node check."""

from __future__ import annotations

import ast
from typing import Any

from gateway.validators.base import ValidationResult

FORBIDDEN_BUILTIN_CALLS: frozenset[str] = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
        "breakpoint",
        "input",
        "memoryview",
    }
)

FORBIDDEN_DUNDER_ATTRS: frozenset[str] = frozenset(
    {
        "__subclasses__",
        "__bases__",
        "__mro__",
        "__globals__",
        "__builtins__",
        "__code__",
        "__closure__",
        "__class__",
        "__dict__",
        "__loader__",
        "__spec__",
        "tb_frame",
        "f_globals",
        "f_locals",
        "f_builtins",
        "system",
        "popen",
        "spawn",
    }
)


class _SecurityASTVisitor(ast.NodeVisitor):
    """Walks a Python AST enforcing import allowlists and blocking escape primitives."""

    def __init__(self, allowed_imports: set[str], forbidden_imports: set[str]) -> None:
        self.allowed_imports = allowed_imports
        self.forbidden_imports = forbidden_imports
        self.import_violations: list[str] = []
        self.ast_violations: list[str] = []
        self.seen_imports: list[str] = []

    def _check_module(self, mod: str, lineno: int) -> None:
        self.seen_imports.append(mod)
        root = mod.split(".", 1)[0]
        if mod in self.forbidden_imports or root in self.forbidden_imports:
            self.import_violations.append(f"line {lineno}: forbidden module '{mod}'")
            return
        if mod not in self.allowed_imports and root not in self.allowed_imports:
            self.import_violations.append(f"line {lineno}: module '{mod}' not in allowlist")

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_module(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level and node.level > 0:
            self.import_violations.append(f"line {node.lineno}: relative imports are disallowed")
            return
        if not node.module:
            self.import_violations.append(f"line {node.lineno}: empty module import disallowed")
            return
        self._check_module(node.module, node.lineno)
        for alias in node.names:
            if alias.name == "*":
                self.import_violations.append(
                    f"line {node.lineno}: wildcard 'from {node.module} import *' is disallowed"
                )
            else:
                qualified = f"{node.module}.{alias.name}"
                if qualified in self.forbidden_imports:
                    self.import_violations.append(
                        f"line {node.lineno}: forbidden symbol '{qualified}'"
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            fn = node.func.id
            if fn in FORBIDDEN_BUILTIN_CALLS:
                self.ast_violations.append(f"line {node.lineno}: forbidden builtin call '{fn}()'")
            elif fn == "open":
                self._validate_open_call(node)
        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in {"system", "popen", "execv", "execve", "execvp", "fork", "kill"}:
                self.ast_violations.append(f"line {node.lineno}: forbidden OS/process call '.{attr}()'")
            elif attr in {"write_text", "write_bytes", "unlink", "rmdir", "mkdir"}:
                self._validate_path_mutation(node, attr)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in FORBIDDEN_DUNDER_ATTRS and node.attr.startswith("__"):
            self.ast_violations.append(
                f"line {node.lineno}: forbidden introspection attribute '{node.attr}'"
            )
        if node.attr in {"tb_frame", "f_globals", "f_locals", "f_builtins"}:
            self.ast_violations.append(
                f"line {node.lineno}: forbidden frame attribute '{node.attr}'"
            )
        self.generic_visit(node)

    def _validate_open_call(self, node: ast.Call) -> None:
        # Determine mode argument (arg #2 or keyword 'mode').
        mode = "r"
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
            mode = node.args[1].value
        elif len(node.args) >= 2:
            self.ast_violations.append(f"line {node.lineno}: open() mode must be a string literal")
            return
        for kw in node.keywords:
            if kw.arg == "mode":
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    mode = kw.value.value
                else:
                    self.ast_violations.append(f"line {node.lineno}: open() mode must be a string literal")
                    return

        # Any open() call must reference a literal path inside /tmp/sandbox.
        if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                self.ast_violations.append(
                    f"line {node.lineno}: write open() requires literal path starting with '/tmp/sandbox/'"
                )
            else:
                self.ast_violations.append(
                    f"line {node.lineno}: open() requires literal path inside '/tmp/sandbox/'"
                )
            return

        path_val = node.args[0].value
        if not path_val.startswith("/tmp/sandbox/") or ".." in path_val:
            self.ast_violations.append(
                f"line {node.lineno}: open('{path_val}') outside '/tmp/sandbox/' is prohibited"
            )

    def _validate_path_mutation(self, node: ast.Call, method: str) -> None:
        # Allow Path('/tmp/sandbox/foo.json').write_text(...) only with literal /tmp/sandbox path.
        receiver = node.func.value
        if (
            isinstance(receiver, ast.Call)
            and receiver.args
            and isinstance(receiver.args[0], ast.Constant)
            and isinstance(receiver.args[0].value, str)
            and receiver.args[0].value.startswith("/tmp/sandbox/")
            and ".." not in receiver.args[0].value
        ):
            return
        self.ast_violations.append(
            f"line {node.lineno}: '.{method}()' allowed only on literal Path('/tmp/sandbox/...')"
        )


def validate_python_script(
    result: ValidationResult,
    script: str,
    policy: dict[str, Any],
) -> None:
    """Run AST syntax parse, strict import allowlist, and sandbox-escape inspection."""
    try:
        tree = ast.parse(script, filename="<untrusted_script.py>", mode="exec")
        result.add_check("python_ast_parse", True, "Valid Python 3 syntax parsed via ast.parse.")
    except SyntaxError as exc:
        result.add_check(
            "python_ast_parse",
            False,
            f"SyntaxError at line {exc.lineno}: {exc.msg}",
        )
        return

    allowed = set(policy.get("allowed_imports", []))
    forbidden = set(policy.get("forbidden_imports", []))

    visitor = _SecurityASTVisitor(allowed_imports=allowed, forbidden_imports=forbidden)
    visitor.visit(tree)

    if visitor.import_violations:
        result.add_check(
            "python_import_allowlist",
            False,
            "; ".join(visitor.import_violations[:5]),
        )
    else:
        summary = ", ".join(sorted(set(visitor.seen_imports))) or "none"
        result.add_check("python_import_allowlist", True, f"Verified imports: {summary}.")

    if visitor.ast_violations:
        result.add_check(
            "python_ast_security",
            False,
            "; ".join(visitor.ast_violations[:5]),
        )
    else:
        result.add_check(
            "python_ast_security",
            True,
            "No dynamic execution, forbidden builtins, dunder escapes, or unsafe file writes.",
        )
