"""Static lint: assert protocol handlers don't mutate self outside __init__.

Handler instances are shared across every connection on a port, so any
`self.foo = ...` in on_connect / on_data / on_close / on_datagram is a
session-state leak waiting to happen. This test walks each handler
module with `ast` and fails if it catches one.

Whitelist of attributes that are intentionally set post-__init__ (none
today, but the list exists so future additions can be approved
explicitly).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PROTOCOLS_DIR = Path(__file__).resolve().parent.parent / "honeyknot" / "protocols"

HANDLER_METHODS = {"on_connect", "on_data", "on_close", "on_datagram"}
WHITELIST: dict[str, set[str]] = {}

EXEMPT_FILES = {"__init__.py", "base.py", "regex.py"}


def _collect_violations(path: Path) -> list[str]:
    """Return descriptions of any `self.X = ...` inside a handler method
    body, excluding attributes in the whitelist for that module."""
    tree = ast.parse(path.read_text(), filename=str(path))
    whitelist = WHITELIST.get(path.stem, set())
    violations: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for method in node.body:
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if method.name not in HANDLER_METHODS:
                continue
            for sub in ast.walk(method):
                if isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        name = _self_attr(target)
                        if name and name not in whitelist:
                            violations.append(
                                f"{path.name}:{sub.lineno} — "
                                f"{node.name}.{method.name} assigns "
                                f"self.{name}"
                            )
                elif isinstance(sub, ast.AugAssign):
                    name = _self_attr(sub.target)
                    if name and name not in whitelist:
                        violations.append(
                            f"{path.name}:{sub.lineno} — "
                            f"{node.name}.{method.name} augments "
                            f"self.{name}"
                        )
    return violations


def _self_attr(target: ast.AST) -> str | None:
    if (isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id == "self"):
        return target.attr
    return None


@pytest.mark.parametrize(
    "path",
    sorted(p for p in PROTOCOLS_DIR.glob("*.py") if p.name not in EXEMPT_FILES),
    ids=lambda p: p.name,
)
def test_no_self_mutation_in_handler_methods(path):
    violations = _collect_violations(path)
    assert not violations, (
        "Protocol handlers share one instance across all connections. "
        "Move per-session state onto ctx.state.\n  "
        + "\n  ".join(violations)
    )
