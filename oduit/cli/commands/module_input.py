"""Helpers for resolving CLI module-list input."""

from __future__ import annotations

import re
import sys

_MODULE_SEPARATOR_RE = re.compile(r"[\s,]+")


def parse_module_names(raw_value: str | None) -> list[str]:
    """Parse comma- or whitespace-separated module names."""
    if raw_value is None:
        return []
    return [item for item in _MODULE_SEPARATOR_RE.split(raw_value.strip()) if item]


def read_piped_stdin() -> str | None:
    """Return stdin content only when stdin is non-interactive."""
    stdin = sys.stdin
    try:
        if stdin.isatty():
            return None
    except (AttributeError, ValueError):
        return None

    raw_value = stdin.read().strip()
    return raw_value or None


def resolve_module_names(raw_value: str | None) -> tuple[list[str], str | None]:
    """Resolve module names from an argument first, then piped stdin."""
    module_names = parse_module_names(raw_value)
    if module_names:
        return module_names, "argument"

    stdin_value = read_piped_stdin()
    module_names = parse_module_names(stdin_value)
    if module_names:
        return module_names, "stdin"

    return [], None


def resolve_module_argument(raw_value: str | None) -> tuple[str | None, str | None]:
    """Resolve module names and format them for Odoo's comma-separated option."""
    module_names, source = resolve_module_names(raw_value)
    if not module_names:
        return None, None
    return ",".join(module_names), source
