"""Documentation directory policy helpers for technical documentation workflows."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

_MISSING = object()


def _resolve_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _coerce_path_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list | tuple):
        result: list[str] = []
        for item in value:
            if item is None:
                continue
            text = str(item).strip()
            if text:
                result.append(text)
        return result
    raise ValueError(
        "[documentation].allowed_addon_dirs must be a string or list of strings"
    )


@dataclass(frozen=True)
class DocumentationDirectoryPolicy:
    configured: bool
    allowed_dirs: tuple[Path, ...]

    def is_allowed(self, addon_root: str | Path) -> bool:
        if not self.configured:
            return True
        root = _resolve_path(Path(addon_root))
        return any(_is_relative_to(root, allowed) for allowed in self.allowed_dirs)

    def intersects(self, path: str | Path) -> bool:
        if not self.configured:
            return True
        candidate = _resolve_path(Path(path))
        for allowed in self.allowed_dirs:
            if _is_relative_to(candidate, allowed) or _is_relative_to(
                allowed, candidate
            ):
                return True
        return False

    def display_allowed_dirs(self, *, base_dir: Path) -> list[str]:
        resolved_base = _resolve_path(base_dir)
        result: list[str] = []
        for path in self.allowed_dirs:
            try:
                result.append(path.relative_to(resolved_base).as_posix())
            except ValueError:
                result.append(path.as_posix())
        return result


class DocumentationTargetNotAllowedError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        addon_root: str,
        allowed_dirs: list[str],
    ) -> None:
        super().__init__(message)
        self.addon_root = addon_root
        self.allowed_dirs = allowed_dirs


def load_documentation_directory_policy(
    env_config: dict[str, Any],
    *,
    path_base_dir: str | Path | None,
) -> DocumentationDirectoryPolicy:
    documentation_block = env_config.get("documentation")
    configured = False
    raw_value: Any = _MISSING

    if isinstance(documentation_block, dict):
        configured = "allowed_addon_dirs" in documentation_block
        raw_value = documentation_block.get("allowed_addon_dirs", _MISSING)

    if raw_value is _MISSING and "documentation_allowed_addon_dirs" in env_config:
        configured = True
        raw_value = env_config.get("documentation_allowed_addon_dirs")

    if raw_value is _MISSING:
        return DocumentationDirectoryPolicy(configured=False, allowed_dirs=())

    base_dir = (
        _resolve_path(Path(path_base_dir))
        if path_base_dir is not None
        else _resolve_path(Path.cwd())
    )
    values = _coerce_path_list(raw_value)
    allowed_dirs = tuple(
        _resolve_path(Path(value))
        if Path(value).expanduser().is_absolute()
        else _resolve_path(base_dir / value)
        for value in values
    )
    return DocumentationDirectoryPolicy(
        configured=configured, allowed_dirs=allowed_dirs
    )
