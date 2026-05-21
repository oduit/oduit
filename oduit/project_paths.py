"""Helpers for deriving a portable project path base."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

PathBaseSource = Literal["explicit", "local_config", "git", "cwd"]


def _resolve_path(path: str | Path, *, start: Path | None = None) -> Path:
    value = Path(path).expanduser()
    if not value.is_absolute():
        value = ((start or Path.cwd().resolve(strict=False)) / value).resolve(
            strict=False
        )
    return value.resolve(strict=False)


@dataclass(frozen=True)
class ProjectPathContext:
    """Resolved base directory used for portable documentation paths."""

    base_dir: Path
    source: PathBaseSource

    def relative(self, path: str | Path) -> str:
        """Return a path relative to ``base_dir`` when possible."""

        resolved = _resolve_path(path, start=self.base_dir)
        try:
            value = resolved.relative_to(self.base_dir).as_posix()
        except ValueError:
            return resolved.as_posix()
        return value or "."

    def resolve_user_path(self, value: str | Path) -> Path:
        """Resolve a user-provided path relative to ``base_dir``."""

        return _resolve_path(value, start=self.base_dir)


def find_git_root(start: Path) -> Path | None:
    """Walk parents from ``start`` until a git root is found."""

    current_start = start if start.is_dir() else start.parent
    for current in (current_start, *current_start.parents):
        if (current / ".git").exists():
            return current.resolve(strict=False)
    return None


def resolve_project_path_context(
    *,
    config_path: str | None,
    explicit_base: str | None = None,
    start: Path | None = None,
) -> ProjectPathContext:
    """Resolve the best available portable base directory for documentation paths."""

    start_path = (start or Path.cwd()).resolve(strict=False)

    if explicit_base:
        return ProjectPathContext(
            _resolve_path(explicit_base, start=start_path),
            "explicit",
        )

    if config_path:
        cfg = _resolve_path(config_path, start=start_path)
        if cfg.name == ".oduit.toml":
            return ProjectPathContext(cfg.parent, "local_config")
        git_root = find_git_root(cfg.parent)
        if git_root is not None:
            return ProjectPathContext(git_root, "git")

    git_root = find_git_root(start_path)
    if git_root is not None:
        return ProjectPathContext(git_root, "git")

    return ProjectPathContext(start_path, "cwd")
