"""Shared helpers for addon-local technical documentation workflows."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .addons_path_manager import AddonsPathManager
from .api_models import AddonDocTarget
from .documentation_policy import (
    DocumentationDirectoryPolicy,
    DocumentationTargetNotAllowedError,
)
from .module_manager import ModuleManager

_MANIFEST_FILENAMES = ("__manifest__.py", "__openerp__.py")


def _resolve_path(path: Path) -> Path:
    return path.resolve(strict=False)


def _manifest_path_for_root(addon_root: Path) -> Path | None:
    for filename in _MANIFEST_FILENAMES:
        manifest_path = addon_root / filename
        if manifest_path.exists():
            return manifest_path
    return None


def _find_addon_root(candidate: Path) -> Path | None:
    search_root = candidate if candidate.is_dir() else candidate.parent
    for current in (search_root, *search_root.parents):
        if _manifest_path_for_root(current) is not None:
            return current
    return None


def _is_under_configured_addons_path(path: Path, configured_paths: list[Path]) -> bool:
    for configured_path in configured_paths:
        try:
            path.relative_to(configured_path)
        except ValueError:
            continue
        return True
    return False


def resolve_addon_documentation_target(
    env_config: dict[str, Any],
    target: str,
    *,
    path_base_dir: str | Path | None = None,
    documentation_policy: DocumentationDirectoryPolicy | None = None,
) -> AddonDocTarget:
    """Resolve a technical-documentation target to one concrete addon root."""

    raw_target = target[1:] if target.startswith("@") else target
    requested_path = Path(raw_target).expanduser()
    base_dir = (
        _resolve_path(Path(path_base_dir).expanduser())
        if path_base_dir is not None
        else _resolve_path(Path.cwd())
    )
    resolved_requested_path = (
        _resolve_path(requested_path)
        if requested_path.is_absolute()
        else _resolve_path(base_dir / requested_path)
    )

    path_manager = AddonsPathManager(env_config["addons_path"])
    configured_paths = [
        _resolve_path(Path(path).expanduser())
        for path in path_manager.get_configured_paths()
    ]
    warnings: list[str] = []
    policy = documentation_policy

    if resolved_requested_path.exists():
        addon_root = _find_addon_root(resolved_requested_path)
        if addon_root is None:
            raise FileNotFoundError(
                f"Path {target!r} does not resolve to an addon root with a manifest."
            )
        manifest_path = _manifest_path_for_root(addon_root)
        assert manifest_path is not None
        inside_configured_addons_path = _is_under_configured_addons_path(
            addon_root, configured_paths
        )
        if not inside_configured_addons_path:
            warnings.append(
                "The resolved addon path is outside the configured addons_path entries."
            )
        if policy is not None and not policy.is_allowed(addon_root):
            raise DocumentationTargetNotAllowedError(
                (
                    "Technical documentation is not allowed for addon target "
                    f"{target!r}; "
                    "the resolved addon root is outside "
                    "[documentation].allowed_addon_dirs."
                ),
                addon_root=addon_root.as_posix(),
                allowed_dirs=policy.display_allowed_dirs(base_dir=base_dir),
            )
        addon_root_str = addon_root.as_posix()
        return AddonDocTarget(
            module=addon_root.name,
            addon_root=addon_root_str,
            target_kind="path",
            manifest_path=manifest_path.as_posix(),
            inside_configured_addons_path=inside_configured_addons_path,
            warnings=warnings,
            candidate_addon_roots=[addon_root_str],
            ambiguous=False,
        )

    module_manager = ModuleManager(env_config["addons_path"])
    duplicate_roots = path_manager.find_duplicate_module_names().get(raw_target, [])
    resolved_module_path = module_manager.find_module_path(raw_target)
    if resolved_module_path is None:
        raise FileNotFoundError(f"Addon target {target!r} was not found.")

    addon_root = _resolve_path(Path(resolved_module_path))
    manifest_path = _manifest_path_for_root(addon_root)
    if manifest_path is None:
        raise FileNotFoundError(
            f"Resolved addon target {target!r} does not contain a manifest."
        )

    candidate_addon_roots = sorted(
        {Path(path).as_posix() for path in duplicate_roots} | {addon_root.as_posix()}
    )
    ambiguous = len(candidate_addon_roots) > 1
    if ambiguous:
        warnings.append(
            "Module-name resolution is ambiguous; use an explicit addon path for "
            "source mutation."
        )
    if policy is not None and not policy.is_allowed(addon_root):
        raise DocumentationTargetNotAllowedError(
            (
                "Technical documentation is not allowed for addon target "
                f"{target!r}; "
                "the resolved addon root is outside "
                "[documentation].allowed_addon_dirs."
            ),
            addon_root=addon_root.as_posix(),
            allowed_dirs=policy.display_allowed_dirs(base_dir=base_dir),
        )

    return AddonDocTarget(
        module=raw_target,
        addon_root=addon_root.as_posix(),
        target_kind="module",
        manifest_path=manifest_path.as_posix(),
        inside_configured_addons_path=_is_under_configured_addons_path(
            addon_root, configured_paths
        ),
        warnings=warnings,
        candidate_addon_roots=candidate_addon_roots,
        ambiguous=ambiguous,
    )


def resolve_technical_doc_output_path(
    target: AddonDocTarget | None,
    *,
    addon_root: str | Path | None = None,
    output: Path | None,
    output_in_addon: bool,
    filename: str = "architecture.md",
) -> Path | None:
    """Resolve the output path for a technical-documentation request."""

    if output is not None:
        return output
    if output_in_addon:
        effective_addon_root = addon_root or (
            target.addon_root if target is not None else None
        )
        if effective_addon_root is None:
            return None
        return Path(effective_addon_root) / "docs" / filename
    return None
