"""Shared manifest resolution helpers for CLI command surfaces."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..manifest import InvalidManifestError, Manifest, ManifestNotFoundError
from ..module_manager import ModuleManager


def resolve_manifest_target(
    env_config: dict[str, Any],
    target: str,
) -> tuple[str, str]:
    """Resolve an addon target to a module path and logical module name."""
    target_path = Path(target).expanduser()
    if target_path.exists():
        module_path = target_path if target_path.is_dir() else target_path.parent
        return str(module_path), module_path.name

    module_manager = ModuleManager(env_config["addons_path"])
    resolved_module_path = module_manager.find_module_path(target)
    if resolved_module_path is None:
        raise FileNotFoundError(target)
    return str(Path(resolved_module_path)), target


def build_manifest_result(
    target: str,
    env_config: dict[str, Any],
) -> tuple[dict[str, Any], Manifest | None]:
    """Build the shared manifest-check payload and resolved manifest."""
    try:
        module_path, module_name = resolve_manifest_target(env_config, target)
    except FileNotFoundError:
        return (
            {
                "success": False,
                "operation": "manifest_check",
                "target": target,
                "error": f"Manifest target {target!r} was not found",
                "error_type": "NotFoundError",
                "read_only": True,
            },
            None,
        )

    try:
        manifest = Manifest(module_path)
    except ManifestNotFoundError as exc:
        return (
            {
                "success": False,
                "operation": "manifest_check",
                "target": target,
                "module": module_name,
                "module_path": module_path,
                "error": str(exc),
                "error_type": "ManifestNotFoundError",
                "read_only": True,
            },
            None,
        )
    except InvalidManifestError as exc:
        return (
            {
                "success": False,
                "operation": "manifest_check",
                "target": target,
                "module": module_name,
                "module_path": module_path,
                "error": str(exc),
                "error_type": "InvalidManifestError",
                "read_only": True,
            },
            None,
        )

    warnings = manifest.validate_structure()
    result = {
        "success": True,
        "operation": "manifest_check",
        "target": target,
        "module": module_name,
        "module_path": module_path,
        "warnings": warnings,
        "warning_count": len(warnings),
        "read_only": True,
    }
    return result, manifest
