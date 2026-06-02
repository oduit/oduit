"""Operation set parsing, validation, resolution, and result aggregation."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .cli.commands.module_input import parse_module_names
from .exceptions import ConfigError

OperationSetMode = Literal["install", "update", "test", "apply"]

_VALID_TOP_LEVEL_KEYS = {"name", "description", "install", "update", "test"}

_VALID_INSTALL_KEYS = {
    "addons",
    "with_demo",
    "without_demo",
    "language",
    "max_cron_threads",
    "compact",
    "log_level",
}

_VALID_UPDATE_KEYS = {
    "addons",
    "without_demo",
    "language",
    "i18n_overwrite",
    "max_cron_threads",
    "compact",
    "log_level",
}

_VALID_TEST_KEYS = {
    "install",
    "update",
    "test_tags",
    "test_files",
    "coverage",
    "compact",
    "stop_on_error",
    "log_level",
}


def _load_toml(path: Path) -> dict[str, Any]:
    if path.suffix != ".toml":
        raise ConfigError("Operation sets currently support TOML files only.")
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        import tomli as tomllib
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    if not isinstance(data, dict):
        raise ConfigError(f"Invalid operation set format: {path}")
    return data


def _check_unknown_keys(
    data: dict[str, Any],
    valid_keys: set[str],
    *,
    section: str,
) -> None:
    unknown = set(data.keys()) - valid_keys
    if unknown:
        sorted_unknown = sorted(unknown)
        sorted_valid = sorted(valid_keys)
        raise ConfigError(
            f"Unknown key in operation set [{section}]: "
            f"{', '.join(sorted_unknown)}. "
            f"Supported keys: {', '.join(sorted_valid)}."
        )


def _string_list(value: Any, *, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(item for item in parse_module_names(value) if item)
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ConfigError(f"`{key}` must be a string or list of strings.")
            if item.strip():
                result.append(item.strip())
        return tuple(result)
    raise ConfigError(f"`{key}` must be a string or list of strings.")


def _test_tags_list(value: Any, *, key: str) -> tuple[str, ...]:
    """Normalize test_tags. Unlike addons, tags may contain slashes, colons, etc."""
    if value is None:
        return ()
    if isinstance(value, str):
        if "," in value:
            return tuple(t.strip() for t in value.split(",") if t.strip())
        return (value,) if value.strip() else ()
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ConfigError(f"`{key}` must be a string or list of strings.")
            if item.strip():
                result.append(item.strip())
        return tuple(result)
    raise ConfigError(f"`{key}` must be a string or list of strings.")


def _test_files_list(
    value: Any,
    *,
    key: str,
    set_file_dir: Path,
    allow_missing: bool = False,
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Normalize test_files. Returns (resolved_paths, original_inputs)."""
    raw = _string_list(value, key=key)
    if not raw:
        return (), ()

    resolved_paths: list[Path] = []
    original_inputs: list[str] = []

    for raw_path in raw:
        resolved = (set_file_dir / raw_path).resolve(strict=False)
        if not resolved.exists() and not allow_missing:
            raise ConfigError(
                f"Test file not found: {raw_path} (resolved to {resolved})"
            )
        resolved_paths.append(resolved)
        original_inputs.append(raw_path)

    return tuple(resolved_paths), tuple(original_inputs)


def _without_demo_value(value: Any) -> bool | str:
    if value in (None, False):
        return False
    if value is True:
        return True
    if isinstance(value, str):
        return value
    raise ConfigError("without_demo must be a boolean or string.")


def _optional_bool(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    raise ConfigError("Expected a boolean value.")


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise ConfigError("Expected a string value.")


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise ConfigError("Expected an integer value.")


# --- Dataclasses ---


@dataclass(frozen=True)
class InstallSetSection:
    addons: tuple[str, ...] = ()
    with_demo: bool = False
    without_demo: bool | str = False
    language: str | None = None
    max_cron_threads: int | None = None
    compact: bool = False
    log_level: str | None = None


@dataclass(frozen=True)
class UpdateSetSection:
    addons: tuple[str, ...] = ()
    without_demo: bool | str = False
    language: str | None = None
    i18n_overwrite: bool = False
    max_cron_threads: int | None = None
    compact: bool = False
    log_level: str | None = None


@dataclass(frozen=True)
class TestSetSection:
    install: tuple[str, ...] = ()
    update: tuple[str, ...] = ()
    test_tags: tuple[str, ...] = ()
    test_files: tuple[Path, ...] = ()
    test_file_inputs: tuple[str, ...] = ()
    coverage: str | None = None
    compact: bool = False
    stop_on_error: bool = False
    log_level: str | None = None


@dataclass(frozen=True)
class OperationSet:
    path: Path
    requested_value: str
    name: str | None = None
    description: str | None = None
    install: InstallSetSection | None = None
    update: UpdateSetSection | None = None
    test: TestSetSection | None = None


# --- Path resolution ---


def resolve_operation_set_path(value: str, *, base_dir: Path | None = None) -> Path:
    """Resolve a user-provided set reference to an absolute path.

    Resolution order:
    1. Exact file path
    2. .oduit/sets/<name>.toml
    3. .oduit/sets/<name>
    """
    cwd = base_dir or Path.cwd()
    direct = Path(value)
    if direct.is_file():
        return direct.resolve()

    candidates = [
        cwd / ".oduit" / "sets" / f"{value}.toml",
        cwd / ".oduit" / "sets" / value,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    attempted = [str(direct)] + [str(c) for c in candidates]
    raise ConfigError(
        f"Cannot resolve operation set '{value}'. " f"Tried: {', '.join(attempted)}"
    )


# --- Loading ---


def _parse_install_section(data: dict[str, Any]) -> InstallSetSection:
    _check_unknown_keys(data, _VALID_INSTALL_KEYS, section="install")

    with_demo = _optional_bool(data.get("with_demo"))
    without_demo = _without_demo_value(data.get("without_demo"))

    if with_demo and without_demo:
        raise ConfigError(
            "with_demo and without_demo must not both be active "
            "in the same install section."
        )

    return InstallSetSection(
        addons=_string_list(data.get("addons"), key="addons"),
        with_demo=with_demo,
        without_demo=without_demo,
        language=_optional_str(data.get("language")),
        max_cron_threads=_optional_int(data.get("max_cron_threads")),
        compact=_optional_bool(data.get("compact")),
        log_level=_optional_str(data.get("log_level")),
    )


def _parse_update_section(data: dict[str, Any]) -> UpdateSetSection:
    _check_unknown_keys(data, _VALID_UPDATE_KEYS, section="update")

    return UpdateSetSection(
        addons=_string_list(data.get("addons"), key="addons"),
        without_demo=_without_demo_value(data.get("without_demo")),
        language=_optional_str(data.get("language")),
        i18n_overwrite=_optional_bool(data.get("i18n_overwrite")),
        max_cron_threads=_optional_int(data.get("max_cron_threads")),
        compact=_optional_bool(data.get("compact")),
        log_level=_optional_str(data.get("log_level")),
    )


def _parse_test_section(
    data: dict[str, Any],
    *,
    set_file_dir: Path,
    allow_missing_test_files: bool = False,
) -> TestSetSection:
    _check_unknown_keys(data, _VALID_TEST_KEYS, section="test")

    test_files, test_file_inputs = _test_files_list(
        data.get("test_files"),
        key="test_files",
        set_file_dir=set_file_dir,
        allow_missing=allow_missing_test_files,
    )

    return TestSetSection(
        install=_string_list(data.get("install"), key="install"),
        update=_string_list(data.get("update"), key="update"),
        test_tags=_test_tags_list(data.get("test_tags"), key="test_tags"),
        test_files=test_files,
        test_file_inputs=test_file_inputs,
        coverage=_optional_str(data.get("coverage")),
        compact=_optional_bool(data.get("compact")),
        stop_on_error=_optional_bool(data.get("stop_on_error")),
        log_level=_optional_str(data.get("log_level")),
    )


def load_operation_set(
    value: str,
    *,
    base_dir: Path | None = None,
    allow_missing_test_files: bool = False,
) -> OperationSet:
    """Load and validate an operation set from a user-provided reference."""
    path = resolve_operation_set_path(value, base_dir=base_dir)
    data = _load_toml(path)

    _check_unknown_keys(data, _VALID_TOP_LEVEL_KEYS, section="top level")

    install_section = None
    update_section = None
    test_section = None

    if "install" in data:
        install_section = _parse_install_section(data["install"])
    if "update" in data:
        update_section = _parse_update_section(data["update"])
    if "test" in data:
        test_section = _parse_test_section(
            data["test"],
            set_file_dir=path.parent,
            allow_missing_test_files=allow_missing_test_files,
        )

    return OperationSet(
        path=path,
        requested_value=value,
        name=data.get("name"),
        description=data.get("description"),
        install=install_section,
        update=update_section,
        test=test_section,
    )


# --- Addon validation ---


def validate_operation_set_addons(
    operation_set: OperationSet,
    *,
    addons_path: str,
    module_manager_cls: type | None = None,
) -> None:
    """Validate that all addon names in the set exist in the addons path."""
    if module_manager_cls is None:
        from .module_manager import ModuleManager

        module_manager_cls = ModuleManager

    manager = module_manager_cls(addons_path)
    all_addon_lists: list[tuple[str, tuple[str, ...]]] = []

    if operation_set.install:
        all_addon_lists.append(("install.addons", operation_set.install.addons))
    if operation_set.update:
        all_addon_lists.append(("update.addons", operation_set.update.addons))
    if operation_set.test:
        all_addon_lists.append(("test.install", operation_set.test.install))
        all_addon_lists.append(("test.update", operation_set.test.update))
        if operation_set.test.coverage:
            all_addon_lists.append(("test.coverage", (operation_set.test.coverage,)))

    missing: list[str] = []
    for _label, addons in all_addon_lists:
        for addon in addons:
            if not manager.find_module_path(addon):
                if addon not in missing:
                    missing.append(addon)

    if missing:
        raise ConfigError(
            f"Operation set contains unknown addon(s): "
            f"{', '.join(missing)}. Check addons_path or the set file."
        )


# --- Result aggregation ---


def build_operation_set_result(
    operation_set: OperationSet,
    *,
    mode: OperationSetMode,
    results: list[dict[str, Any]],
    skipped_operations: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    started_at: float,
) -> dict[str, Any]:
    """Build the aggregate result for an operation set execution."""
    any_failure = len(failures) > 0 or any(not r.get("success", False) for r in results)
    duration = time.time() - started_at

    return {
        "success": not any_failure,
        "operation": f"operation_set_{mode}",
        "set_name": operation_set.name,
        "set_description": operation_set.description,
        "set_path": str(operation_set.path),
        "set_reference": operation_set.requested_value,
        "mode": mode,
        "executed_operations": results,
        "skipped_operations": skipped_operations,
        "failures": failures,
        "summary": {
            "executed": len(results),
            "skipped": len(skipped_operations),
            "failed": len(failures),
        },
        "duration": round(duration, 2),
    }


def sanitize_operation_result(
    result: dict[str, Any],
    *,
    include_command: bool,
    include_stdout: bool,
) -> dict[str, Any]:
    """Remove sensitive/verbose fields from a per-operation result."""
    blocked: set[str] = set()
    if not include_command:
        blocked.add("command")
    if not include_stdout:
        blocked.add("stdout")
    blocked.add("stderr")
    return {k: v for k, v in result.items() if k not in blocked}


def require_section(
    operation_set: OperationSet,
    mode: OperationSetMode,
) -> None:
    """Fail if the required section is absent for the given mode."""
    if mode == "install" and operation_set.install is None:
        raise ConfigError(
            f"Operation set '{operation_set.requested_value}' "
            f"has no [install] section."
        )
    if mode == "update" and operation_set.update is None:
        raise ConfigError(
            f"Operation set '{operation_set.requested_value}' "
            f"has no [update] section."
        )
    if mode == "test" and operation_set.test is None:
        raise ConfigError(
            f"Operation set '{operation_set.requested_value}' "
            f"has no [test] section."
        )
