"""Operation set parsing, validation, resolution, inspection, and writing."""

from __future__ import annotations

import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal

from .exceptions import ConfigError

OperationSetKind = Literal["install", "update", "test"]

_DEFAULT_SCHEMA_VERSION = 2
_DEFAULT_EMPTY_MAPPING = MappingProxyType({})
_NAME_SEPARATOR_RE = re.compile(r"[\s,]+")
_VALID_KINDS = {"install", "update", "test"}
_VALID_TOP_LEVEL_KEYS = {
    "schema_version",
    "kind",
    "name",
    "description",
    "metadata",
    "source",
    "install",
    "update",
    "test",
}
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


def _empty_mapping() -> Mapping[str, Any]:
    return _DEFAULT_EMPTY_MAPPING


def _load_toml(path: Path) -> dict[str, Any]:
    if path.suffix not in {"", ".toml"}:
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
    data: Mapping[str, Any],
    valid_keys: set[str],
    *,
    section: str,
    reference: str | None = None,
) -> None:
    unknown = sorted(set(data.keys()) - valid_keys)
    if not unknown:
        return
    prefix = "Operation set"
    if reference:
        prefix += f" '{reference}'"
    prefix += f" has unknown key(s) in [{section}]"
    raise ConfigError(
        f"{prefix}: {', '.join(unknown)}. "
        f"Supported keys: {', '.join(sorted(valid_keys))}."
    )


def _split_names(raw_value: str) -> tuple[str, ...]:
    return tuple(item for item in _NAME_SEPARATOR_RE.split(raw_value.strip()) if item)


def _string_list(value: Any, *, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return _split_names(value)
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
    """Normalize test tags while preserving tag punctuation."""
    if value is None:
        return ()
    if isinstance(value, str):
        if "," in value:
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return (value.strip(),) if value.strip() else ()
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


def _mapping_section(value: Any, *, key: str) -> Mapping[str, Any]:
    if value is None:
        return _empty_mapping()
    if not isinstance(value, dict):
        raise ConfigError(f"`{key}` must be a table/object.")
    return MappingProxyType(dict(value))


def _string_or_none(value: Any, *, key: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise ConfigError(f"`{key}` must be a string.")


def _normalize_schema_version(value: Any, *, reference: str) -> int:
    if value is None:
        return _DEFAULT_SCHEMA_VERSION
    if isinstance(value, int) and not isinstance(value, bool) and value == 2:
        return value
    raise ConfigError(
        f"Operation set '{reference}' is invalid: schema_version must be 2."
    )


def _normalize_kind(value: Any, *, reference: str) -> OperationSetKind:
    if value is None:
        raise ConfigError(
            f"Operation set '{reference}' is invalid: "
            "missing required top-level key 'kind'."
        )
    if not isinstance(value, str) or value not in _VALID_KINDS:
        raise ConfigError(
            f"Operation set '{reference}' is invalid: "
            "kind must be one of install, update, test."
        )
    return value


def _validate_kind_sections(
    kind: OperationSetKind,
    *,
    reference: str,
    install_section: InstallSetSection | None,
    update_section: UpdateSetSection | None,
    test_section: TestSetSection | None,
) -> None:
    required_map = {
        "install": install_section is not None,
        "update": update_section is not None,
        "test": test_section is not None,
    }
    if not required_map[kind] or any(
        present
        for section, present in required_map.items()
        if section != kind and present
    ):
        forbidden = ", ".join(
            f"[{section}]"
            for section, present in required_map.items()
            if section != kind and present
        )
        suffix = f" and forbids {forbidden}" if forbidden else ""
        raise ConfigError(
            f"Operation set '{reference}' is invalid: "
            f"kind '{kind}' requires [{kind}]{suffix}."
        )


def _is_explicit_read_reference(value: str) -> bool:
    reference_path = Path(value)
    return reference_path.is_absolute() or "/" in value or "\\" in value


def _is_explicit_write_reference(value: str) -> bool:
    reference_path = Path(value)
    return (
        reference_path.is_absolute()
        or "/" in value
        or "\\" in value
        or reference_path.suffix != ""
    )


def _directory_reference_names(value: str) -> tuple[str, ...]:
    reference_name = Path(value).name
    if reference_name.endswith(".toml"):
        return (reference_name,)
    return (f"{reference_name}.toml", reference_name)


def _unique_paths(paths: Sequence[tuple[Path, str]]) -> list[tuple[Path, str]]:
    seen: set[Path] = set()
    unique: list[tuple[Path, str]] = []
    for path, source in paths:
        normalized = path.resolve(strict=False)
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append((normalized, source))
    return unique


def _active_config_sets_dir(context: OperationSetLocationContext) -> Path | None:
    if (
        context.active_config_source == "local"
        and context.active_config_path is not None
    ):
        return context.active_config_path.parent / ".oduit" / "sets"
    if (
        context.active_config_source in {"env", "demo"}
        and context.global_config_dir is not None
    ):
        return context.global_config_dir / "sets"
    return None


def _serialize_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _serialize_value(item) for key, item in value.items()}


def _serialize_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _serialize_mapping(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, tuple):
        return [_serialize_value(item) for item in value]
    if isinstance(value, list):
        return [_serialize_value(item) for item in value]
    return value


def _dump_toml(document: Mapping[str, Any]) -> str:
    try:
        import tomli_w
    except ModuleNotFoundError as exc:
        raise ConfigError("Operation set writing requires tomli_w.") from exc
    return tomli_w.dumps(_serialize_mapping(document))


def _operation_set_section_addons(
    operation_set: OperationSet,
) -> list[tuple[str, tuple[str, ...]]]:
    addon_lists: list[tuple[str, tuple[str, ...]]] = []
    if operation_set.install is not None:
        addon_lists.append(("install.addons", operation_set.install.addons))
    if operation_set.update is not None:
        addon_lists.append(("update.addons", operation_set.update.addons))
    if operation_set.test is not None:
        addon_lists.append(("test.install", operation_set.test.install))
        addon_lists.append(("test.update", operation_set.test.update))
        if operation_set.test.coverage:
            addon_lists.append(("test.coverage", (operation_set.test.coverage,)))
    return addon_lists


def _addon_roles(operation_set: OperationSet) -> dict[str, list[str]]:
    roles: dict[str, list[str]] = {}
    for label, addons in _operation_set_section_addons(operation_set):
        if addons:
            roles[label] = list(addons)
    return roles


def _operation_set_addon_count(operation_set: OperationSet) -> int:
    unique_addons: list[str] = []
    for _label, addons in _operation_set_section_addons(operation_set):
        for addon in addons:
            if addon not in unique_addons:
                unique_addons.append(addon)
    return len(unique_addons)


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
class OperationSetLocationContext:
    cwd: Path
    active_config_path: Path | None = None
    active_config_source: str | None = None
    global_config_dir: Path | None = None


@dataclass(frozen=True)
class OperationSetResolution:
    reference: str
    path: Path
    source: str
    attempted: tuple[Path, ...]


@dataclass(frozen=True)
class OperationSetWriteResult:
    path: Path
    reference: str
    kind: OperationSetKind
    addon_count: int
    overwritten: bool


@dataclass(frozen=True)
class OperationSet:
    path: Path
    requested_value: str
    kind: OperationSetKind
    schema_version: int = _DEFAULT_SCHEMA_VERSION
    name: str | None = None
    description: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=_empty_mapping)
    source: Mapping[str, Any] = field(default_factory=_empty_mapping)
    install: InstallSetSection | None = None
    update: UpdateSetSection | None = None
    test: TestSetSection | None = None
    resolution_source: str | None = None


def build_operation_set_location_context(
    *,
    cwd: Path,
    config_path: str | None,
    config_source: str | None,
    config_dir: str | None,
) -> OperationSetLocationContext:
    return OperationSetLocationContext(
        cwd=cwd.resolve(strict=False),
        active_config_path=(
            Path(config_path).expanduser().resolve(strict=False)
            if config_path
            else None
        ),
        active_config_source=config_source,
        global_config_dir=(
            Path(config_dir).expanduser().resolve(strict=False) if config_dir else None
        ),
    )


def resolve_operation_set_path(
    value: str,
    *,
    context: OperationSetLocationContext | None = None,
    base_dir: Path | None = None,
) -> OperationSetResolution:
    """Resolve a user-provided set reference to an absolute path."""
    if context is None:
        context = OperationSetLocationContext(cwd=(base_dir or Path.cwd()).resolve())

    cwd = context.cwd
    direct_candidate = Path(value)
    if not direct_candidate.is_absolute():
        direct_candidate = (cwd / direct_candidate).resolve(strict=False)
    attempted: list[Path] = [direct_candidate]
    if direct_candidate.is_file():
        return OperationSetResolution(
            reference=value,
            path=direct_candidate.resolve(),
            source="direct",
            attempted=tuple(attempted),
        )

    if _is_explicit_read_reference(value):
        raise ConfigError(
            f"Cannot resolve operation set '{value}'. Tried:\n  "
            + "\n  ".join(str(path) for path in attempted)
        )

    candidate_dirs: list[tuple[Path, str]] = []
    active_dir = _active_config_sets_dir(context)
    if active_dir is not None:
        candidate_dirs.append((active_dir, "active_config"))
    candidate_dirs.append((cwd / ".oduit" / "sets", "local_project"))
    if context.global_config_dir is not None:
        candidate_dirs.append((context.global_config_dir / "sets", "global_config"))

    for directory, source in _unique_paths(candidate_dirs):
        for filename in _directory_reference_names(value):
            candidate = (directory / filename).resolve(strict=False)
            attempted.append(candidate)
            if candidate.is_file():
                return OperationSetResolution(
                    reference=value,
                    path=candidate.resolve(),
                    source=source,
                    attempted=tuple(attempted),
                )

    raise ConfigError(
        f"Cannot resolve operation set '{value}'. Tried:\n  "
        + "\n  ".join(str(path) for path in attempted)
    )


def resolve_operation_set_write_path(
    value: str,
    *,
    context: OperationSetLocationContext | None = None,
    base_dir: Path | None = None,
    overwrite: bool = False,
) -> OperationSetResolution:
    """Resolve the target path for writing an operation set."""
    if context is None:
        context = OperationSetLocationContext(cwd=(base_dir or Path.cwd()).resolve())

    cwd = context.cwd
    attempted: list[Path] = []

    if _is_explicit_write_reference(value):
        path = Path(value)
        if not path.is_absolute():
            path = (cwd / path).resolve(strict=False)
        attempted.append(path)
        if path.suffix not in {"", ".toml"}:
            raise ConfigError("Operation sets currently support TOML files only.")
        if path.exists() and not overwrite:
            raise ConfigError(
                f"Refusing to overwrite existing operation set: "
                f"{path}. Use --overwrite."
            )
        return OperationSetResolution(
            reference=value,
            path=path,
            source="explicit",
            attempted=tuple(attempted),
        )

    active_dir = _active_config_sets_dir(context)
    if active_dir is not None:
        target_dir = active_dir
        source = "active_config"
    elif context.global_config_dir is not None:
        target_dir = context.global_config_dir / "sets"
        source = "global_config"
    else:
        target_dir = cwd / ".oduit" / "sets"
        source = "local_project"

    path = (target_dir / f"{value}.toml").resolve(strict=False)
    attempted.append(path)
    if path.exists() and not overwrite:
        raise ConfigError(
            f"Refusing to overwrite existing operation set: {path}. Use --overwrite."
        )
    return OperationSetResolution(
        reference=value,
        path=path,
        source=source,
        attempted=tuple(attempted),
    )


def _parse_install_section(
    data: dict[str, Any], *, reference: str
) -> InstallSetSection:
    _check_unknown_keys(
        data, _VALID_INSTALL_KEYS, section="install", reference=reference
    )
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


def _parse_update_section(data: dict[str, Any], *, reference: str) -> UpdateSetSection:
    _check_unknown_keys(data, _VALID_UPDATE_KEYS, section="update", reference=reference)
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
    reference: str,
    set_file_dir: Path,
    allow_missing_test_files: bool = False,
) -> TestSetSection:
    _check_unknown_keys(data, _VALID_TEST_KEYS, section="test", reference=reference)
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
    context: OperationSetLocationContext | None = None,
    base_dir: Path | None = None,
    allow_missing_test_files: bool = False,
) -> OperationSet:
    """Load and validate an operation set from a user-provided reference."""
    resolution = resolve_operation_set_path(value, context=context, base_dir=base_dir)
    data = _load_toml(resolution.path)
    _check_unknown_keys(
        data, _VALID_TOP_LEVEL_KEYS, section="top level", reference=value
    )

    schema_version = _normalize_schema_version(
        data.get("schema_version"), reference=value
    )
    kind = _normalize_kind(data.get("kind"), reference=value)
    install_section = (
        _parse_install_section(data["install"], reference=value)
        if "install" in data
        else None
    )
    update_section = (
        _parse_update_section(data["update"], reference=value)
        if "update" in data
        else None
    )
    test_section = (
        _parse_test_section(
            data["test"],
            reference=value,
            set_file_dir=resolution.path.parent,
            allow_missing_test_files=allow_missing_test_files,
        )
        if "test" in data
        else None
    )
    _validate_kind_sections(
        kind,
        reference=value,
        install_section=install_section,
        update_section=update_section,
        test_section=test_section,
    )

    return OperationSet(
        path=resolution.path,
        requested_value=value,
        kind=kind,
        schema_version=schema_version,
        name=_string_or_none(data.get("name"), key="name"),
        description=_string_or_none(data.get("description"), key="description"),
        metadata=_mapping_section(data.get("metadata"), key="metadata"),
        source=_mapping_section(data.get("source"), key="source"),
        install=install_section,
        update=update_section,
        test=test_section,
        resolution_source=resolution.source,
    )


def find_missing_operation_set_addons(
    operation_set: OperationSet,
    *,
    addons_path: str,
    module_manager_cls: type | None = None,
) -> list[str]:
    if module_manager_cls is None:
        from .module_manager import ModuleManager

        module_manager_cls = ModuleManager

    manager = module_manager_cls(addons_path)
    missing: list[str] = []
    for _label, addons in _operation_set_section_addons(operation_set):
        for addon in addons:
            if not manager.find_module_path(addon) and addon not in missing:
                missing.append(addon)
    return missing


def validate_operation_set_addons(
    operation_set: OperationSet,
    *,
    addons_path: str,
    module_manager_cls: type | None = None,
) -> None:
    """Validate that all addon names in the set exist in the addons path."""
    missing = find_missing_operation_set_addons(
        operation_set,
        addons_path=addons_path,
        module_manager_cls=module_manager_cls,
    )
    if missing:
        raise ConfigError(
            "Operation set contains unknown addon(s): "
            f"{', '.join(missing)}. Check addons_path or the set file."
        )


def inspect_operation_set(
    operation_set: OperationSet,
    *,
    addons_path: str | None = None,
    module_manager_cls: type | None = None,
) -> dict[str, Any]:
    missing_addons: list[str] = []
    validation_status = "not_checked"
    if addons_path:
        missing_addons = find_missing_operation_set_addons(
            operation_set,
            addons_path=addons_path,
            module_manager_cls=module_manager_cls,
        )
        validation_status = "ok" if not missing_addons else "missing_addons"

    test_files = []
    if operation_set.test is not None:
        for index, resolved_path in enumerate(operation_set.test.test_files):
            input_value = (
                operation_set.test.test_file_inputs[index]
                if index < len(operation_set.test.test_file_inputs)
                else str(resolved_path)
            )
            test_files.append(
                {
                    "input": input_value,
                    "path": str(resolved_path),
                    "exists": resolved_path.exists(),
                }
            )

    return {
        "reference": operation_set.requested_value,
        "path": str(operation_set.path),
        "resolution_source": operation_set.resolution_source,
        "schema_version": operation_set.schema_version,
        "kind": operation_set.kind,
        "name": operation_set.name,
        "description": operation_set.description,
        "addon_count": _operation_set_addon_count(operation_set),
        "addons_by_role": _addon_roles(operation_set),
        "missing_addons": missing_addons,
        "addons_path_status": validation_status,
        "test_files": test_files,
        "metadata": _serialize_mapping(operation_set.metadata),
        "source": _serialize_mapping(operation_set.source),
    }


def build_operation_set_document(
    *,
    kind: OperationSetKind,
    addons: Sequence[str],
    name: str | None = None,
    description: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    source: Mapping[str, Any] | None = None,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": _DEFAULT_SCHEMA_VERSION,
        "kind": kind,
    }
    if name:
        document["name"] = name
    if description:
        document["description"] = description
    if metadata:
        document["metadata"] = _serialize_mapping(metadata)
    if source:
        document["source"] = _serialize_mapping(source)

    addon_list = [addon for addon in addons if addon]
    section: dict[str, Any] = {}
    if kind == "install":
        section["addons"] = addon_list
    elif kind == "update":
        section["addons"] = addon_list
    else:
        section["install"] = addon_list
        section["test_tags"] = [f"/{addon}" for addon in addon_list]

    if options:
        section.update(_serialize_mapping(options))
    document[kind] = section
    return document


def write_operation_set(
    reference: str,
    *,
    kind: OperationSetKind,
    addons: Sequence[str],
    context: OperationSetLocationContext | None = None,
    base_dir: Path | None = None,
    overwrite: bool = False,
    name: str | None = None,
    description: str | None = None,
    metadata: Mapping[str, Any] | None = None,
    source: Mapping[str, Any] | None = None,
    options: Mapping[str, Any] | None = None,
) -> OperationSetWriteResult:
    resolution = resolve_operation_set_write_path(
        reference,
        context=context,
        base_dir=base_dir,
        overwrite=overwrite,
    )
    document = build_operation_set_document(
        kind=kind,
        addons=addons,
        name=name,
        description=description,
        metadata=metadata,
        source=source,
        options=options,
    )
    resolution.path.parent.mkdir(parents=True, exist_ok=True)
    overwritten = resolution.path.exists()
    resolution.path.write_text(_dump_toml(document), encoding="utf-8")
    return OperationSetWriteResult(
        path=resolution.path,
        reference=reference,
        kind=kind,
        addon_count=len([addon for addon in addons if addon]),
        overwritten=overwritten,
    )


def list_operation_sets(
    *,
    context: OperationSetLocationContext,
) -> list[OperationSetResolution]:
    candidate_dirs: list[tuple[Path, str]] = []
    active_dir = _active_config_sets_dir(context)
    if active_dir is not None:
        candidate_dirs.append((active_dir, "active_config"))
    candidate_dirs.append((context.cwd / ".oduit" / "sets", "local_project"))
    if context.global_config_dir is not None:
        candidate_dirs.append((context.global_config_dir / "sets", "global_config"))

    results: list[OperationSetResolution] = []
    seen_paths: set[Path] = set()
    for directory, source in _unique_paths(candidate_dirs):
        if not directory.is_dir():
            continue
        for candidate in sorted(directory.iterdir()):
            if not candidate.is_file() or candidate.suffix not in {"", ".toml"}:
                continue
            resolved = candidate.resolve()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            results.append(
                OperationSetResolution(
                    reference=candidate.stem
                    if candidate.suffix == ".toml"
                    else candidate.name,
                    path=resolved,
                    source=source,
                    attempted=(resolved,),
                )
            )
    return results


def build_operation_set_result(
    operation_set: OperationSet,
    *,
    results: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    started_at: float,
) -> dict[str, Any]:
    """Build the aggregate result for an operation set execution."""
    any_failure = len(failures) > 0 or any(
        not result.get("success", False) for result in results
    )
    duration = time.time() - started_at
    kind = operation_set.kind
    return {
        "success": not any_failure,
        "operation": f"operation_set_{kind}",
        "set_name": operation_set.name,
        "set_description": operation_set.description,
        "set_path": str(operation_set.path),
        "set_reference": operation_set.requested_value,
        "kind": kind,
        "executed_operations": results,
        "failures": failures,
        "summary": {
            "kind": kind,
            "addon_count": _operation_set_addon_count(operation_set),
            "executed": len(results),
            "failed": len(failures),
            "skipped": 0,
        },
        "duration": round(duration, 2),
    }


def sanitize_operation_result(
    result: dict[str, Any],
    *,
    include_command: bool,
    include_stdout: bool,
) -> dict[str, Any]:
    """Remove sensitive or verbose fields from a per-operation result."""
    blocked: set[str] = {"stderr"}
    if not include_command:
        blocked.add("command")
    if not include_stdout:
        blocked.add("stdout")
    return {key: value for key, value in result.items() if key not in blocked}
