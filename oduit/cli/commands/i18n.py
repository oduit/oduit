"""Classic CLI commands for version-aware Odoo translation workflows."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, NoReturn

import typer

from ...builders import (
    ConfigProvider,
    I18nExportCommandBuilder,
    I18nImportCommandBuilder,
    I18nLoadLanguageCommandBuilder,
    odoo_series_major,
)
from ...cli_types import LogLevel, OutputFormat
from ...exceptions import ConfigError
from ...module_manager import ModuleManager
from ...utils import output_result_to_json


def _split_csv_values(values: list[str] | tuple[str, ...] | None) -> list[str]:
    result: list[str] = []
    for raw_value in values or []:
        for item in str(raw_value).split(","):
            cleaned = item.strip()
            if cleaned:
                result.append(cleaned)
    return result


def _fail_i18n_command(
    *,
    global_config: Any,
    operation: str,
    message: str,
    print_command_error_result_fn: Any,
    error_type: str = "CommandError",
    remediation: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> NoReturn:
    print_command_error_result_fn(
        global_config,
        operation,
        message,
        error_type=error_type,
        remediation=remediation,
        details=details,
    )
    raise typer.Exit(1) from None


def _require_source_mutation(
    *,
    global_config: Any,
    allow_mutation: bool,
    operation: str,
    action: str,
    confirmation_required_error_fn: Any,
) -> None:
    if allow_mutation:
        return
    confirmation_required_error_fn(
        global_config,
        operation,
        f"{action} writes translation files; pass --allow-mutation.",
        [
            "Retry with `--allow-mutation` after reviewing the planned output path.",
        ],
    )


def _resolve_i18n_series(
    *,
    global_config: Any,
    env_config: dict[str, Any],
    module_manager_cls: type[ModuleManager],
    build_odoo_operations_fn: Any,
    allow_version_probe: bool = True,
) -> Any:
    for candidate in (global_config.odoo_series, env_config.get("odoo_series")):
        if odoo_series_major(candidate) is not None:
            return candidate

    addons_path = env_config.get("addons_path")
    if isinstance(addons_path, str) and addons_path.strip():
        detected = module_manager_cls(addons_path).detect_odoo_series()
        if odoo_series_major(detected) is not None:
            return detected

    if allow_version_probe:
        ops = build_odoo_operations_fn(global_config)
        version_result = ops.get_odoo_version(suppress_output=True)
        version = (
            version_result.get("version") if version_result.get("success") else None
        )
        if odoo_series_major(version) is not None:
            return version

    raise ConfigError(
        "Unable to determine the Odoo series for the i18n command. "
        "Pass --odoo-series 18.0 or --odoo-series 19.0."
    )


def _normalize_series_label(value: Any) -> str | None:
    major = odoo_series_major(value)
    if major is None:
        return None
    return f"{major}.0"


def _strip_nested_result_fields(
    value: Any,
    *,
    include_command: bool,
    include_stdout: bool,
) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, nested_value in value.items():
            if key == "command" and not include_command:
                continue
            if key == "stdout" and not include_stdout:
                continue
            result[key] = _strip_nested_result_fields(
                nested_value,
                include_command=include_command,
                include_stdout=include_stdout,
            )
        return result
    if isinstance(value, list):
        return [
            _strip_nested_result_fields(
                item,
                include_command=include_command,
                include_stdout=include_stdout,
            )
            for item in value
        ]
    return value


def _emit_json_result(
    *,
    global_config: Any,
    result: dict[str, Any],
    result_type: str,
    include_command: bool,
    include_stdout: bool,
    additional_fields: dict[str, Any] | None = None,
) -> None:
    if global_config.format != OutputFormat.JSON:
        return

    payload = output_result_to_json(
        _strip_nested_result_fields(
            result,
            include_command=include_command,
            include_stdout=include_stdout,
        ),
        additional_fields=additional_fields,
        exclude_fields=[],
        result_type=result_type,
    )
    print(json.dumps(payload))


def _validate_export_request(
    *,
    env_config: dict[str, Any],
    modules: list[str],
    languages: list[str],
    output: str | None,
    resolved_series: Any,
    log_level: LogLevel | None,
) -> I18nExportCommandBuilder:
    builder = I18nExportCommandBuilder(
        ConfigProvider(env_config),
        modules=modules,
        languages=languages or None,
        output=output,
        odoo_series=resolved_series,
    )
    if log_level:
        builder.log_level(log_level.value)
    return builder


def _validate_import_request(
    *,
    env_config: dict[str, Any],
    files: list[str],
    language: str,
    overwrite: bool,
    resolved_series: Any,
    log_level: LogLevel | None,
) -> None:
    series_major = odoo_series_major(resolved_series)
    assert series_major is not None
    if series_major >= 19:
        builder = I18nImportCommandBuilder(
            ConfigProvider(env_config),
            files=files,
            language=language,
            overwrite=overwrite,
            odoo_series=resolved_series,
        )
        if log_level:
            builder.log_level(log_level.value)
        return

    for filename in files:
        builder = I18nImportCommandBuilder(
            ConfigProvider(env_config),
            files=[filename],
            language=language,
            overwrite=overwrite,
            odoo_series=resolved_series,
        )
        if log_level:
            builder.log_level(log_level.value)


def _validate_load_request(
    *,
    env_config: dict[str, Any],
    languages: list[str],
    resolved_series: Any,
    log_level: LogLevel | None,
) -> None:
    builder = I18nLoadLanguageCommandBuilder(
        ConfigProvider(env_config),
        languages=languages,
        odoo_series=resolved_series,
    )
    if log_level:
        builder.log_level(log_level.value)


def _compat_export_output_path(module_path: str, language: str) -> Path:
    i18n_dir = Path(module_path) / "i18n"
    language_slug = language.split("_")[0] if "_" in language else language
    return i18n_dir / f"{language_slug}.po"


def i18n_export_command(
    ctx: typer.Context,
    *,
    modules: list[str],
    languages: list[str] | None,
    output: str | None,
    allow_mutation: bool,
    include_command: bool,
    include_stdout: bool,
    log_level: LogLevel | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    module_manager_cls: type[ModuleManager],
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Export translations through the version-aware i18n service."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    normalized_modules = _split_csv_values(modules)
    normalized_languages = _split_csv_values(languages)

    operation = "i18n_export"
    try:
        resolved_series = _resolve_i18n_series(
            global_config=global_config,
            env_config=env_config,
            module_manager_cls=module_manager_cls,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )
        builder = _validate_export_request(
            env_config=env_config,
            modules=normalized_modules,
            languages=normalized_languages,
            output=output,
            resolved_series=resolved_series,
            log_level=log_level,
        )
    except ConfigError as exc:
        _fail_i18n_command(
            global_config=global_config,
            operation=operation,
            message=str(exc),
            print_command_error_result_fn=print_command_error_result_fn,
            error_type="ConfigError",
        )

    series_major = odoo_series_major(resolved_series)
    assert series_major is not None
    writes_source_files = output != "-" and (output is not None or series_major >= 19)
    if writes_source_files:
        _require_source_mutation(
            global_config=global_config,
            allow_mutation=allow_mutation,
            operation=operation,
            action="Translation export",
            confirmation_required_error_fn=confirmation_required_error_fn,
        )

    if output and output != "-":
        Path(output).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)

    ops = build_odoo_operations_fn(global_config)
    result = ops.export_translations(
        modules=normalized_modules,
        languages=normalized_languages or None,
        output=output,
        odoo_series=resolved_series,
        log_level=log_level.value if log_level else None,
        suppress_output=global_config.format == OutputFormat.JSON,
    )
    _emit_json_result(
        global_config=global_config,
        result=result,
        result_type="i18n_export",
        include_command=include_command,
        include_stdout=include_stdout,
        additional_fields={
            "modules": normalized_modules,
            "languages": normalized_languages or ["pot"],
            "output": output,
            "odoo_series": _normalize_series_label(resolved_series),
            "strategy": builder.strategy,
        },
    )
    if not result.get("success", False):
        raise typer.Exit(1)


def i18n_import_command(
    ctx: typer.Context,
    *,
    files: list[str],
    language: str,
    overwrite: bool,
    allow_mutation: bool,
    include_command: bool,
    include_stdout: bool,
    log_level: LogLevel | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    module_manager_cls: type[ModuleManager],
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Import translations through the version-aware i18n service."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    normalized_files = [str(Path(filename)) for filename in files]
    operation = "i18n_import"
    try:
        resolved_series = _resolve_i18n_series(
            global_config=global_config,
            env_config=env_config,
            module_manager_cls=module_manager_cls,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )
        _validate_import_request(
            env_config=env_config,
            files=normalized_files,
            language=language,
            overwrite=overwrite,
            resolved_series=resolved_series,
            log_level=log_level,
        )
    except ConfigError as exc:
        _fail_i18n_command(
            global_config=global_config,
            operation=operation,
            message=str(exc),
            print_command_error_result_fn=print_command_error_result_fn,
            error_type="ConfigError",
        )

    require_cli_runtime_db_mutation_fn(
        global_config=global_config,
        env_config=env_config,
        allow_mutation=allow_mutation,
        operation=operation,
        action="translation import",
        print_command_error_result_fn=print_command_error_result_fn,
        confirmation_required_error_fn=confirmation_required_error_fn,
    )
    ops = build_odoo_operations_fn(global_config)
    result = ops.import_translations(
        files=normalized_files,
        language=language,
        overwrite=overwrite,
        odoo_series=resolved_series,
        log_level=log_level.value if log_level else None,
        suppress_output=global_config.format == OutputFormat.JSON,
    )
    _emit_json_result(
        global_config=global_config,
        result=result,
        result_type="i18n_import",
        include_command=include_command,
        include_stdout=include_stdout,
        additional_fields={
            "files": normalized_files,
            "language": language,
            "overwrite": overwrite,
            "odoo_series": _normalize_series_label(resolved_series),
        },
    )
    if not result.get("success", False):
        raise typer.Exit(1)


def i18n_loadlang_command(
    ctx: typer.Context,
    *,
    languages: list[str],
    allow_mutation: bool,
    include_command: bool,
    include_stdout: bool,
    log_level: LogLevel | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    module_manager_cls: type[ModuleManager],
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Load languages into the configured database."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    normalized_languages = _split_csv_values(languages)
    operation = "i18n_loadlang"
    try:
        resolved_series = _resolve_i18n_series(
            global_config=global_config,
            env_config=env_config,
            module_manager_cls=module_manager_cls,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )
        _validate_load_request(
            env_config=env_config,
            languages=normalized_languages,
            resolved_series=resolved_series,
            log_level=log_level,
        )
    except ConfigError as exc:
        _fail_i18n_command(
            global_config=global_config,
            operation=operation,
            message=str(exc),
            print_command_error_result_fn=print_command_error_result_fn,
            error_type="ConfigError",
        )

    require_cli_runtime_db_mutation_fn(
        global_config=global_config,
        env_config=env_config,
        allow_mutation=allow_mutation,
        operation=operation,
        action="language loading",
        print_command_error_result_fn=print_command_error_result_fn,
        confirmation_required_error_fn=confirmation_required_error_fn,
    )
    ops = build_odoo_operations_fn(global_config)
    result = ops.load_languages(
        languages=normalized_languages,
        odoo_series=resolved_series,
        log_level=log_level.value if log_level else None,
        suppress_output=global_config.format == OutputFormat.JSON,
    )
    _emit_json_result(
        global_config=global_config,
        result=result,
        result_type="i18n_loadlang",
        include_command=include_command,
        include_stdout=include_stdout,
        additional_fields={
            "languages": normalized_languages,
            "odoo_series": _normalize_series_label(resolved_series),
        },
    )
    if not result.get("success", False):
        raise typer.Exit(1)


def export_lang_compat_command(
    ctx: typer.Context,
    *,
    module: str,
    language: str | None,
    allow_mutation: bool,
    include_command: bool,
    include_stdout: bool,
    log_level: LogLevel | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    module_manager_cls: type[ModuleManager],
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Compatibility wrapper for ``export-lang``."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    operation = "export_language"
    language_value = language or env_config.get("language", "de_DE")
    if language_value is None:
        language_value = "de_DE"

    module_manager = module_manager_cls(env_config["addons_path"])
    module_path = module_manager.find_module_path(module)
    if module_path is None:
        _fail_i18n_command(
            global_config=global_config,
            operation=operation,
            message=f"Module '{module}' was not found in the configured addons paths.",
            print_command_error_result_fn=print_command_error_result_fn,
            error_type="ModuleNotFoundError",
            details={"module": module},
        )

    _require_source_mutation(
        global_config=global_config,
        allow_mutation=allow_mutation,
        operation=operation,
        action="Translation export",
        confirmation_required_error_fn=confirmation_required_error_fn,
    )

    filename = _compat_export_output_path(module_path, language_value)
    try:
        resolved_series = _resolve_i18n_series(
            global_config=global_config,
            env_config=env_config,
            module_manager_cls=module_manager_cls,
            build_odoo_operations_fn=build_odoo_operations_fn,
        )
        _validate_export_request(
            env_config=env_config,
            modules=[module],
            languages=[language_value],
            output=str(filename),
            resolved_series=resolved_series,
            log_level=log_level,
        )
    except ConfigError as exc:
        _fail_i18n_command(
            global_config=global_config,
            operation=operation,
            message=str(exc),
            print_command_error_result_fn=print_command_error_result_fn,
            error_type="ConfigError",
        )

    os.makedirs(filename.parent, exist_ok=True)
    ops = build_odoo_operations_fn(global_config)
    result = ops.export_module_language(
        module,
        str(filename),
        language_value,
        no_http=global_config.no_http,
        log_level=log_level.value if log_level else None,
        suppress_output=global_config.format == OutputFormat.JSON,
        odoo_series=resolved_series,
    )
    _emit_json_result(
        global_config=global_config,
        result=result,
        result_type="i18n_export",
        include_command=include_command,
        include_stdout=include_stdout,
        additional_fields={
            "module": module,
            "language": language_value,
            "filename": str(filename),
            "odoo_series": _normalize_series_label(resolved_series),
            "compatibility_alias": True,
        },
    )
    if not result.get("success", False):
        raise typer.Exit(1)
