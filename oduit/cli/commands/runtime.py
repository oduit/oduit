"""Runtime and system command implementations."""

import json
import os
from typing import Any

import typer

from ...cli_types import (
    DevFeature,
    LogLevel,
    OutputFormat,
    ShellInterface,
)
from ...module_manager import ModuleManager
from ...output import print_error, print_info, print_warning
from ...utils import output_result_to_json


def _parse_csv_items(raw_value: str | None) -> list[str] | None:
    """Parse a comma-separated CLI option into a list of strings."""
    if raw_value is None:
        return None
    items = [item.strip() for item in raw_value.split(",") if item.strip()]
    return items or None


def _config_flag_enabled(value: Any) -> bool:
    """Normalize boolean-like config values from CLI config dictionaries."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def doctor_command(
    ctx: typer.Context,
    *,
    resolve_command_global_config_fn: Any,
    build_doctor_report_fn: Any,
    print_doctor_report_fn: Any,
) -> None:
    """Diagnose environment and configuration issues."""
    global_config = resolve_command_global_config_fn(ctx)
    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    report = build_doctor_report_fn(global_config)
    if global_config.format == OutputFormat.JSON:
        print(json.dumps(report))
    else:
        print_doctor_report_fn(report)

    if not report.get("success", False):
        raise typer.Exit(1)


def list_installed_addons_command(
    ctx: typer.Context,
    *,
    modules: str | None,
    state: list[str],
    separator: str | None,
    include_state: bool,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
) -> None:
    """List runtime addon inventory from the active database."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    odoo_operations = build_odoo_operations_fn(global_config)
    result = odoo_operations.list_installed_addons(
        modules=_parse_csv_items(modules),
        states=state or None,
    )

    if global_config.format == OutputFormat.JSON:
        print(
            json.dumps(
                output_result_to_json(
                    result.to_dict(),
                    result_type="installed_addon_inventory",
                )
            )
        )
    elif result.success:
        output_items = [
            f"{addon.module}:{addon.state}" if include_state else addon.module
            for addon in result.addons
        ]
        if separator:
            print(separator.join(output_items))
        else:
            for item in output_items:
                print(item)
    else:
        print_error(result.error or "Runtime installed-addon query failed")

    if not result.success:
        raise typer.Exit(1)


def run_command(
    ctx: typer.Context,
    *,
    dev: DevFeature | None,
    log_level: LogLevel | None,
    stop_after_init: bool,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
) -> None:
    """Run Odoo server."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    odoo_operations = build_odoo_operations_fn(global_config)
    odoo_operations.run_odoo(
        no_http=global_config.no_http,
        dev=dev,
        log_level=log_level.value if log_level else None,
        stop_after_init=stop_after_init,
    )


def shell_command(
    ctx: typer.Context,
    *,
    shell_interface: ShellInterface | None,
    compact: bool,
    log_level: LogLevel | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
) -> None:
    """Start Odoo shell."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    odoo_operations = build_odoo_operations_fn(global_config)
    odoo_operations.run_shell(
        shell_interface=shell_interface.value if shell_interface else None,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )


def install_command(
    ctx: typer.Context,
    *,
    module: str,
    without_demo: str | None,
    with_demo: bool,
    language: str | None,
    max_cron_threads: int | None,
    log_level: LogLevel | None,
    allow_mutation: bool,
    compact: bool,
    include_command: bool,
    include_stdout: bool,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Install a module."""
    if not module:
        print_error("Module name is required for install")
        raise typer.Exit(1) from None

    global_config, env_config = resolve_command_env_config_fn(ctx)
    require_cli_runtime_db_mutation_fn(
        global_config=global_config,
        env_config=env_config,
        allow_mutation=allow_mutation,
        operation="install_module",
        action="module install",
        print_command_error_result_fn=print_command_error_result_fn,
        confirmation_required_error_fn=confirmation_required_error_fn,
    )
    odoo_operations = build_odoo_operations_fn(global_config)
    output = odoo_operations.install_module(
        module,
        no_http=global_config.no_http,
        max_cron_threads=max_cron_threads,
        without_demo=without_demo or False,
        with_demo=with_demo,
        language=language,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )

    if global_config.format == OutputFormat.JSON:
        exclude_fields = ["command", "stdout"]
        additional_fields = {
            "without_demo": without_demo,
            "verbose": global_config.verbose,
        }
        if include_command:
            exclude_fields.remove("command")
        if include_stdout:
            exclude_fields.remove("stdout")
        result_json = output_result_to_json(
            output,
            additional_fields=additional_fields,
            exclude_fields=exclude_fields,
        )
        print(json.dumps(result_json))

    if not output.get("success"):
        raise typer.Exit(1)


def update_command(
    ctx: typer.Context,
    *,
    module: str,
    without_demo: str | None,
    language: str | None,
    i18n_overwrite: bool,
    max_cron_threads: int | None,
    log_level: LogLevel | None,
    allow_mutation: bool,
    compact: bool,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Update a module."""
    if not module:
        print_error("Module name is required for update")
        raise typer.Exit(1) from None

    global_config, env_config = resolve_command_env_config_fn(ctx)
    require_cli_runtime_db_mutation_fn(
        global_config=global_config,
        env_config=env_config,
        allow_mutation=allow_mutation,
        operation="update_module",
        action="module update",
        print_command_error_result_fn=print_command_error_result_fn,
        confirmation_required_error_fn=confirmation_required_error_fn,
    )
    if i18n_overwrite:
        language = language or env_config.get("language", "de_DE")
        if language is None:
            language = "de_DE"

    odoo_operations = build_odoo_operations_fn(global_config)
    result = odoo_operations.update_module(
        module,
        no_http=global_config.no_http,
        max_cron_threads=max_cron_threads,
        without_demo=without_demo or False,
        language=language,
        i18n_overwrite=i18n_overwrite,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )
    if compact and result:
        print_info(str(result))

    if not result.get("success"):
        raise typer.Exit(1)


def uninstall_command(
    ctx: typer.Context,
    *,
    module: str,
    allow_uninstall: bool,
    allow_mutation: bool,
    compact: bool,
    log_level: LogLevel | None,
    include_command: bool,
    include_stdout: bool,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Uninstall a module."""
    if not module:
        print_error("Module name is required for uninstall")
        raise typer.Exit(1) from None

    global_config, env_config = resolve_command_env_config_fn(ctx)
    require_cli_runtime_db_mutation_fn(
        global_config=global_config,
        env_config=env_config,
        allow_mutation=allow_mutation,
        operation="uninstall_module",
        action="module uninstall",
        print_command_error_result_fn=print_command_error_result_fn,
        confirmation_required_error_fn=confirmation_required_error_fn,
    )
    if not _config_flag_enabled(env_config.get("allow_uninstall", False)):
        print_command_error_result_fn(
            global_config,
            "uninstall_module",
            "Uninstall is disabled in this environment. "
            "Set allow_uninstall=true in config.",
            error_type="ConfigError",
            details={"module": module},
            remediation=[
                "Enable `allow_uninstall = true` in the selected environment.",
            ],
        )
        raise typer.Exit(1) from None

    if not allow_uninstall:
        confirmation_required_error_fn(
            global_config,
            "uninstall_module",
            "Uninstall requires --allow-uninstall.",
            remediation=[
                f"Retry `oduit uninstall {module} --allow-uninstall` after "
                "reviewing dependent modules.",
            ],
        )

    odoo_operations = build_odoo_operations_fn(global_config)
    result = odoo_operations.uninstall_module(
        module,
        suppress_output=True,
        compact=compact,
        log_level=log_level.value if log_level else None,
        allow_uninstall=allow_uninstall,
    )

    if global_config.format == OutputFormat.JSON:
        exclude_fields = ["command", "stdout"]
        if include_command:
            exclude_fields.remove("command")
        if include_stdout:
            exclude_fields.remove("stdout")
        payload = output_result_to_json(
            result,
            additional_fields={"module": module},
            exclude_fields=exclude_fields,
            result_type="module_uninstallation",
        )
        print(json.dumps(payload))
    elif result.get("success", False):
        print_info(f"Uninstalled module: {module}")
    else:
        print_error(result.get("error") or "Module uninstall failed")

    if not result.get("success", False):
        raise typer.Exit(1)


def test_command(
    ctx: typer.Context,
    *,
    stop_on_error: bool,
    install: str | None,
    update: str | None,
    coverage: str | None,
    test_file: str | None,
    test_tags: str | None,
    compact: bool,
    log_level: LogLevel | None,
    allow_mutation: bool,
    include_command: bool,
    include_stdout: bool,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Run module tests."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    require_cli_runtime_db_mutation_fn(
        global_config=global_config,
        env_config=env_config,
        allow_mutation=allow_mutation,
        operation="test",
        action="test execution",
        print_command_error_result_fn=print_command_error_result_fn,
        confirmation_required_error_fn=confirmation_required_error_fn,
    )
    odoo_operations = build_odoo_operations_fn(global_config)
    result = odoo_operations.run_tests(
        None,
        stop_on_error=stop_on_error,
        update=update,
        install=install,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )

    if global_config.format == OutputFormat.JSON:
        exclude_fields = ["command", "stdout"]
        additional_fields: dict[str, Any] = {
            "stop_on_error": stop_on_error,
            "install": install,
            "update": update,
            "coverage": coverage,
            "test_file": test_file,
            "test_tags": test_tags,
            "compact": compact,
            "verbose": global_config.verbose,
        }
        if include_command:
            exclude_fields.remove("command")
        if include_stdout:
            exclude_fields.remove("stdout")
        result_json = output_result_to_json(
            result,
            additional_fields=additional_fields,
            exclude_fields=exclude_fields,
        )
        print(json.dumps(result_json))

    if not result.get("success"):
        raise typer.Exit(1)


def export_lang_command(
    ctx: typer.Context,
    *,
    module: str,
    language: str | None,
    log_level: LogLevel | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    module_manager_cls: type[ModuleManager] = ModuleManager,
) -> None:
    """Export module translations."""
    global_config, env_config = resolve_command_env_config_fn(ctx)

    language = language or env_config.get("language", "de_DE")
    if language is None:
        language = "de_DE"

    module_manager = module_manager_cls(env_config["addons_path"])
    module_path = module_manager.find_module_path(module)
    if not module_path:
        print_warning(
            f"Module '{module}' not found in addons path. Using default path."
        )
        module_path = os.path.join(env_config["addons_path"].split(",")[0], module)

    i18n_dir = os.path.join(module_path, "i18n")
    if "_" in language:
        filename = os.path.join(i18n_dir, f"{language.split('_')[0]}.po")
    else:
        filename = os.path.join(i18n_dir, f"{language}.po")

    os.makedirs(i18n_dir, exist_ok=True)
    odoo_operations = build_odoo_operations_fn(global_config)
    odoo_operations.export_module_language(
        module,
        filename,
        language,
        no_http=global_config.no_http,
        log_level=log_level.value if log_level else None,
    )


def get_odoo_version_command(
    ctx: typer.Context,
    *,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
) -> None:
    """Get the Odoo version."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    ops = build_odoo_operations_fn(global_config)
    result = ops.get_odoo_version(suppress_output=True)

    if global_config.format == OutputFormat.JSON:
        result_json = output_result_to_json(result)
        print(json.dumps(result_json))
        return

    if result.get("success", False) and result.get("version"):
        typer.echo(result["version"])
        return

    print_error("Failed to detect Odoo version")
    raise typer.Exit(1)
