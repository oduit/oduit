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
from ...exceptions import ConfigError
from ...module_manager import ModuleManager
from ...operation_sets import (
    InstallSetSection,
    OperationSetMode,
    TestSetSection,
    UpdateSetSection,
    build_operation_set_result,
    load_operation_set,
    require_section,
    sanitize_operation_result,
    validate_operation_set_addons,
)
from ...output import print_error, print_info, print_warning
from ...schemas import CONTROLLED_RUNTIME_MUTATION
from ...utils import build_json_payload, output_result_to_json
from .module_input import resolve_module_argument, resolve_module_names


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
    module_names, _ = resolve_module_names(modules)
    result = odoo_operations.list_installed_addons(
        modules=module_names or None,
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
    module: str | None,
    without_demo: str | None,
    with_demo: bool,
    language: str | None,
    max_cron_threads: int | None,
    log_level: LogLevel | None,
    allow_mutation: bool,
    compact: bool,
    include_command: bool,
    include_stdout: bool,
    operation_set: str | None = None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Install a module."""
    if operation_set:
        return operation_set_command(
            ctx,
            mode="install",
            operation_set=operation_set,
            allow_mutation=allow_mutation,
            allow_missing_test_files=False,
            include_command=include_command,
            include_stdout=include_stdout,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            require_cli_runtime_db_mutation_fn=require_cli_runtime_db_mutation_fn,
            confirmation_required_error_fn=confirmation_required_error_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )
    """Install a module."""
    module, _ = resolve_module_argument(module)
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
    module: str | None,
    without_demo: str | None,
    language: str | None,
    i18n_overwrite: bool,
    max_cron_threads: int | None,
    log_level: LogLevel | None,
    allow_mutation: bool,
    compact: bool,
    include_command: bool = False,
    include_stdout: bool = False,
    operation_set: str | None = None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Update a module."""
    if operation_set:
        return operation_set_command(
            ctx,
            mode="update",
            operation_set=operation_set,
            allow_mutation=allow_mutation,
            allow_missing_test_files=False,
            include_command=include_command,
            include_stdout=include_stdout,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            require_cli_runtime_db_mutation_fn=require_cli_runtime_db_mutation_fn,
            confirmation_required_error_fn=confirmation_required_error_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )
    """Update a module."""
    module, _ = resolve_module_argument(module)
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
    operation_set: str | None = None,
    allow_missing_test_files: bool = False,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Run module tests."""
    if operation_set:
        return operation_set_command(
            ctx,
            mode="test",
            operation_set=operation_set,
            allow_mutation=allow_mutation,
            allow_missing_test_files=allow_missing_test_files,
            include_command=include_command,
            include_stdout=include_stdout,
            resolve_command_env_config_fn=resolve_command_env_config_fn,
            build_odoo_operations_fn=build_odoo_operations_fn,
            require_cli_runtime_db_mutation_fn=require_cli_runtime_db_mutation_fn,
            confirmation_required_error_fn=confirmation_required_error_fn,
            print_command_error_result_fn=print_command_error_result_fn,
        )
    """Run module tests."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    is_runtime_db_mutation = bool(install or update)
    if is_runtime_db_mutation:
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


def _execute_install_section(
    odoo_operations: Any,
    section: InstallSetSection,
    global_config: Any,
    suppress_output: bool,
) -> dict[str, Any]:
    """Execute an install set section."""
    addons_csv = ",".join(section.addons)
    if not addons_csv:
        return {
            "success": True,
            "operation": "install",
            "section": "install",
            "note": "empty",
        }

    without_demo_arg: bool | str = section.without_demo
    if without_demo_arg is True:
        without_demo_arg = addons_csv

    result: Any = odoo_operations.install_module(
        addons_csv,
        no_http=global_config.no_http,
        max_cron_threads=section.max_cron_threads,
        without_demo=without_demo_arg,
        with_demo=section.with_demo,
        language=section.language,
        compact=section.compact,
        log_level=section.log_level,
        suppress_output=suppress_output,
    )
    return result  # type: ignore[no-any-return]


def _execute_update_section(
    odoo_operations: Any,
    section: UpdateSetSection,
    global_config: Any,
    suppress_output: bool,
) -> dict[str, Any]:
    """Execute an update set section."""
    addons_csv = ",".join(section.addons)
    if not addons_csv:
        return {
            "success": True,
            "operation": "update",
            "section": "update",
            "note": "empty",
        }

    without_demo_arg: bool | str = section.without_demo
    if without_demo_arg is True:
        without_demo_arg = addons_csv

    result: Any = odoo_operations.update_module(
        addons_csv,
        no_http=global_config.no_http,
        max_cron_threads=section.max_cron_threads,
        without_demo=without_demo_arg,
        language=section.language,
        i18n_overwrite=section.i18n_overwrite,
        compact=section.compact,
        log_level=section.log_level,
        suppress_output=suppress_output,
    )
    return result  # type: ignore[no-any-return]


def _execute_test_section(
    odoo_operations: Any,
    section: TestSetSection,
    global_config: Any,
    suppress_output: bool,
) -> list[dict[str, Any]]:
    """Execute a test set section, returning one result per operation."""
    results: list[dict[str, Any]] = []

    # Pre-test install
    if section.install:
        install_csv = ",".join(section.install)
        without_demo_arg: bool | str = True
        install_result = odoo_operations.install_module(
            install_csv,
            no_http=global_config.no_http,
            without_demo=without_demo_arg,
            compact=section.compact,
            log_level=section.log_level,
            suppress_output=suppress_output,
        )
        results.append(
            {
                "section": "test",
                "operation": "install",
                "success": install_result.get("success", False),
                "addons": list(section.install),
                **install_result,
            }
        )
        if not install_result.get("success", False) and section.stop_on_error:
            return results

    # Pre-test update
    if section.update:
        update_csv = ",".join(section.update)
        without_demo_arg = True
        update_result = odoo_operations.update_module(
            update_csv,
            no_http=global_config.no_http,
            without_demo=without_demo_arg,
            compact=section.compact,
            log_level=section.log_level,
            suppress_output=suppress_output,
        )
        results.append(
            {
                "section": "test",
                "operation": "update",
                "success": update_result.get("success", False),
                "addons": list(section.update),
                **update_result,
            }
        )
        if not update_result.get("success", False) and section.stop_on_error:
            return results

    # Test by tags
    if section.test_tags:
        combined_tags = ",".join(section.test_tags)
        test_result = odoo_operations.run_tests(
            None,
            stop_on_error=section.stop_on_error,
            coverage=section.coverage,
            test_tags=combined_tags,
            compact=section.compact,
            log_level=section.log_level,
            suppress_output=suppress_output,
        )
        results.append(
            {
                "section": "test",
                "operation": "test",
                "test_tags": list(section.test_tags),
                "success": test_result.get("success", False),
                **test_result,
            }
        )
        if not test_result.get("success", False) and section.stop_on_error:
            return results

    # Test by files
    for i, resolved_path in enumerate(section.test_files):
        original_input = (
            section.test_file_inputs[i]
            if i < len(section.test_file_inputs)
            else str(resolved_path)
        )
        test_result = odoo_operations.run_tests(
            None,
            stop_on_error=section.stop_on_error,
            coverage=section.coverage if not section.test_tags else None,
            test_file=str(resolved_path),
            compact=section.compact,
            log_level=section.log_level,
            suppress_output=suppress_output,
        )
        results.append(
            {
                "section": "test",
                "operation": "test",
                "test_file": original_input,
                "success": test_result.get("success", False),
                **test_result,
            }
        )
        if not test_result.get("success", False) and section.stop_on_error:
            return results

    # If no tags and no files but coverage is set, run generic test
    if not section.test_tags and not section.test_files and section.coverage:
        test_result = odoo_operations.run_tests(
            None,
            stop_on_error=section.stop_on_error,
            coverage=section.coverage,
            compact=section.compact,
            log_level=section.log_level,
            suppress_output=suppress_output,
        )
        results.append(
            {
                "section": "test",
                "operation": "test",
                "coverage": section.coverage,
                "success": test_result.get("success", False),
                **test_result,
            }
        )

    return results


def _build_section_list(
    op_set: Any, mode: OperationSetMode
) -> tuple[list[tuple[str, Any]], list[dict[str, Any]]]:
    """Build (sections, skipped) lists for the given mode."""
    sections: list[tuple[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    if mode == "apply":
        for name, sec in [
            ("install", op_set.install),
            ("update", op_set.update),
            ("test", op_set.test),
        ]:
            if sec:
                sections.append((name, sec))
            else:
                skipped.append({"section": name, "reason": "section_absent"})
    elif mode == "install":
        sections.append(("install", op_set.install))
    elif mode == "update":
        sections.append(("update", op_set.update))
    elif mode == "test":
        sections.append(("test", op_set.test))

    return sections, skipped


def _run_sections(
    sections: list[tuple[str, Any]],
    odoo_operations: Any,
    global_config: Any,
    suppress_output: bool,
    include_command: bool,
    include_stdout: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Execute sections and return (results, failures)."""
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for section_name, section in sections:
        if section_name in ("install", "update"):
            if section_name == "install":
                result = _execute_install_section(
                    odoo_operations,
                    section,
                    global_config,
                    suppress_output,
                )
            else:
                result = _execute_update_section(
                    odoo_operations,
                    section,
                    global_config,
                    suppress_output,
                )
            sanitized = sanitize_operation_result(
                result,
                include_command=include_command,
                include_stdout=include_stdout,
            )
            sanitized["section"] = section_name
            sanitized["addons"] = list(section.addons)
            results.append(sanitized)
            if not result.get("success", False):
                failures.append(sanitized)
                break
        elif section_name == "test":
            test_results = _execute_test_section(
                odoo_operations,
                section,
                global_config,
                suppress_output,
            )
            for tr in test_results:
                sanitized = sanitize_operation_result(
                    tr,
                    include_command=include_command,
                    include_stdout=include_stdout,
                )
                results.append(sanitized)
                if not tr.get("success", False):
                    failures.append(sanitized)
                    if section.stop_on_error:
                        break
            if failures:
                break

    return results, failures


def operation_set_command(
    ctx: typer.Context,
    *,
    mode: OperationSetMode,
    operation_set: str,
    allow_mutation: bool,
    allow_missing_test_files: bool,
    include_command: bool,
    include_stdout: bool,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Execute an operation set for a single mode (install, update, or test)."""
    import time as _time

    global_config, env_config = resolve_command_env_config_fn(ctx)
    suppress_output = global_config.format == OutputFormat.JSON

    operation = f"operation_set_{mode}"
    require_cli_runtime_db_mutation_fn(
        global_config=global_config,
        env_config=env_config,
        allow_mutation=allow_mutation,
        operation=operation,
        action=f"operation set {mode}",
        print_command_error_result_fn=print_command_error_result_fn,
        confirmation_required_error_fn=confirmation_required_error_fn,
    )

    started_at = _time.time()
    try:
        op_set = load_operation_set(
            operation_set,
            allow_missing_test_files=allow_missing_test_files,
        )
    except ConfigError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from None

    if mode != "apply":
        try:
            require_section(op_set, mode)
        except ConfigError as exc:
            print_error(str(exc))
            raise typer.Exit(1) from None

    try:
        validate_operation_set_addons(op_set, addons_path=env_config["addons_path"])
    except ConfigError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from None

    odoo_operations = build_odoo_operations_fn(global_config)

    if not suppress_output:
        label = op_set.name or op_set.requested_value
        print_info(f"Applying operation set: {label} ({op_set.path})")

    sections, skipped = _build_section_list(op_set, mode)

    if mode == "apply" and not sections:
        print_error("Operation set has no sections to execute.")
        raise typer.Exit(1) from None

    results, failures = _run_sections(
        sections,
        odoo_operations,
        global_config,
        suppress_output,
        include_command,
        include_stdout,
    )

    aggregate = build_operation_set_result(
        op_set,
        mode=mode,
        results=results,
        skipped_operations=skipped,
        failures=failures,
        started_at=started_at,
    )

    if global_config.format == OutputFormat.JSON:
        payload = build_json_payload(
            "operation_set_result",
            aggregate,
            success=aggregate["success"],
            flatten_data=True,
        )
        payload["read_only"] = False
        payload["safety_level"] = CONTROLLED_RUNTIME_MUTATION
        print(json.dumps(payload))
    else:
        summary = aggregate["summary"]
        if aggregate["success"]:
            print_info(
                f"Operation set succeeded: "
                f"{summary['executed']} executed, "
                f"{summary['failed']} failed, "
                f"{summary['skipped']} skipped"
            )
        else:
            print_error(
                f"Operation set failed: "
                f"{summary['executed']} executed, "
                f"{summary['failed']} failed, "
                f"{summary['skipped']} skipped"
            )

    if not aggregate["success"]:
        raise typer.Exit(1)


def apply_command(
    ctx: typer.Context,
    *,
    operation_set: str,
    allow_mutation: bool,
    allow_missing_test_files: bool,
    include_command: bool,
    include_stdout: bool,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Run an operation set in apply mode (install, update, test in order)."""
    operation_set_command(
        ctx,
        mode="apply",
        operation_set=operation_set,
        allow_mutation=allow_mutation,
        allow_missing_test_files=allow_missing_test_files,
        include_command=include_command,
        include_stdout=include_stdout,
        resolve_command_env_config_fn=resolve_command_env_config_fn,
        build_odoo_operations_fn=build_odoo_operations_fn,
        require_cli_runtime_db_mutation_fn=require_cli_runtime_db_mutation_fn,
        confirmation_required_error_fn=confirmation_required_error_fn,
        print_command_error_result_fn=print_command_error_result_fn,
    )
