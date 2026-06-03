"""Runtime and system command implementations."""

import json
import os
from typing import Any

import typer

from ...cli.bootstrap_support import resolve_operation_set_location_context
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
    TestSetSection,
    UpdateSetSection,
    build_operation_set_result,
    inspect_operation_set,
    list_operation_sets,
    load_operation_set,
    sanitize_operation_result,
    validate_operation_set_addons,
)
from ...output import print_error, print_info, print_warning
from ...schemas import CONTROLLED_RUNTIME_MUTATION, SAFE_READ_ONLY
from ...utils import build_json_payload, output_result_to_json
from .module_input import resolve_module_argument, resolve_module_names
from .operation_set_cli import save_addon_list_as_operation_set


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
    save_set: str | None,
    set_kind: str | None,
    set_name: str | None,
    set_description: str | None,
    overwrite: bool,
    config_loader_cls: Any,
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

    saved_set = None
    if result.success and save_set:
        saved_set = save_addon_list_as_operation_set(
            global_config=global_config,
            config_loader_cls=config_loader_cls,
            save_set=save_set,
            addons=[addon.module for addon in result.addons],
            set_kind=set_kind,
            default_kind="install",
            overwrite=overwrite,
            set_name=set_name,
            set_description=set_description,
            source={
                "command": "list-installed-addons",
                "state": list(state or ["installed"]),
                "env": global_config.env_name,
                "config_source": global_config.config_source,
                "config_path": global_config.config_path,
            },
        )

    if global_config.format == OutputFormat.JSON:
        payload_data = result.to_dict()
        if saved_set is not None:
            payload_data["saved_set"] = {
                "path": str(saved_set.path),
                "kind": saved_set.kind,
                "addon_count": saved_set.addon_count,
            }
        print(
            json.dumps(
                output_result_to_json(
                    payload_data,
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
        if saved_set is not None:
            typer.echo(f"Saved {saved_set.kind} set: {saved_set.path}", err=True)
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
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
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
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
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
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
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


_RUNTIME_MODULE_STATES = [
    "installed",
    "uninstalled",
    "to install",
    "to upgrade",
    "to remove",
]


def _query_requested_addon_states(
    odoo_operations: Any,
    addons: list[str],
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    unique_addons = list(dict.fromkeys(addons))
    if not unique_addons:
        return {"success": True, "states": {}, "missing": []}

    inventory = odoo_operations.list_installed_addons(
        modules=unique_addons,
        states=_RUNTIME_MODULE_STATES,
        timeout=timeout,
    )
    if not getattr(inventory, "success", False):
        return {
            "success": False,
            "states": {},
            "missing": unique_addons,
            "error": getattr(inventory, "error", None) or "Runtime state query failed",
            "error_type": getattr(inventory, "error_type", None),
        }

    records = getattr(inventory, "addons", []) or []
    states = {addon: "uninstalled" for addon in unique_addons}
    for record in records:
        module = getattr(record, "module", None) or record.get("module")
        state = getattr(record, "state", None) or record.get("state")
        if module in states:
            states[module] = state or "uninstalled"

    missing = [addon for addon, state in states.items() if state != "installed"]
    return {"success": True, "states": states, "missing": missing}


def _call_install_module(
    odoo_operations: Any,
    addons_csv: str,
    section: Any,
    global_config: Any,
    suppress_output: bool,
    without_demo_arg: bool | str,
) -> Any:
    return odoo_operations.install_module(
        addons_csv,
        no_http=global_config.no_http,
        max_cron_threads=getattr(section, "max_cron_threads", None),
        without_demo=without_demo_arg,
        with_demo=getattr(section, "with_demo", False),
        language=getattr(section, "language", None),
        compact=getattr(section, "compact", False),
        log_level=getattr(section, "log_level", None),
        suppress_output=suppress_output,
    )


def _call_update_module(
    odoo_operations: Any,
    addons_csv: str,
    section: Any,
    global_config: Any,
    suppress_output: bool,
    without_demo_arg: bool | str,
) -> Any:
    return odoo_operations.update_module(
        addons_csv,
        no_http=global_config.no_http,
        max_cron_threads=getattr(section, "max_cron_threads", None),
        without_demo=without_demo_arg,
        language=getattr(section, "language", None),
        i18n_overwrite=getattr(section, "i18n_overwrite", False),
        compact=getattr(section, "compact", False),
        log_level=getattr(section, "log_level", None),
        suppress_output=suppress_output,
    )


def _make_install_section(
    addons: tuple[str, ...] | list[str],
    base_section: InstallSetSection | Any,
) -> InstallSetSection:
    return InstallSetSection(
        addons=tuple(addons),
        with_demo=getattr(base_section, "with_demo", False),
        without_demo=getattr(base_section, "without_demo", False),
        language=getattr(base_section, "language", None),
        max_cron_threads=getattr(base_section, "max_cron_threads", None),
        compact=getattr(base_section, "compact", False),
        log_level=getattr(base_section, "log_level", None),
    )


def _make_update_section(
    addons: tuple[str, ...] | list[str],
    base_section: UpdateSetSection | Any,
) -> UpdateSetSection:
    return UpdateSetSection(
        addons=tuple(addons),
        without_demo=getattr(base_section, "without_demo", False),
        language=getattr(base_section, "language", None),
        i18n_overwrite=getattr(base_section, "i18n_overwrite", False),
        max_cron_threads=getattr(base_section, "max_cron_threads", None),
        compact=getattr(base_section, "compact", False),
        log_level=getattr(base_section, "log_level", None),
    )


def _execute_addon_action(
    *,
    odoo_operations: Any,
    action: str,
    addons: tuple[str, ...],
    section: Any,
    global_config: Any,
    suppress_output: bool,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute install or update for a list of addons with verification and retry."""
    if policy is None:
        policy = {}

    original_addons = list(dict.fromkeys(addons))
    if not original_addons:
        return {
            "success": True,
            "operation": action,
            "section": action,
            "note": "empty",
        }

    verify_state = policy.get("verify_state", getattr(section, "verify_state", True))
    retry_missing = max(
        policy.get("retry_missing", getattr(section, "retry_missing", 0)), 0
    )
    one_by_one = policy.get("one_by_one", getattr(section, "one_by_one", False))
    section_stop = getattr(section, "stop_on_error", True)
    continue_on_error = policy.get("continue_on_error", False)
    stop_on_error = not continue_on_error and section_stop

    if one_by_one:
        return _execute_addon_action_one_by_one(
            odoo_operations=odoo_operations,
            action=action,
            addons=original_addons,
            section=section,
            global_config=global_config,
            suppress_output=suppress_output,
            verify_state=verify_state,
            retry_missing=retry_missing,
            stop_on_error=stop_on_error,
        )
    else:
        return _execute_addon_action_batch(
            odoo_operations=odoo_operations,
            action=action,
            addons=original_addons,
            section=section,
            global_config=global_config,
            suppress_output=suppress_output,
            verify_state=verify_state,
            retry_missing=retry_missing,
        )


def _run_addon_mutation(
    odoo_operations: Any,
    action: str,
    addons_csv: str,
    section: Any,
    global_config: Any,
    suppress_output: bool,
) -> Any:
    without_demo_arg: bool | str = getattr(section, "without_demo", False)
    if without_demo_arg is True:
        without_demo_arg = addons_csv

    if action == "install":
        return _call_install_module(
            odoo_operations,
            addons_csv,
            section,
            global_config,
            suppress_output,
            without_demo_arg,
        )
    else:
        return _call_update_module(
            odoo_operations,
            addons_csv,
            section,
            global_config,
            suppress_output,
            without_demo_arg,
        )


def _execute_addon_action_batch(
    *,
    odoo_operations: Any,
    action: str,
    addons: list[str],
    section: Any,
    global_config: Any,
    suppress_output: bool,
    verify_state: bool,
    retry_missing: int,
) -> dict[str, Any]:
    skipped_addons: list[str] = []
    addons_to_run = list(addons)

    # Pre-flight checks
    if action == "install" and getattr(section, "skip_installed", True):
        precheck = _query_requested_addon_states(odoo_operations, addons_to_run)
        if precheck["success"]:
            skipped_addons = [
                a for a, s in precheck["states"].items() if s == "installed"
            ]
            addons_to_run = [a for a in addons_to_run if a not in skipped_addons]
    elif action == "update" and getattr(section, "require_installed", True):
        precheck = _query_requested_addon_states(odoo_operations, addons_to_run)
        if precheck["success"]:
            not_installed = [
                a for a, s in precheck["states"].items() if s != "installed"
            ]
            if not_installed:
                return {
                    "success": False,
                    "operation": action,
                    "section": action,
                    "execution_mode": "batch",
                    "addons": addons,
                    "skipped_addons": skipped_addons,
                    "error": (
                        f"Update precheck failed: addons not installed: "
                        f"{', '.join(not_installed)}"
                    ),
                    "error_type": "precheck_failed",
                    "precheck_missing": not_installed,
                }

    if not addons_to_run:
        return {
            "success": True,
            "operation": action,
            "section": action,
            "execution_mode": "batch",
            "addons": addons,
            "skipped_addons": skipped_addons,
            "note": "all_skipped",
        }

    addons_csv = ",".join(addons_to_run)
    result: Any = _run_addon_mutation(
        odoo_operations,
        action,
        addons_csv,
        section,
        global_config,
        suppress_output,
    )
    process_success = (
        result.get("success", False) if isinstance(result, dict) else False
    )

    attempts: list[dict[str, Any]] = [
        {"attempt": 1, "addons": addons_to_run, "success": process_success}
    ]

    verification: dict[str, Any] | None = None
    if verify_state:
        v = _query_requested_addon_states(odoo_operations, addons_to_run)
        verification = {
            "enabled": True,
            "states": v.get("states", {}),
            "missing": v.get("missing", []),
        }
        attempts[0]["verification"] = verification
        missing = v.get("missing", [])
        if missing and retry_missing > 0:
            for attempt_num in range(1, retry_missing + 1):
                retry_csv = ",".join(missing)
                retry_result: Any = _run_addon_mutation(
                    odoo_operations,
                    action,
                    retry_csv,
                    section,
                    global_config,
                    suppress_output,
                )
                retry_success = (
                    retry_result.get("success", False)
                    if isinstance(retry_result, dict)
                    else False
                )
                rv = _query_requested_addon_states(odoo_operations, missing)
                retry_verification = {
                    "enabled": True,
                    "states": rv.get("states", {}),
                    "missing": rv.get("missing", []),
                }
                attempts.append(
                    {
                        "attempt": attempt_num + 1,
                        "addons": missing,
                        "success": retry_success,
                        "verification": retry_verification,
                    }
                )
                missing = rv.get("missing", [])
                verification = retry_verification
                if not missing:
                    break

    final_missing = []
    if verification:
        final_missing = verification.get("missing", [])

    overall_success = process_success and not final_missing
    return {
        "success": overall_success,
        "operation": action,
        "section": action,
        "execution_mode": "batch",
        "addons": addons,
        "skipped_addons": skipped_addons,
        "attempts": attempts,
        "verification": verification,
        "missing_addons": final_missing,
        "process_success": process_success,
    }


def _execute_addon_action_one_by_one(
    *,
    odoo_operations: Any,
    action: str,
    addons: list[str],
    section: Any,
    global_config: Any,
    suppress_output: bool,
    verify_state: bool,
    retry_missing: int,
    stop_on_error: bool,
) -> dict[str, Any]:
    succeeded_addons: list[str] = []
    failed_addons: list[str] = []
    skipped_addons: list[str] = []
    attempts: list[dict[str, Any]] = []

    for addon in addons:
        # Pre-flight per addon
        if action == "install" and getattr(section, "skip_installed", True):
            pre = _query_requested_addon_states(odoo_operations, [addon])
            if pre["success"] and pre["states"].get(addon) == "installed":
                skipped_addons.append(addon)
                succeeded_addons.append(addon)
                continue
        elif action == "update" and getattr(section, "require_installed", True):
            pre = _query_requested_addon_states(odoo_operations, [addon])
            if not pre["success"] or pre["states"].get(addon) != "installed":
                failed_addons.append(addon)
                attempts.append(
                    {
                        "attempt": 1,
                        "addon": addon,
                        "success": False,
                        "error": (
                            f"Update precheck failed: addon not installed: {addon}"
                        ),
                        "error_type": "precheck_failed",
                    }
                )
                if stop_on_error:
                    break
                continue

        addon_success = False
        for attempt_num in range(1, retry_missing + 2):
            result: Any = _run_addon_mutation(
                odoo_operations,
                action,
                addon,
                section,
                global_config,
                suppress_output,
            )
            process_success = (
                result.get("success", False) if isinstance(result, dict) else False
            )
            attempt_info: dict[str, Any] = {
                "attempt": attempt_num,
                "addon": addon,
                "success": process_success,
            }
            if verify_state:
                v = _query_requested_addon_states(odoo_operations, [addon])
                attempt_info["verification"] = {
                    "enabled": True,
                    "states": v.get("states", {}),
                    "missing": v.get("missing", []),
                }
                installed = (
                    v.get("success") and v.get("states", {}).get(addon) == "installed"
                )
                addon_success = bool(process_success and installed)
            else:
                addon_success = process_success
            attempts.append(attempt_info)
            if addon_success:
                break
            if attempt_num > retry_missing:
                break

        if addon_success:
            succeeded_addons.append(addon)
        else:
            failed_addons.append(addon)
            if stop_on_error:
                break

    return {
        "success": len(failed_addons) == 0,
        "operation": action,
        "section": action,
        "execution_mode": "one_by_one",
        "addons": addons,
        "succeeded_addons": succeeded_addons,
        "failed_addons": failed_addons,
        "skipped_addons": skipped_addons,
        "attempts": attempts,
        "missing_addons": failed_addons,
    }


def _execute_test_section(  # noqa: C901
    odoo_operations: Any,
    section: TestSetSection,
    global_config: Any,
    suppress_output: bool,
    policy: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Execute a test set section, returning one result per operation."""
    if policy is None:
        policy = {}
    results: list[dict[str, Any]] = []

    # Derive effective execution controls from policy and section
    effective_policy = {
        "verify_state": policy.get(
            "verify_state", getattr(section, "verify_state", True)
        ),
        "retry_missing": policy.get(
            "retry_missing", getattr(section, "retry_missing", 0)
        ),
        "one_by_one": policy.get("one_by_one", getattr(section, "one_by_one", False)),
        "continue_on_error": policy.get("continue_on_error", False),
    }

    # Pre-test install
    if section.install:
        install_section = _make_install_section(section.install, section)
        install_result = _execute_addon_action(
            odoo_operations=odoo_operations,
            action="install",
            addons=section.install,
            section=install_section,
            global_config=global_config,
            suppress_output=suppress_output,
            policy=effective_policy,
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
        update_section = _make_update_section(section.update, section)
        update_result = _execute_addon_action(
            odoo_operations=odoo_operations,
            action="update",
            addons=section.update,
            section=update_section,
            global_config=global_config,
            suppress_output=suppress_output,
            policy=effective_policy,
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
    retry_failed_tests = max(
        policy.get("retry_failed_tests", getattr(section, "retry_failed_tests", 0)), 0
    )
    one_by_one = effective_policy["one_by_one"]
    if section.test_tags:
        if one_by_one:
            for tag in section.test_tags:
                tag_result = None
                for attempt in range(1, retry_failed_tests + 2):
                    test_result = odoo_operations.run_tests(
                        None,
                        stop_on_error=section.stop_on_error,
                        coverage=section.coverage,
                        test_tags=tag,
                        compact=section.compact,
                        log_level=section.log_level,
                        suppress_output=suppress_output,
                    )
                    test_success = (
                        test_result.get("success", False)
                        if isinstance(test_result, dict)
                        else False
                    )
                    tag_result = {
                        "section": "test",
                        "operation": "test",
                        "test_tags": [tag],
                        "attempt": attempt,
                        "success": test_success,
                        **test_result,
                    }
                    if test_success or attempt > retry_failed_tests:
                        break
                    if section.stop_on_error:
                        results.append(tag_result)
                        return results
                if tag_result is not None:
                    results.append(tag_result)
        else:
            combined_tags = ",".join(section.test_tags)
            batch_result = None
            for attempt in range(1, retry_failed_tests + 2):
                test_result = odoo_operations.run_tests(
                    None,
                    stop_on_error=section.stop_on_error,
                    coverage=section.coverage,
                    test_tags=combined_tags,
                    compact=section.compact,
                    log_level=section.log_level,
                    suppress_output=suppress_output,
                )
                test_success = (
                    test_result.get("success", False)
                    if isinstance(test_result, dict)
                    else False
                )
                batch_result = {
                    "section": "test",
                    "operation": "test",
                    "test_tags": list(section.test_tags),
                    "attempt": attempt,
                    "success": test_success,
                    **test_result,
                }
                if test_success or attempt > retry_failed_tests:
                    break
            if batch_result is not None:
                results.append(batch_result)
            if (
                results
                and not results[-1].get("success", False)
                and section.stop_on_error
            ):
                return results

    # Test by files
    for i, resolved_path in enumerate(section.test_files):
        original_input = (
            section.test_file_inputs[i]
            if i < len(section.test_file_inputs)
            else str(resolved_path)
        )
        file_result = None
        for attempt in range(1, retry_failed_tests + 2):
            test_result = odoo_operations.run_tests(
                None,
                stop_on_error=section.stop_on_error,
                coverage=section.coverage if not section.test_tags else None,
                test_file=str(resolved_path),
                compact=section.compact,
                log_level=section.log_level,
                suppress_output=suppress_output,
            )
            test_success = (
                test_result.get("success", False)
                if isinstance(test_result, dict)
                else False
            )
            file_result = {
                "section": "test",
                "operation": "test",
                "test_file": original_input,
                "attempt": attempt,
                "success": test_success,
                **test_result,
            }
            if test_success or attempt > retry_failed_tests:
                break
            if section.stop_on_error:
                if file_result is not None:
                    results.append(file_result)
                return results
        if file_result is not None:
            results.append(file_result)

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


def _execute_install_section(
    odoo_operations: Any,
    section: InstallSetSection,
    global_config: Any,
    suppress_output: bool,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _execute_addon_action(
        odoo_operations=odoo_operations,
        action="install",
        addons=section.addons,
        section=section,
        global_config=global_config,
        suppress_output=suppress_output,
        policy=policy,
    )


def _execute_update_section(
    odoo_operations: Any,
    section: UpdateSetSection,
    global_config: Any,
    suppress_output: bool,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _execute_addon_action(
        odoo_operations=odoo_operations,
        action="update",
        addons=section.addons,
        section=section,
        global_config=global_config,
        suppress_output=suppress_output,
        policy=policy,
    )


def _run_sections(
    sections: list[tuple[str, Any]],
    odoo_operations: Any,
    global_config: Any,
    suppress_output: bool,
    include_command: bool,
    include_stdout: bool,
    policy: dict[str, Any] | None = None,
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
                    policy=policy,
                )
            else:
                result = _execute_update_section(
                    odoo_operations,
                    section,
                    global_config,
                    suppress_output,
                    policy=policy,
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
                policy=policy,
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


def _operation_set_context(
    global_config: Any,
    *,
    config_loader_cls: Any,
) -> Any:
    return resolve_operation_set_location_context(
        global_config,
        config_loader_cls=config_loader_cls,
    )


def _load_runtime_operation_set(
    operation_set: str,
    *,
    global_config: Any,
    config_loader_cls: Any,
    allow_missing_test_files: bool,
) -> Any:
    context = _operation_set_context(
        global_config,
        config_loader_cls=config_loader_cls,
    )
    return load_operation_set(
        operation_set,
        context=context,
        allow_missing_test_files=allow_missing_test_files,
    )


def _set_requires_mutation(op_set: Any) -> bool:
    if op_set.kind in {"install", "update"}:
        return True
    assert op_set.test is not None
    return bool(op_set.test.install or op_set.test.update)


def _set_sections(op_set: Any) -> list[tuple[str, Any]]:
    if op_set.kind == "install":
        return [("install", op_set.install)]
    if op_set.kind == "update":
        return [("update", op_set.update)]
    return [("test", op_set.test)]


def _set_label(op_set: Any) -> str:
    return str(op_set.name or op_set.requested_value)


def _print_set_inspection_text(inspection: dict[str, Any]) -> None:
    print(f"Set: {inspection['reference']}")
    print(f"Kind: {inspection['kind']}")
    print(f"Path: {inspection['path']}")
    print(f"Resolution: {inspection.get('resolution_source') or '-'}")

    addons_by_role = inspection.get("addons_by_role", {})
    if addons_by_role:
        for role, addons in addons_by_role.items():
            print("")
            print(f"{role} ({len(addons)}):")
            for addon in addons:
                print(f"  {addon}")

    print("")
    print("Validation:")
    print(f"  addons_path: {inspection.get('addons_path_status')}")
    missing = inspection.get("missing_addons", [])
    print(f"  missing addons: {', '.join(missing) if missing else '-'}")

    test_files = inspection.get("test_files", [])
    if test_files:
        print("  test files:")
        for item in test_files:
            suffix = "ok" if item.get("exists") else "missing"
            print(f"    {item['input']} ({suffix})")


def set_apply_command(
    ctx: typer.Context,
    *,
    operation_set: str,
    allow_mutation: bool,
    allow_missing_test_files: bool,
    include_command: bool,
    include_stdout: bool,
    apply_policy: dict[str, Any] | None = None,
    config_loader_cls: Any,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    confirmation_required_error_fn: Any,
    print_command_error_result_fn: Any,
) -> None:
    """Execute an operation set by its declared kind."""
    import time as _time

    if apply_policy is None:
        apply_policy = {}

    global_config, env_config = resolve_command_env_config_fn(ctx)
    suppress_output = global_config.format == OutputFormat.JSON

    started_at = _time.time()
    try:
        op_set = _load_runtime_operation_set(
            operation_set,
            global_config=global_config,
            config_loader_cls=config_loader_cls,
            allow_missing_test_files=allow_missing_test_files,
        )
    except ConfigError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from None

    try:
        validate_operation_set_addons(op_set, addons_path=env_config["addons_path"])
    except ConfigError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from None

    if _set_requires_mutation(op_set):
        require_cli_runtime_db_mutation_fn(
            global_config=global_config,
            env_config=env_config,
            allow_mutation=allow_mutation,
            operation=f"operation_set_{op_set.kind}",
            action=f"operation set {op_set.kind}",
            print_command_error_result_fn=print_command_error_result_fn,
            confirmation_required_error_fn=confirmation_required_error_fn,
        )

    odoo_operations = build_odoo_operations_fn(global_config)

    if not suppress_output:
        print_info(f"Applying operation set: {_set_label(op_set)} ({op_set.path})")

    results, failures = _run_sections(
        _set_sections(op_set),
        odoo_operations,
        global_config,
        suppress_output,
        include_command,
        include_stdout,
        policy=apply_policy,
    )

    aggregate = build_operation_set_result(
        op_set,
        results=results,
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
        payload["read_only"] = not _set_requires_mutation(op_set)
        payload["safety_level"] = (
            SAFE_READ_ONLY
            if not _set_requires_mutation(op_set)
            else CONTROLLED_RUNTIME_MUTATION
        )
        print(json.dumps(payload))
    else:
        summary = aggregate["summary"]
        if aggregate["success"]:
            print_info(
                f"Operation set succeeded: "
                f"{summary['kind']} set, "
                f"{summary['addon_count']} addons, "
                f"{summary['executed']} executed, "
                f"{summary['failed']} failed"
            )
        else:
            print_error(
                f"Operation set failed: "
                f"{summary['kind']} set, "
                f"{summary['addon_count']} addons, "
                f"{summary['executed']} executed, "
                f"{summary['failed']} failed"
            )

    if not aggregate["success"]:
        raise typer.Exit(1)


def set_inspect_command(
    ctx: typer.Context,
    *,
    operation_set: str,
    allow_missing_test_files: bool,
    config_loader_cls: Any,
    resolve_command_env_config_fn: Any,
) -> None:
    """Inspect an operation set without mutating anything."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    try:
        op_set = _load_runtime_operation_set(
            operation_set,
            global_config=global_config,
            config_loader_cls=config_loader_cls,
            allow_missing_test_files=allow_missing_test_files,
        )
    except ConfigError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from None

    inspection = inspect_operation_set(op_set, addons_path=env_config["addons_path"])
    inspection["operation"] = "operation_set_inspect"

    if global_config.format == OutputFormat.JSON:
        payload = build_json_payload(
            "operation_set_inspection",
            inspection,
            success=True,
            flatten_data=True,
        )
        payload["read_only"] = True
        payload["safety_level"] = SAFE_READ_ONLY
        print(json.dumps(payload))
        return

    _print_set_inspection_text(inspection)


def set_list_command(
    ctx: typer.Context,
    *,
    config_loader_cls: Any,
    resolve_command_global_config_fn: Any,
) -> None:
    """List discoverable operation sets from the active lookup locations."""
    global_config = resolve_command_global_config_fn(ctx)
    context = _operation_set_context(global_config, config_loader_cls=config_loader_cls)
    results = list_operation_sets(context=context)

    data = {
        "operation": "operation_set_list",
        "sets": [
            {
                "reference": item.reference,
                "path": str(item.path),
                "source": item.source,
            }
            for item in results
        ],
    }

    if global_config.format == OutputFormat.JSON:
        payload = build_json_payload(
            "operation_set_list",
            data,
            success=True,
            flatten_data=True,
        )
        payload["read_only"] = True
        payload["safety_level"] = SAFE_READ_ONLY
        print(json.dumps(payload))
        return

    for item in results:
        print(f"{item.reference}\t{item.source}\t{item.path}")
