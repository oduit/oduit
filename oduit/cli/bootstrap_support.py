"""Bootstrap helpers for the Typer composition root."""

import os
from typing import Any, cast

import typer

from ..cli_types import GlobalConfig, OutputFormat
from .runtime_context import AppRuntimeContext


def resolve_config_source(
    config_loader: Any,
    env: str | None,
    env_config: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
    """Resolve where the active configuration came from."""
    config_path = None
    source = "local" if env is None else "env"

    if env is None:
        if config_loader.has_local_config():
            try:
                config_path = config_loader.get_local_config_path()
            except Exception:
                config_path = os.path.abspath(".oduit.toml")
    else:
        resolved_path = None
        try:
            resolved = config_loader.resolve_config_path(env.strip())
            if isinstance(resolved, tuple) and len(resolved) == 2:
                resolved_path = resolved[0]
        except Exception:
            resolved_path = None

        if isinstance(resolved_path, str) and os.path.exists(resolved_path):
            config_path = os.path.abspath(resolved_path)

    if env_config and env_config.get("demo_mode", False):
        source = "demo"

    return source, config_path


def create_global_config(
    *,
    env: str | None,
    json: bool,
    non_interactive: bool,
    verbose: bool,
    no_http: bool,
    odoo_series: Any,
    configure_output_fn: Any,
    config_loader_cls: Any,
    print_error_fn: Any,
    echo_fn: Any,
    resolve_config_source_fn: Any,
) -> GlobalConfig:
    """Create and validate global configuration."""
    output_format = OutputFormat.JSON if json else OutputFormat.TEXT
    configure_output_fn(
        format_type=output_format.value,
        non_interactive=True,
    )

    env_config = None
    env_name = None
    config_loader = config_loader_cls()

    if env is None:
        if config_loader.has_local_config():
            if verbose:
                echo_fn("Using local .oduit.toml configuration")
            try:
                env_config = config_loader.load_local_config()
                env_name = "local"
            except (FileNotFoundError, ImportError, ValueError) as exc:
                print_error_fn(f"[ERROR] {str(exc)}")
                raise typer.Exit(1) from exc
        else:
            print_error_fn(
                "No environment specified and no .oduit.toml found in current directory"
            )
            raise typer.Exit(1) from None
    else:
        env_name = env.strip()
        try:
            env_config = config_loader.load_config(env_name)
        except (FileNotFoundError, ImportError, ValueError) as exc:
            print_error_fn(f"[ERROR] {str(exc)}")
            raise typer.Exit(1) from exc
        except Exception as exc:
            print_error_fn(f"Error loading environment '{env_name}': {str(exc)}")
            raise typer.Exit(1) from exc

    config_source, config_path = resolve_config_source_fn(
        config_loader, env, env_config
    )

    return GlobalConfig(
        env=env,
        non_interactive=non_interactive,
        format=output_format,
        verbose=verbose,
        no_http=no_http,
        env_config=env_config,
        env_name=env_name,
        odoo_series=odoo_series,
        config_source=config_source,
        config_path=config_path,
    )


def resolve_command_global_config(
    ctx: typer.Context,
    *,
    create_global_config_fn: Any,
    print_error_fn: Any,
) -> GlobalConfig:
    """Resolve command context into a ``GlobalConfig`` instance."""
    if ctx.obj is None:
        print_error_fn("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            return cast(GlobalConfig, create_global_config_fn(**ctx.obj))
        except typer.Exit:
            raise
        except Exception as exc:
            print_error_fn(f"Failed to create global config: {exc}")
            raise typer.Exit(1) from None

    if not isinstance(ctx.obj, GlobalConfig):
        print_error_fn("No global configuration found")
        raise typer.Exit(1) from None

    return ctx.obj


def resolve_command_env_config(
    ctx: typer.Context,
    *,
    resolve_command_global_config_fn: Any,
    print_error_fn: Any,
) -> tuple[GlobalConfig, dict[str, Any]]:
    """Resolve command context and require an environment configuration."""
    global_config = resolve_command_global_config_fn(ctx)
    if global_config.env_config is None:
        print_error_fn("No environment configuration available")
        raise typer.Exit(1) from None
    return global_config, global_config.env_config


def build_odoo_operations(
    global_config: GlobalConfig,
    *,
    odoo_operations_cls: Any,
) -> Any:
    """Build an operations facade from resolved global config."""
    assert global_config.env_config is not None
    return odoo_operations_cls(global_config.env_config, verbose=global_config.verbose)


def build_doctor_report(
    global_config: GlobalConfig,
    *,
    build_doctor_report_fn: Any,
    addons_path_manager_cls: Any,
    module_manager_cls: Any,
    odoo_operations_cls: Any,
) -> dict[str, Any]:
    """Build a diagnostics report for the active configuration."""
    return cast(
        dict[str, Any],
        build_doctor_report_fn(
            global_config,
            addons_path_manager_cls=addons_path_manager_cls,
            module_manager_cls=module_manager_cls,
            odoo_operations_cls=odoo_operations_cls,
        ),
    )


def build_registration_helpers(
    *,
    create_global_config_fn: Any,
    print_error_fn: Any,
    build_doctor_report_impl_fn: Any,
    get_addons_path_manager_cls: Any,
    get_module_manager_cls: Any,
    get_odoo_operations_cls: Any,
) -> AppRuntimeContext:
    """Build classic CLI helper callables for command registration."""

    def resolve_command_global_config_fn(ctx: typer.Context) -> GlobalConfig:
        return resolve_command_global_config(
            ctx,
            create_global_config_fn=create_global_config_fn,
            print_error_fn=print_error_fn,
        )

    def resolve_command_env_config_fn(
        ctx: typer.Context,
    ) -> tuple[GlobalConfig, dict[str, Any]]:
        return resolve_command_env_config(
            ctx,
            resolve_command_global_config_fn=resolve_command_global_config_fn,
            print_error_fn=print_error_fn,
        )

    def build_odoo_operations_fn(global_config: GlobalConfig) -> Any:
        return build_odoo_operations(
            global_config,
            odoo_operations_cls=get_odoo_operations_cls(),
        )

    def build_doctor_report_fn(global_config: GlobalConfig) -> dict[str, Any]:
        return build_doctor_report(
            global_config,
            build_doctor_report_fn=build_doctor_report_impl_fn,
            addons_path_manager_cls=get_addons_path_manager_cls(),
            module_manager_cls=get_module_manager_cls(),
            odoo_operations_cls=get_odoo_operations_cls(),
        )

    return AppRuntimeContext(
        resolve_command_global_config_fn=resolve_command_global_config_fn,
        resolve_command_env_config_fn=resolve_command_env_config_fn,
        build_odoo_operations_fn=build_odoo_operations_fn,
        build_doctor_report_fn=build_doctor_report_fn,
    )
