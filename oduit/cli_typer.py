# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""New Typer-based CLI implementation for oduit."""

import functools
import json
import os
from typing import Any

import typer
from manifestoo_core.odoo_series import OdooSeries

from .cli_types import (
    AddonListType,
    AddonTemplate,
    DevFeature,
    GlobalConfig,
    LogLevel,
    OutputFormat,
    ShellInterface,
)
from .config_loader import ConfigLoader
from .module_manager import ModuleManager
from .odoo_operations import OdooOperations
from .output import configure_output, print_error, print_info, print_warning
from .utils import format_dependency_tree, output_result_to_json, validate_addon_name

SHELL_INTERFACE_OPTION = typer.Option(
    "python",
    "--shell-interface",
    help="Shell interface to use (overrides config setting)",
)

ADDON_TEMPLATE_OPTION = typer.Option(
    AddonTemplate.BASIC, "--template", help="Addon template to use"
)

ADDON_LIST_TYPE_OPTION = typer.Option(
    AddonListType.ALL, "--type", help="Type of addons to list"
)

LOG_LEVEL_OPTION = typer.Option(
    None,
    "--log-level",
    "-l",
    help="Set Odoo log level",
)

LANGUAGE_OPTION = typer.Option(
    None,
    "--language",
    "--lang",
    help="Set language (e.g., 'de_DE', 'en_US')",
)


DEV_OPTION = typer.Option(
    None,
    "--dev",
    "-d",
    help=(
        "Comma-separated list of dev features (e.g., 'all', 'xml', 'reload,qweb'). "
        "Available: all, xml, reload, qweb, ipdb, pdb, pudb, werkzeug. "
        "For development only - do not use in production."
    ),
)

ODOO_SERIES_OPTION = typer.Option(
    None,
    "--odoo-series",
    envvar=["ODOO_VERSION", "ODOO_SERIES"],
    help="Odoo series to use, in case it is not autodetected from addons version.",
)

SORT_OPTION = typer.Option(
    "alphabetical",
    "--sort",
    help="Choice between 'alphabetical' and 'topological'. "
    "Topological sorting is useful when seeking a migration order.",
    show_default=True,
)


def create_global_config(
    env: str | None = None,
    json: bool = False,
    verbose: bool = False,
    no_http: bool = False,
    odoo_series: OdooSeries | None = None,
) -> GlobalConfig:
    """Create and validate global configuration."""

    # Configure output based on arguments
    format = OutputFormat.JSON if json else OutputFormat.TEXT
    configure_output(
        format_type=format.value,
        non_interactive=True,
    )

    # Handle environment and config loading
    env_config = None
    env_name = None
    config_loader = ConfigLoader()

    if env is None:
        if config_loader.has_local_config():
            if verbose:
                typer.echo("Using local .oduit.toml configuration")
            try:
                env_config = config_loader.load_local_config()
                env_name = "local"
            except (FileNotFoundError, ImportError, ValueError) as e:
                print_error(f"[ERROR] {str(e)}")
                raise typer.Exit(1) from e
        else:
            print_error(
                "No environment specified and no .oduit.toml found in current directory"
            )
            raise typer.Exit(1) from None
    else:
        env_name = env.strip()
        try:
            env_config = config_loader.load_config(env_name)
        except (FileNotFoundError, ImportError, ValueError) as e:
            print_error(f"[ERROR] {str(e)}")
            raise typer.Exit(1) from e
        except Exception as e:
            print_error(f"Error loading environment '{env_name}': {str(e)}")
            raise typer.Exit(1) from e

    return GlobalConfig(
        env=env,
        format=format,
        verbose=verbose,
        no_http=no_http,
        env_config=env_config,
        env_name=env_name,
        odoo_series=odoo_series,
    )


def with_config(func: Any) -> Any:
    """Decorator to inject global configuration into command functions."""

    @functools.wraps(func)
    def wrapper(ctx: typer.Context) -> Any:
        if ctx.obj is None:
            print_error("No global configuration found")
            raise typer.Exit(1) from None

        if isinstance(ctx.obj, dict):
            try:
                global_config = create_global_config(**ctx.obj)
            except typer.Exit:
                raise
            except Exception as e:
                print_error(f"Failed to create global config: {e}")
                raise typer.Exit(1) from e
        else:
            global_config = ctx.obj

        return func(global_config)

    return wrapper


# Create the main Typer app
app = typer.Typer(
    name="oduit",
    help="Odoo CLI tool for starting odoo-bin and running tasks",
    epilog="""
Examples:
  oduit --env dev run                        # Run Odoo server
  oduit --env dev shell                      # Start Odoo shell
  oduit --env dev test --test-tags /sale     # Test with module filter
  oduit run                                  # Run with local .oduit.toml
    """,
    no_args_is_help=False,  # Allow no args for interactive mode
)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    env: str | None = typer.Option(
        None,
        "--env",
        "-e",
        help=(
            "Environment to use (e.g. prod, test). "
            "If not provided, looks for .oduit.toml in current directory"
        ),
    ),
    json: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output in JSON format",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show verbose output including configuration and command details",
    ),
    no_http: bool = typer.Option(
        False,
        "--no-http",
        help="Add --no-http flag to all odoo-bin commands",
    ),
    odoo_series: OdooSeries | None = ODOO_SERIES_OPTION,
) -> None:
    """Odoo CLI tool for starting odoo-bin and running tasks."""

    # Store config info in context for subcommands
    ctx.obj = {
        "env": env,
        "json": json,
        "verbose": verbose,
        "no_http": no_http,
        "odoo_series": odoo_series,
    }
    if not ctx.invoked_subcommand:
        config_loader = ConfigLoader()
        has_local = config_loader.has_local_config()

        if has_local:
            print("Available commands:")
            print("  run                Run Odoo server")
            print("  shell              Start Odoo shell")
            print("  install MODULE     Install a module")
            print("  update MODULE      Update a module")
            print("  test               Run tests")
            print("  create-db          Create database")
            print("  list-db            List databases")
            print("  list-env           List available environments")
            print("  create-addon NAME  Create new addon")
            print("  list-addons        List available addons")
            print("  list-depends MODULES   List direct dependencies for installation")
            print("  list-codepends MODULE  List codependencies of a module")
            print("  list-missing MODULES   Find missing dependencies")
            print("  export-lang MODULE Export language translations")
            print("  print-config       Print environment configuration")
            print("")
            print("Examples:")
            print("  oduit run                         # Run with local .oduit.toml")
            print("  oduit test --test-tags /sale      # Test sale module")
            print("  oduit update sale                 # Update sale module")
        else:
            print_error(
                "No command specified and no .oduit.toml found in current directory"
            )
            print("")
            print("Usage: oduit [--env ENV] COMMAND [arguments]")
            print("")
            print("Available commands:")
            print("  run, shell, install, update, test, create-db, list-db, list-env")
            print(
                "  create-addon, list-addons, list-depends, list-codepends, "
                "list-missing"
            )
            print("  export-lang, print-config")
            print("")
            print("Examples:")
            print("  oduit --env dev run               # Run Odoo server")
            print("  oduit --env dev update sale       # Update module 'sale'")
        raise typer.Exit(1) from None


@app.command()
def run(
    ctx: typer.Context,
    dev: DevFeature | None = DEV_OPTION,
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    stop_after_init: bool = typer.Option(
        False,
        "--stop-after-init",
        "-s",
        help="Stop the server after initialization",
    ),
) -> None:
    """Run Odoo server."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )
    odoo_operations.run_odoo(
        no_http=global_config.no_http,
        dev=dev,
        log_level=log_level.value if log_level else None,
        stop_after_init=stop_after_init,
    )


@app.command()
def shell(
    ctx: typer.Context,
    shell_interface: ShellInterface | None = SHELL_INTERFACE_OPTION,
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Suppress INFO logs at startup for cleaner output",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Start Odoo shell."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    odoo_operations.run_shell(
        shell_interface=shell_interface.value if shell_interface else None,
        compact=compact,
        log_level=log_level.value if log_level else None,
    )


@app.command()
def install(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to install"),
    without_demo: str | None = typer.Option(
        None, "--without-demo", help="Install without demo data"
    ),
    with_demo: bool = typer.Option(
        False, "--with-demo", help="Install with demo data (overrides config)"
    ),
    language: str | None = LANGUAGE_OPTION,
    max_cron_threads: int | None = typer.Option(
        None,
        "--max-cron-threads",
        help="Set maximum cron threads for Odoo server",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    compact: bool = typer.Option(
        False, "--compact", help="Suppress INFO logs at startup for cleaner output"
    ),
    include_command: bool = typer.Option(
        False, "--include-command", help="Include executed command in result JSON"
    ),
    include_stdout: bool = typer.Option(
        False, "--include-stdout", help="Include stdout in result JSON"
    ),
) -> None:
    """Install module."""
    if not module:
        print_error("Module name is required for install")
        raise typer.Exit(1) from None
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

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

    # Optional JSON output
    if global_config.format == OutputFormat.JSON:
        # By default, exclude command and stdout from result
        exclude_fields = ["command", "stdout"]

        additional_fields = {
            "without_demo": without_demo,
            "verbose": global_config.verbose,
        }

        # Only include command if requested
        if include_command:
            exclude_fields.remove("command")

        # Only include stdout if requested
        if include_stdout:
            exclude_fields.remove("stdout")

        result_json = output_result_to_json(
            output, additional_fields=additional_fields, exclude_fields=exclude_fields
        )
        result_json["type"] = "result"
        print(json.dumps(result_json))

    # Exit with code 1 on failure regardless of output format
    if not output.get("success"):
        raise typer.Exit(1)


@app.command()
def update(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to update"),
    without_demo: str | None = typer.Option(
        None, "--without-demo", help="Update without demo data"
    ),
    language: str | None = LANGUAGE_OPTION,
    i18n_overwrite: bool = typer.Option(
        False, "--i18n-overwrite", help="Overwrite existing translations during update"
    ),
    max_cron_threads: int | None = typer.Option(
        None,
        "--max-cron-threads",
        help="Set maximum cron threads for Odoo server",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Suppress INFO logs at startup for cleaner output",
    ),
) -> None:
    """Update module."""
    if not module:
        print_error("Module name is required for update")
        raise typer.Exit(1) from None
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    if i18n_overwrite:
        language = language or global_config.env_config.get("language", "de_DE")
        # Ensure language is a string
        if language is None:
            language = "de_DE"

    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

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

    # Exit with code 1 on failure regardless of output format
    if not result.get("success"):
        raise typer.Exit(1)


@app.command()
def test(
    ctx: typer.Context,
    stop_on_error: bool = typer.Option(
        False,
        "--stop-on-error",
        help="Abort test run on first detected failure in output",
    ),
    install: str | None = typer.Option(
        None,
        "--install",
        help="Install specified addon before testing",
    ),
    update: str | None = typer.Option(
        None,
        "--update",
        help="Update specified addon before testing",
    ),
    coverage: str | None = typer.Option(
        None,
        "--coverage",
        help="Run coverage report for specified module after tests",
    ),
    test_file: str | None = typer.Option(
        None,
        "--test-file",
        help="Run a specific Python test file",
    ),
    test_tags: str | None = typer.Option(
        None,
        "--test-tags",
        help="Comma-separated list of specs to filter tests",
    ),
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Show only test progress dots, statistics, and result summaries",
    ),
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
    include_command: bool = typer.Option(
        False, "--include-command", help="Include executed command in result JSON"
    ),
    include_stdout: bool = typer.Option(
        False, "--include-stdout", help="Include stdout in result JSON"
    ),
) -> None:
    """Run module tests with various options.

    Examples:
      oduit test --test-tags /sale                     # Test sale
      oduit test --test-tags /sale --coverage sale     # With coverage
      oduit test --install sale --test-tags /sale      # Install & test
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

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

    # Optional JSON output
    if global_config.format == OutputFormat.JSON:
        # By default, exclude command and stdout from result
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

        # Only include command if requested
        if include_command:
            exclude_fields.remove("command")

        # Only include stdout if requested
        if include_stdout:
            exclude_fields.remove("stdout")

        result_json = output_result_to_json(
            result, additional_fields=additional_fields, exclude_fields=exclude_fields
        )
        result_json["type"] = "result"
        print(json.dumps(result_json))

    # Exit with code 1 on failure regardless of output format
    if not result.get("success"):
        raise typer.Exit(1)


@app.command("create-db")
def create_db(
    ctx: typer.Context,
    create_role: bool = typer.Option(
        False,
        "--create-role",
        help="Create DB Role",
    ),
    alter_role: bool = typer.Option(
        False,
        "--alter-role",
        help="Alter DB Role",
    ),
    with_sudo: bool = typer.Option(
        False,
        "--with-sudo",
        help="Use sudo for database creation (if required by PostgreSQL setup)",
    ),
    drop: bool = typer.Option(
        False,
        "--drop",
        help="Drop database if it exists before creating",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Run without confirmation prompt (use with caution)",
    ),
    db_user: str | None = typer.Option(
        None,
        "--db-user",
        help="Specify the database user (overrides config setting)",
    ),
) -> None:
    """Create database."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None
    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    db_name = global_config.env_config.get("db_name", "Unknown")

    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    # Check if database exists
    exists_result = odoo_operations.db_exists(
        with_sudo=with_sudo,
        suppress_output=True,
        db_user=db_user,
    )

    db_exists = exists_result.get("exists", False)

    # Handle existing database
    if db_exists:
        if drop:
            confirmation = "y"
            if not non_interactive:
                print_warning(f"Database '{db_name}' already exists.")
                message = "Do you want to drop it before creating?"
                confirmation = input(f"{message} (y/N): ").strip().lower()

            if confirmation == "y":
                print_info(f"Dropping existing database '{db_name}'...")
                drop_result = odoo_operations.drop_db(
                    with_sudo=with_sudo,
                    suppress_output=False,
                )
                if not drop_result.get("success", False):
                    print_error("Failed to drop database")
                    raise typer.Exit(1) from None
            else:
                print_info("Database drop cancelled.")
                raise typer.Exit(0) from None
        else:
            print_error(
                f"Database '{db_name}' already exists. "
                f"Use --drop flag to drop it first."
            )
            raise typer.Exit(1) from None

    # Create database
    confirmation = "y"
    if not non_interactive and not db_exists:
        print_warning(f"This will create a new database named '{db_name}'.")
        message = "Are you sure you want to create a new database?"
        confirmation = input(f"{message} (y/N): ").strip().lower()

    if confirmation == "y":
        odoo_operations.create_db(
            create_role=create_role,
            alter_role=alter_role,
            with_sudo=with_sudo,
            db_user=db_user,
        )
    else:
        print_info("Database creation cancelled.")


@app.command("list-db")
def list_db(
    ctx: typer.Context,
    with_sudo: bool = typer.Option(
        False,
        "--with-sudo/--no-sudo",
        help="Use sudo for database listing (default: False)",
    ),
    db_user: str | None = typer.Option(
        None,
        "--db-user",
        help="Specify the database user (overrides config setting)",
    ),
    include_command: bool = typer.Option(
        False, "--include-command", help="Include executed command in result JSON"
    ),
    include_stdout: bool = typer.Option(
        False, "--include-stdout", help="Include stdout in result JSON"
    ),
) -> None:
    """List all databases."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None
    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )
    result = odoo_operations.list_db(
        with_sudo=with_sudo,
        db_user=db_user,
    )

    if global_config.format == OutputFormat.JSON:
        # By default, exclude command and stdout from result
        exclude_fields = ["command", "stdout"]

        additional_fields: dict[str, Any] = {}

        # Only include command if requested
        if include_command:
            exclude_fields.remove("command")

        # Only include stdout if requested
        if include_stdout:
            exclude_fields.remove("stdout")

        result_json = output_result_to_json(
            result, additional_fields=additional_fields, exclude_fields=exclude_fields
        )
        result_json["type"] = "result"
        print(json.dumps(result_json))
    elif not result.get("success"):
        raise typer.Exit(1)


@app.command("list-env")
def list_env() -> None:
    """List available environments."""
    from rich.console import Console
    from rich.table import Table

    from oduit.config_loader import ConfigLoader

    try:
        environments = ConfigLoader().get_available_environments()
        if not environments:
            print_info("No environments found in .oduit directory")
            return

        table = Table(title="Available Environments", show_header=True)
        table.add_column("Environment", style="cyan", no_wrap=True)

        for env in environments:
            table.add_row(env)

        console = Console()
        console.print(table)
    except FileNotFoundError:
        print_error("No .oduit directory found in current directory")
        raise typer.Exit(1) from None
    except Exception as e:
        print_error(f"Failed to list environments: {e}")
        raise typer.Exit(1) from None


@app.command("print-config")
def print_config_cmd(ctx: typer.Context) -> None:
    """Print environment config."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    print_info(f"Environment: {global_config.env_name}")
    for key, value in global_config.env_config.items():
        if isinstance(value, list):
            print_info(f"{key}:")
            for item in value:
                print_info(f"  - {item}")
        else:
            print_info(f"{key}: {value}")


@app.command("create-addon")
def create_addon(
    ctx: typer.Context,
    addon_name: str = typer.Argument(help="Name of the addon to create"),
    path: str | None = typer.Option(
        None, "--path", help="Path where to create the addon"
    ),
    template: AddonTemplate = ADDON_TEMPLATE_OPTION,
) -> None:
    """Create new addon."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    if not validate_addon_name(addon_name):
        print_error(
            f"Invalid addon name '{addon_name}'. "
            f"Must be lowercase letters, numbers, underscores only."
        )
        raise typer.Exit(1) from None
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    odoo_operations.create_addon(addon_name, destination=path, template=template.value)


@app.command("list-addons")
def list_addons(
    ctx: typer.Context,
    type: AddonListType = ADDON_LIST_TYPE_OPTION,
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter addons by directory (e.g., 'myaddons')",
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    exclude_core_addons: bool = typer.Option(
        False,
        "--exclude-core-addons",
        help="Exclude Odoo Community Edition (CE) core addons from the list",
    ),
    exclude_enterprise_addons: bool = typer.Option(
        False,
        "--exclude-enterprise-addons",
        help="Exclude Odoo Enterprise Edition (EE) addons from the list",
    ),
    sorting: str = SORT_OPTION,
) -> None:
    """List available addons."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])
    addons = module_manager.find_module_dirs(filter_dir=select_dir)

    addons = [addon for addon in addons if not addon.startswith("test_")]

    if exclude_core_addons or exclude_enterprise_addons:
        from manifestoo_core.core_addons import is_core_ce_addon, is_core_ee_addon

        odoo_series = (
            global_config.odoo_series
            if global_config.odoo_series
            else module_manager.detect_odoo_series()
        )
        if odoo_series:
            filtered_addons = []
            for addon in addons:
                if exclude_core_addons and is_core_ce_addon(addon, odoo_series):
                    continue
                if exclude_enterprise_addons and is_core_ee_addon(addon, odoo_series):
                    continue
                filtered_addons.append(addon)
            addons = filtered_addons
        else:
            print_error(
                "Could not detect Odoo series. "
                "Please specify --odoo-series to use exclusion filters"
            )
            raise typer.Exit(1) from None

    try:
        sorted_addons = module_manager.sort_modules(addons, sorting)
    except ValueError as e:
        print_error(f"Sorting failed: {e}")
        raise typer.Exit(1) from None

    if separator:
        print(separator.join(sorted_addons))
    else:
        for addon in sorted_addons:
            print(addon)


def _print_dependency_tree(
    module_list: list[str],
    module_manager: ModuleManager,
    tree_depth: int | None,
    odoo_series: OdooSeries | None = None,
) -> None:
    """Print dependency tree for a list of modules."""
    if odoo_series is None:
        odoo_series = module_manager.detect_odoo_series()

    for i, module_name in enumerate(module_list):
        dep_tree = module_manager.get_dependency_tree(module_name, max_depth=tree_depth)
        lines = format_dependency_tree(
            module_name,
            dep_tree,
            module_manager,
            "",
            True,
            set(),
            odoo_series,
            is_root=True,
        )
        for module_part, version_part in lines:
            typer.echo(module_part, nl=False)
            if version_part == " ⬆":
                typer.secho(version_part, fg="bright_black")
            elif version_part:
                typer.secho(version_part, fg="bright_black")
            else:
                typer.echo("")
        if i < len(module_list) - 1:
            typer.echo()


def _print_dependency_list(
    module_list: list[str],
    module_manager: ModuleManager,
    tree_depth: int | None,
    depth: int | None,
    separator: str | None,
    source_desc: str,
    sorting: str = "alphabetical",
) -> None:
    """Print flat list of dependencies."""
    if depth is not None and depth >= 0:
        dependencies = module_manager.get_dependencies_at_depth(
            module_list, max_depth=tree_depth
        )
    else:
        dependencies = module_manager.get_direct_dependencies(*module_list)

    try:
        sorted_dependencies = module_manager.sort_modules(dependencies, sorting)
    except ValueError as e:
        print_error(f"Sorting failed: {e}")
        sorted_dependencies = dependencies

    if separator:
        if sorted_dependencies:
            print(separator.join(sorted_dependencies))
    elif sorted_dependencies:
        for dep in sorted_dependencies:
            print(f"{dep}")
    else:
        print(f"No external dependencies for {source_desc}")


@app.command("list-depends")
def list_depends(
    ctx: typer.Context,
    modules: str | None = typer.Argument(
        None, help="Comma-separated module names to check dependencies for"
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    tree: bool = typer.Option(
        False,
        "--tree",
        help="Display dependencies as a tree structure",
    ),
    depth: int | None = typer.Option(
        -1,
        "--depth",
        help="Maximum depth of dependencies to show "
        "(-1= no maximum, 0=direct only, 1=direct+their deps, etc.)",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter modules by directory (e.g., 'myaddons')",
    ),
    sorting: str = SORT_OPTION,
) -> None:
    """List direct dependencies needed to install a set of modules.

    Direct dependencies are external modules (not in the provided set) needed
    for installation. For example, if modules a, b, c depend on crm and mail,
    this will show crm and mail.

    Use --tree to show the full dependency tree with versions.
    Use --select-dir to get dependencies for all modules in a specific directory.
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    if modules is None and select_dir is None:
        print_error("Either provide module names or use --select-dir option")
        raise typer.Exit(1) from None

    if modules is not None and select_dir is not None:
        print_error("Cannot use both module names and --select-dir option")
        raise typer.Exit(1) from None

    try:
        if select_dir:
            addons = module_manager.find_module_dirs(filter_dir=select_dir)
            if not addons:
                print_error(f"No modules found in directory '{select_dir}'")
                raise typer.Exit(1) from None
            module_list = sorted(addons)
            source_desc = f"directory '{select_dir}'"
        else:
            assert modules is not None
            module_list = [m.strip() for m in modules.split(",")]
            if len(module_list) == 1:
                source_desc = f"'{modules}'"
            else:
                source_desc = f"modules [{', '.join(module_list)}]"

        tree_depth = depth + 1 if depth is not None and depth >= 0 else None

        if tree:
            _print_dependency_tree(
                module_list, module_manager, tree_depth, global_config.odoo_series
            )
        else:
            _print_dependency_list(
                module_list,
                module_manager,
                tree_depth,
                depth,
                separator,
                source_desc,
                sorting,
            )
    except ValueError as e:
        print_error(f"Error checking dependencies: {e}")
        raise typer.Exit(1) from None


@app.command("list-codepends")
def list_codepends(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to check codependencies for"),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
) -> None:
    """List codependencies for a module.

    Codependencies are modules that depend on the specified module, meaning
    changes to the specified module may impact those modules.
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    codependencies = module_manager.get_reverse_dependencies(module)

    # Include the selected module itself in the output
    all_codeps = sorted(codependencies + [module])

    if separator:
        if all_codeps:
            print(separator.join(all_codeps))
    elif all_codeps:
        for dep in all_codeps:
            print(f"{dep}")
    else:
        print_info(f"Module '{module}' has no codependencies")


@app.command("list-missing")
def list_missing(
    ctx: typer.Context,
    modules: str | None = typer.Argument(
        None, help="Comma-separated module names to check for missing dependencies"
    ),
    separator: str | None = typer.Option(
        None,
        "--separator",
        help="Separator for output (e.g., ',' for 'a,b,c')",
    ),
    select_dir: str | None = typer.Option(
        None,
        "--select-dir",
        help="Filter modules by directory (e.g., 'myaddons')",
    ),
) -> None:
    """Find missing dependencies for modules.

    This command identifies dependencies that are not available in the addons_path.
    Useful for ensuring all required modules are present before installation.

    Use --select-dir to check all modules in a specific directory.
    """
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    if modules is None and select_dir is None:
        print_error("Either provide module names or use --select-dir option")
        raise typer.Exit(1) from None

    if modules is not None and select_dir is not None:
        print_error("Cannot use both module names and --select-dir option")
        raise typer.Exit(1) from None

    try:
        if select_dir:
            module_list = module_manager.find_module_dirs(filter_dir=select_dir)
            if not module_list:
                print_error(f"No modules found in directory '{select_dir}'")
                raise typer.Exit(1) from None
        else:
            assert modules is not None
            module_list = [m.strip() for m in modules.split(",")]

        all_missing = set()
        for module in module_list:
            missing = module_manager.find_missing_dependencies(module)
            all_missing.update(missing)

        if all_missing:
            sorted_missing = sorted(all_missing)
            if separator:
                print(separator.join(sorted_missing))
            else:
                for dep in sorted_missing:
                    print(dep)
        else:
            if not separator:
                print_info("All dependencies are available")
    except ValueError as e:
        print_error(f"Error checking missing dependencies: {e}")
        raise typer.Exit(1) from None


@app.command("export-lang")
def export_lang(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to export"),
    language: str | None = LANGUAGE_OPTION,
    log_level: LogLevel | None = LOG_LEVEL_OPTION,
) -> None:
    """Export language module."""
    if ctx.obj is None:
        print_error("No global configuration found")
        raise typer.Exit(1) from None

    if isinstance(ctx.obj, dict):
        try:
            global_config = create_global_config(**ctx.obj)
        except typer.Exit:
            raise
        except Exception as e:
            print_error(f"Failed to create global config: {e}")
            raise typer.Exit(1) from None
    else:
        global_config = ctx.obj

    if global_config.env_config is None:
        print_error("No environment configuration available")
        raise typer.Exit(1) from None

    language = language or global_config.env_config.get("language", "de_DE")
    if language is None:
        language = "de_DE"

    module_manager = ModuleManager(global_config.env_config["addons_path"])

    module_path = module_manager.find_module_path(module)
    if not module_path:
        print_warning(
            f"Module '{module}' not found in addons path. Using default path."
        )
        module_path = os.path.join(
            global_config.env_config["addons_path"].split(",")[0], module
        )

    i18n_dir = os.path.join(module_path, "i18n")
    if "_" in language:
        filename = os.path.join(i18n_dir, f"{language.split('_')[0]}.po")
    else:
        filename = os.path.join(i18n_dir, f"{language}.po")

    os.makedirs(i18n_dir, exist_ok=True)
    odoo_operations = OdooOperations(
        global_config.env_config, verbose=global_config.verbose
    )

    odoo_operations.export_module_language(
        module,
        filename,
        language,
        no_http=global_config.no_http,
        log_level=log_level.value if log_level else None,
    )


def cli_main() -> None:
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    cli_main()
