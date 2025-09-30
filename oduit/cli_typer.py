# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""New Typer-based CLI implementation for oduit."""

import functools
import os
import sys

import typer

from .cli_types import (
    AddonListType,
    AddonTemplate,
    GlobalConfig,
    OutputFormat,
    ShellInterface,
)
from .config_loader import has_local_config, load_config, load_local_config
from .module_manager import ModuleManager
from .odoo_operations import OdooOperations
from .output import configure_output, print_error, print_info, print_warning
from .utils import output_result_to_json, validate_addon_name

# Module-level constants for typer.Option defaults
FORMAT_OPTION = typer.Option(
    OutputFormat.TEXT,
    "--format",
    help="Output format",
)

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


def create_global_config(
    env: str | None = None,
    format: OutputFormat = OutputFormat.TEXT,
    verbose: bool = False,
    no_http: bool = False,
) -> GlobalConfig:
    """Create and validate global configuration."""

    # Configure output based on arguments
    configure_output(
        format_type=format.value if isinstance(format, OutputFormat) else format,
        non_interactive=True,
    )

    # Handle environment and config loading
    env_config = None
    env_name = None

    if env is None:
        if has_local_config():
            if verbose:
                typer.echo("Using local .oduit.toml configuration")
            try:
                env_config = load_local_config()
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
            env_config = load_config(env_name)
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
    )


def with_config(func):
    """Decorator to inject global configuration into command functions."""

    @functools.wraps(func)
    def wrapper(ctx: typer.Context):
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
    format: OutputFormat = FORMAT_OPTION,
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
):
    """Odoo CLI tool for starting odoo-bin and running tasks."""

    # Store config info in context for subcommands
    ctx.obj = {
        "env": env,
        "format": format,
        "verbose": verbose,
        "no_http": no_http,
    }
    if len(sys.argv) == 1:
        # Check if there's a local config file
        print_error("Usage: oduit [--env ENV] [command] [arguments]")
        print_error(
            "No environment specified and no .oduit.toml found in current directory"
        )
        print_error("Examples:")
        print_error("  oduit --env dev                   # Interactive mode with env")
        print_error("  oduit --env dev run               # Run Odoo server")
        print_error("  oduit --env dev update sale      # Update module 'sale'")
        raise typer.Exit(1) from None


@app.command()
def run(ctx: typer.Context):
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
):
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
    language: str | None = typer.Option(None, "--language"),
    i18n_overwrite: bool = typer.Option(
        False, "--i18n-overwrite", help="Overwrite existing translations during update"
    ),
 
    max_cron_threads: int | None = typer.Option(
        None,
        "--max-cron-threads",
        help="Set maximum cron threads for Odoo server",
    ),
):
    """Install module."""
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
        i18n_overwrite=i18n_overwrite,
    )

    # Optional JSON output
    if global_config.format == OutputFormat.JSON:
        output_result_to_json(
            output,
            additional_fields={
                "without_demo": without_demo,
                "verbose": global_config.verbose,
            },
        )


@app.command()
def update(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to update"),
    without_demo: str | None = typer.Option(
        None, "--without-demo", help="Update without demo data"
    ),
    language: str | None = typer.Option(None, "--language"),
    i18n_overwrite: bool = typer.Option(
        False, "--i18n-overwrite", help="Overwrite existing translations during update"
    ),
    max_cron_threads: int | None = typer.Option(
        None,
        "--max-cron-threads",
        help="Set maximum cron threads for Odoo server",
    ),
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Suppress INFO logs at startup for cleaner output",
    ),

):
    """Update module."""
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
    )
    if compact and result:
        print_info(str(result))


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
):
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

    odoo_operations.run_tests(
        None,  # No module argument needed anymore
        stop_on_error=stop_on_error,
        update=update,
        install=install,
        coverage=coverage,
        test_file=test_file,
        test_tags=test_tags,
        compact=compact,
    )


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
):
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
    print_warning(f"This will create a new database named '{db_name}'.")
    message = "Are you sure you want to create a new database?"
    confirmation = input(f"{message} (y/N): ").strip().lower()
    if confirmation == "y":
        odoo_operations = OdooOperations(
            global_config.env_config, verbose=global_config.verbose
        )
        odoo_operations.create_db(create_role=create_role, alter_role=alter_role)
    else:
        print_info("Database creation cancelled.")


@app.command("print-config")
def print_config_cmd(ctx: typer.Context):
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
):
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
):
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

    # Basic implementation using ModuleManager
    module_manager = ModuleManager(global_config.env_config["addons_path"])
    addons = module_manager.find_module_dirs()

    if type == AddonListType.ALL:
        print_info(f"Available addons ({len(addons)} found):")
        for addon in sorted(addons):
            print_info(f"  - {addon}")
    else:
        print_warning(f"Filtering by type '{type.value}' not yet implemented")
        print_info(f"All available addons ({len(addons)} found):")
        for addon in sorted(addons):
            print_info(f"  - {addon}")


@app.command("export-lang")
def export_lang(
    ctx: typer.Context,
    module: str = typer.Argument(help="Module to export"),
    language: str | None = typer.Option(
        None, "--language", "-l", help="Language to export"
    ),
):
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
    # Ensure language is a string
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
    )


def cli_main():
    """Entry point for the CLI application."""
    app()


if __name__ == "__main__":
    cli_main()
