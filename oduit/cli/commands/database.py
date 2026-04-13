"""Database and configuration command implementations."""

import json
from typing import Any

import typer

from ...cli_types import OutputFormat
from ...config_loader import ConfigLoader
from ...output import print_error, print_info, print_warning
from ...utils import output_result_to_json


def create_db_command(
    ctx: typer.Context,
    *,
    create_role: bool,
    alter_role: bool,
    with_sudo: bool,
    drop: bool,
    non_interactive: bool,
    db_user: str | None,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
    require_cli_runtime_db_mutation_fn: Any,
    print_command_error_result_fn: Any,
    confirmation_required_error_fn: Any,
) -> None:
    """Create the configured database."""
    global_config, env_config = resolve_command_env_config_fn(ctx)
    require_cli_runtime_db_mutation_fn(
        global_config=global_config,
        env_config=env_config,
        allow_mutation=True,
        operation="create_db",
        action="database creation",
        print_command_error_result_fn=print_command_error_result_fn,
        confirmation_required_error_fn=confirmation_required_error_fn,
    )
    db_name = env_config.get("db_name", "Unknown")
    effective_non_interactive = non_interactive or global_config.non_interactive
    odoo_operations = build_odoo_operations_fn(global_config)

    exists_result = odoo_operations.db_exists(
        with_sudo=with_sudo,
        suppress_output=True,
        db_user=db_user,
    )
    db_exists = exists_result.get("exists", False)

    if db_exists:
        if drop:
            confirmation = ""
            if effective_non_interactive:
                confirmation_required_error_fn(
                    global_config,
                    "create_db",
                    f"Database '{db_name}' already exists and dropping it "
                    "requires confirmation.",
                    remediation=[
                        "Re-run without `--non-interactive` to confirm the drop.",
                        "Or remove `--drop` if the existing database should be kept.",
                    ],
                )
            else:
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
                "Use --drop flag to drop it first."
            )
            raise typer.Exit(1) from None

    confirmation = ""
    if not db_exists:
        if effective_non_interactive:
            confirmation_required_error_fn(
                global_config,
                "create_db",
                f"Creating database '{db_name}' requires confirmation in "
                "non-interactive mode.",
                remediation=[
                    "Re-run without `--non-interactive` to confirm database creation.",
                ],
            )
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


def list_db_command(
    ctx: typer.Context,
    *,
    with_sudo: bool,
    db_user: str | None,
    include_command: bool,
    include_stdout: bool,
    resolve_command_env_config_fn: Any,
    build_odoo_operations_fn: Any,
) -> None:
    """List databases."""
    global_config, _ = resolve_command_env_config_fn(ctx)
    odoo_operations = build_odoo_operations_fn(global_config)
    result = odoo_operations.list_db(
        with_sudo=with_sudo,
        db_user=db_user,
    )

    if global_config.format == OutputFormat.JSON:
        exclude_fields = ["command", "stdout"]
        if include_command:
            exclude_fields.remove("command")
        if include_stdout:
            exclude_fields.remove("stdout")
        result_json = output_result_to_json(
            result,
            additional_fields={},
            exclude_fields=exclude_fields,
        )
        print(json.dumps(result_json))
        return

    if not result.get("success"):
        raise typer.Exit(1)


def list_env_command(
    *,
    config_loader_cls: type[ConfigLoader] = ConfigLoader,
) -> None:
    """List available configured environments."""
    from rich.console import Console
    from rich.table import Table

    try:
        environments = config_loader_cls().get_available_environments()
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
    except Exception as exc:
        print_error(f"Failed to list environments: {exc}")
        raise typer.Exit(1) from None


def print_config_command(
    ctx: typer.Context,
    *,
    resolve_command_env_config_fn: Any,
) -> None:
    """Print the resolved environment configuration."""
    from rich.console import Console
    from rich.table import Table

    global_config, env_config = resolve_command_env_config_fn(ctx)
    if global_config.format == OutputFormat.JSON:
        output_data = output_result_to_json(
            {
                "success": True,
                "operation": "print_config",
                "environment": global_config.env_name,
                "config": env_config,
            }
        )
        print(json.dumps(output_data))
        return

    console = Console()
    table = Table(
        title=f"Environment Configuration: {global_config.env_name}",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Setting", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    for key, value in sorted(env_config.items()):
        if isinstance(value, list):
            formatted_value = "\n".join(f"• {item}" for item in value)
            table.add_row(key, formatted_value)
        elif isinstance(value, str) and key == "addons_path" and "," in value:
            paths = [path.strip() for path in value.split(",")]
            formatted_value = "\n".join(f"• {item}" for item in paths)
            table.add_row(key, formatted_value)
        else:
            table.add_row(key, str(value))

    console.print(table)
