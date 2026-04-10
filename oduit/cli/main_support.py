"""Helpers for the root Typer callback behavior."""

from typing import Any

import typer


def handle_no_subcommand(
    *,
    ctx: typer.Context,
    config_loader_cls: Any,
    print_error_fn: Any,
) -> None:
    """Render root fallback output when no subcommand was invoked."""
    if ctx.invoked_subcommand:
        return

    config_loader = config_loader_cls()
    has_local = config_loader.has_local_config()

    if has_local:
        print("Available commands:")
        print("  init ENV           Initialize new environment")
        print("  run                Run Odoo server")
        print("  shell              Start Odoo shell")
        print("  install MODULE     Install a module")
        print("  update MODULE      Update a module")
        print("  test               Run tests")
        print("  create-db          Create database")
        print("  list-db            List databases")
        print("  list-env           List available environments")
        print("  doctor             Diagnose environment issues")
        print("  create-addon NAME  Create new addon")
        print("  list-addons        List available addons")
        print("  print-manifest NAME   Print addon manifest information")
        print("  list-depends MODULES   List direct dependencies for installation")
        print("  install-order MODULES Dependency-resolved install order")
        print("  list-codepends MODULE  List reverse dependencies of a module")
        print("  impact-of-update MODULE  Addons affected by an update")
        print("  list-missing MODULES   Find missing dependencies")
        print("  list-duplicates     List duplicate addon names")
        print("  export-lang MODULE Export language translations")
        print("  print-config       Print environment configuration")
        print("  agent ...          Structured agent-first inspection commands")
        print("")
        print("Examples:")
        print("  oduit run                         # Run with local .oduit.toml")
        print("  oduit test --test-tags /sale      # Test sale module")
        print("  oduit update sale                 # Update sale module")
        raise typer.Exit(1) from None

    print_error_fn("No command specified and no .oduit.toml found in current directory")
    print("")
    print("Usage: oduit [--env ENV] COMMAND [arguments]")
    print("")
    print("Available commands:")
    print(
        "  init, run, shell, install, update, test, create-db, list-db, "
        "list-env, doctor"
    )
    print(
        "  create-addon, list-addons, print-manifest, list-depends, "
        "install-order, list-codepends, impact-of-update, list-missing, "
        "list-duplicates"
    )
    print("  export-lang, print-config, agent")
    print("")
    print("Examples:")
    print("  oduit --env dev run               # Run Odoo server")
    print("  oduit --env dev update sale       # Update module 'sale'")
    raise typer.Exit(1) from None
