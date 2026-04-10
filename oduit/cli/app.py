"""Typer app objects and CLI entrypoint."""

import typer

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
    no_args_is_help=False,
)

agent_app = typer.Typer(help="Agent-first structured inspection and planning commands")
app.add_typer(agent_app, name="agent")


def cli_main() -> None:
    """Entry point for the CLI application."""
    app()
