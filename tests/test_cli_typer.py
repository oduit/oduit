import oduit.cli.app as canonical_app_module
from oduit import cli_typer
from oduit.cli import init_env


def test_cli_typer_reexports_canonical_app_objects() -> None:
    assert cli_typer.app is canonical_app_module.app
    assert cli_typer.agent_app is canonical_app_module.agent_app
    assert cli_typer.cli_main is canonical_app_module.cli_main
    assert cli_typer.create_global_config is canonical_app_module.create_global_config
    assert cli_typer.main is canonical_app_module.main


def test_cli_typer_reexports_init_env_helpers() -> None:
    assert cli_typer._check_environment_exists is init_env.check_environment_exists
    assert cli_typer._detect_binaries is init_env.detect_binaries
    assert cli_typer._build_initial_config is init_env.build_initial_config
    assert cli_typer._import_or_convert_config is init_env.import_or_convert_config
    assert cli_typer._normalize_addons_path is init_env.normalize_addons_path
    assert cli_typer._save_config_file is init_env.save_config_file
    assert cli_typer._display_config_summary is init_env.display_config_summary
