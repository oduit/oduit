"""Helpers for `oduit init` command flow."""

import os
import shutil
from typing import Any

import typer

from ..config_loader import ConfigLoader
from ..output import print_error, print_info, print_warning


def check_environment_exists(config_loader: ConfigLoader, env_name: str) -> None:
    """Check if environment already exists and exit if it does."""
    try:
        existing_envs = config_loader.get_available_environments()
        if env_name in existing_envs:
            print_error(f"Environment '{env_name}' already exists")
            raise typer.Exit(1) from None
    except FileNotFoundError:
        pass


def detect_binaries(
    python_bin: str | None,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> tuple[str, str | None, str | None]:
    """Auto-detect binary paths if not provided."""
    if python_bin is None:
        python_bin = shutil.which("python3") or shutil.which("python")
        if python_bin is None:
            print_error("Python binary not found in PATH")
            raise typer.Exit(1) from None

    if odoo_bin is None:
        odoo_bin = shutil.which("odoo") or shutil.which("odoo-bin")
        if odoo_bin is None:
            print_warning(
                "Odoo binary not found in PATH, you may need to specify --odoo-bin"
            )

    if coverage_bin is None:
        coverage_bin = shutil.which("coverage")
        if coverage_bin is None:
            print_warning(
                "Coverage binary not found in PATH, "
                "you may need to specify --coverage-bin"
            )

    return python_bin, odoo_bin, coverage_bin


def build_initial_config(
    python_bin: str,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> dict[str, Any]:
    """Build initial flat configuration dictionary."""
    env_config: dict[str, Any] = {
        "python_bin": python_bin,
        "coverage_bin": coverage_bin,
    }

    if odoo_bin:
        env_config["odoo_bin"] = odoo_bin

    return env_config


def import_or_convert_config(
    env_config: dict[str, Any],
    from_conf: str | None,
    config_loader: ConfigLoader,
    python_bin: str,
    odoo_bin: str | None,
    coverage_bin: str | None,
) -> dict[str, Any]:
    """Import config from .conf or convert flat config to sectioned format."""
    if from_conf:
        if not os.path.exists(from_conf):
            print_error(f"Odoo configuration file not found: {from_conf}")
            raise typer.Exit(1) from None

        try:
            env_config = config_loader.import_odoo_conf(from_conf, sectioned=True)

            if "binaries" not in env_config:
                env_config["binaries"] = {}

            binaries_section = env_config.get("binaries")
            if isinstance(binaries_section, dict):
                if python_bin:
                    binaries_section["python_bin"] = python_bin
                if odoo_bin:
                    binaries_section["odoo_bin"] = odoo_bin
                if coverage_bin:
                    binaries_section["coverage_bin"] = coverage_bin

            print_info(f"Imported configuration from: {from_conf}")
        except Exception as e:
            print_error(f"Failed to import Odoo configuration: {e}")
            raise typer.Exit(1) from None
    else:
        from ..config_provider import ConfigProvider

        provider = ConfigProvider(env_config)
        env_config = provider.to_sectioned_dict()

    return env_config


def normalize_addons_path(env_config: dict[str, Any]) -> None:
    """Convert addons_path from comma-separated string to list in-place."""
    odoo_params_section = env_config.get("odoo_params")
    if isinstance(odoo_params_section, dict) and "addons_path" in odoo_params_section:
        addons_path_value = odoo_params_section["addons_path"]
        if isinstance(addons_path_value, str):
            odoo_params_section["addons_path"] = [
                p.strip() for p in addons_path_value.split(",")
            ]


def save_config_file(
    config_path: str,
    env_config: dict[str, Any],
    config_loader: ConfigLoader,
) -> None:
    """Save configuration to TOML file."""
    tomllib, tomli_w = config_loader._import_toml_libs()
    del tomllib
    if tomli_w is None:
        print_error(
            "TOML writing support not available. Install with: pip install tomli-w"
        )
        raise typer.Exit(1) from None

    os.makedirs(config_loader.config_dir, exist_ok=True)

    with open(config_path, "wb") as f:
        tomli_w.dump(env_config, f)


def display_config_summary(env_config: dict[str, Any]) -> None:
    """Display configuration summary to user."""
    print_info("\nConfiguration summary:")

    binaries = env_config.get("binaries")
    if isinstance(binaries, dict):
        if binaries.get("python_bin"):
            print_info(f"  python_bin: {binaries['python_bin']}")
        if binaries.get("odoo_bin"):
            print_info(f"  odoo_bin: {binaries['odoo_bin']}")
        if binaries.get("coverage_bin"):
            print_info(f"  coverage_bin: {binaries['coverage_bin']}")

    params = env_config.get("odoo_params")
    if isinstance(params, dict):
        if params.get("db_name"):
            print_info(f"  db_name: {params['db_name']}")
        if params.get("addons_path"):
            addons = params["addons_path"]
            if isinstance(addons, list):
                print_info(f"  addons_path: {', '.join(addons)}")
            else:
                print_info(f"  addons_path: {addons}")


def init_env_command(
    *,
    env_name: str,
    from_conf: str | None,
    python_bin: str | None,
    odoo_bin: str | None,
    coverage_bin: str | None,
    config_loader_cls: type[ConfigLoader] = ConfigLoader,
    check_environment_exists_fn: Any = check_environment_exists,
    detect_binaries_fn: Any = detect_binaries,
    build_initial_config_fn: Any = build_initial_config,
    import_or_convert_config_fn: Any = import_or_convert_config,
    normalize_addons_path_fn: Any = normalize_addons_path,
    save_config_file_fn: Any = save_config_file,
    display_config_summary_fn: Any = display_config_summary,
) -> None:
    """Initialize a new oduit environment configuration."""
    config_loader = config_loader_cls()
    check_environment_exists_fn(config_loader, env_name)

    python_bin, odoo_bin, coverage_bin = detect_binaries_fn(
        python_bin, odoo_bin, coverage_bin
    )
    env_config = build_initial_config_fn(python_bin, odoo_bin, coverage_bin)
    env_config = import_or_convert_config_fn(
        env_config,
        from_conf,
        config_loader,
        python_bin,
        odoo_bin,
        coverage_bin,
    )
    normalize_addons_path_fn(env_config)

    config_path = config_loader.get_config_path(env_name, "toml")
    try:
        save_config_file_fn(config_path, env_config, config_loader)
        print_info(f"Environment '{env_name}' created successfully")
        print_info(f"Configuration saved to: {config_path}")
        display_config_summary_fn(env_config)
    except Exception as exc:
        print_error(f"Failed to save configuration: {exc}")
        raise typer.Exit(1) from None
