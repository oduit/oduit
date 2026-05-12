"""Helpers for `oduit init` command flow."""

import os
import shutil
from pathlib import Path
from typing import Any

import typer

from ..config_loader import ConfigLoader, ImportedOdooConfDetails
from ..output import print_error, print_info, print_warning

_DEFAULT_PYTHON_BIN_VALUES = {"python", "python3"}
_DEFAULT_ODOO_BIN_VALUES = {"odoo", "odoo-bin"}
_DEFAULT_COVERAGE_BIN_VALUES = {"coverage"}
_SECRET_CONFIG_KEYS = {"db_password", "admin_passwd", "smtp_password"}


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
        "write_protect_db": False,
        "agent_write_protect_db": False,
        "needs_mutation_flag": False,
        "agent_needs_mutation_flag": False,
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
    *,
    explicit_python_bin: str | None = None,
    explicit_odoo_bin: str | None = None,
    explicit_coverage_bin: str | None = None,
    include_report: bool = False,
) -> dict[str, Any] | tuple[dict[str, Any], ImportedOdooConfDetails | None]:
    """Import config from .conf or convert flat config to sectioned format."""
    import_report: ImportedOdooConfDetails | None = None
    if from_conf:
        if not os.path.exists(from_conf):
            print_error(f"Odoo configuration file not found: {from_conf}")
            raise typer.Exit(1) from None

        try:
            import_report = config_loader.inspect_odoo_conf_import(
                from_conf, sectioned=True
            )
            if len(import_report.odoo_bin_candidates) > 1 and explicit_odoo_bin is None:
                print_error(
                    "Multiple odoo-bin candidates were detected from addons_path. "
                    "Pass --odoo-bin explicitly."
                )
                for candidate in import_report.odoo_bin_candidates:
                    print_info(f"  candidate: {candidate}")
                raise typer.Exit(1) from None

            env_config = import_report.config

            if "binaries" not in env_config:
                env_config["binaries"] = {}

            binaries_section = env_config.get("binaries")
            if isinstance(binaries_section, dict):
                binaries_section["python_bin"] = _resolve_imported_binary(
                    binaries_section.get("python_bin"),
                    explicit_value=explicit_python_bin,
                    detected_value=python_bin,
                    placeholder_values=_DEFAULT_PYTHON_BIN_VALUES,
                )
                binaries_section["odoo_bin"] = _resolve_imported_binary(
                    binaries_section.get("odoo_bin"),
                    explicit_value=explicit_odoo_bin,
                    detected_value=odoo_bin,
                    placeholder_values=_DEFAULT_ODOO_BIN_VALUES,
                )
                binaries_section["coverage_bin"] = _resolve_imported_binary(
                    binaries_section.get("coverage_bin"),
                    explicit_value=explicit_coverage_bin,
                    detected_value=coverage_bin,
                    placeholder_values=_DEFAULT_COVERAGE_BIN_VALUES,
                )

            print_info(f"Imported configuration from: {from_conf}")
        except Exception as e:
            print_error(f"Failed to import Odoo configuration: {e}")
            raise typer.Exit(1) from None
    else:
        from ..config_provider import ConfigProvider

        provider = ConfigProvider(env_config)
        env_config = provider.to_sectioned_dict()

    if include_report:
        return env_config, import_report
    return env_config


def _resolve_imported_binary(
    current_value: Any,
    *,
    explicit_value: str | None,
    detected_value: str | None,
    placeholder_values: set[str],
) -> str | None:
    """Prefer explicit values, then imported real paths, then detected fallbacks."""
    if explicit_value is not None:
        return explicit_value

    current_text = str(current_value).strip() if current_value is not None else ""
    if current_text and current_text not in placeholder_values:
        return current_text

    if detected_value is not None:
        return detected_value

    return current_text or None


def normalize_addons_path(env_config: dict[str, Any]) -> None:
    """Convert addons_path from comma-separated string to list in-place."""
    odoo_params_section = env_config.get("odoo_params")
    if isinstance(odoo_params_section, dict) and "addons_path" in odoo_params_section:
        addons_path_value = odoo_params_section["addons_path"]
        if isinstance(addons_path_value, str):
            odoo_params_section["addons_path"] = [
                p.strip() for p in addons_path_value.split(",")
            ]


def dumps_config_toml(env_config: dict[str, Any], config_loader: ConfigLoader) -> str:
    """Serialize configuration to TOML text."""
    tomllib, tomli_w = config_loader._import_toml_libs()
    del tomllib
    if tomli_w is None:
        print_error(
            "TOML writing support not available. Install with: pip install tomli-w"
        )
        raise typer.Exit(1) from None

    return tomli_w.dumps(env_config)


def resolve_init_target(
    *,
    env_name: str,
    config_loader: ConfigLoader,
    local: bool,
    output_path: Path | None,
    force: bool,
    dry_run: bool,
) -> Path | None:
    """Resolve the output target for `oduit init`."""
    if local and output_path is not None:
        print_error("Use either --local or --output, not both.")
        raise typer.Exit(1) from None

    if dry_run:
        return None

    if local:
        target = Path(".oduit.toml").resolve()
    elif output_path is not None:
        target = output_path.resolve()
    else:
        target = Path(config_loader.get_config_path(env_name, "toml")).resolve()
        try:
            existing_envs = config_loader.get_available_environments()
        except FileNotFoundError:
            existing_envs = []
        if env_name in existing_envs:
            existing_path, _ = config_loader.resolve_config_path(env_name)
            existing_target = Path(existing_path).resolve()
            if existing_target != target:
                print_error(
                    f"Environment '{env_name}' already exists at {existing_target}"
                )
                raise typer.Exit(1) from None
            if not force:
                print_error(f"Environment '{env_name}' already exists")
                print_info("Use --force to overwrite it.")
                raise typer.Exit(1) from None

    if target.exists() and not force:
        print_error(f"Configuration file already exists: {target}")
        print_info("Use --force to overwrite it.")
        raise typer.Exit(1) from None

    return target


def save_config_file(
    config_path: str | Path,
    env_config: dict[str, Any],
    config_loader: ConfigLoader,
) -> None:
    """Save configuration to TOML file."""
    target_path = Path(config_path)
    toml_text = dumps_config_toml(env_config, config_loader)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(toml_text, encoding="utf-8")


def display_config_summary(
    env_config: dict[str, Any],
    *,
    output_path: Path | None = None,
    env_name: str | None = None,
    local: bool = False,
    source_conf: str | None = None,
    import_report: ImportedOdooConfDetails | None = None,
) -> None:
    """Display configuration summary to user."""
    print_info("\nConfiguration summary:")

    if output_path is not None:
        print_info(f"  output: {output_path}")
    if source_conf:
        print_info(f"  source_conf: {source_conf}")

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
        if params.get("config_file"):
            print_info(f"  config_file: {params['config_file']}")
        for key in (
            "write_protect_db",
            "agent_write_protect_db",
            "needs_mutation_flag",
            "agent_needs_mutation_flag",
        ):
            if key in params:
                print_info(f"  {key}: {params[key]}")
        if params.get("addons_path"):
            addons = params["addons_path"]
            if isinstance(addons, list):
                print_info("  addons_path:")
                for addon_path in addons:
                    print_info(f"    - {addon_path}")
            else:
                print_info(f"  addons_path: {addons}")

    if import_report is not None:
        print_info(f"Converted {len(import_report.handled_option_keys)} known options.")
        if import_report.unknown_option_keys:
            print_warning(
                "Unconverted Odoo options will still be read from the original "
                "`odoo.conf` via `--config`: "
                + ", ".join(import_report.unknown_option_keys)
            )
            print_info(
                "Kept original config_file so Odoo can still read unconverted options."
            )

    if source_conf and _config_contains_secret_values(env_config):
        print_warning(
            "The generated TOML may contain database or SMTP credentials imported "
            "from your odoo.conf. Review it before committing."
        )

    next_steps_prefix = "oduit" if local else f"oduit --env {env_name}"
    if env_name or local:
        print_info("Next steps:")
        print_info(f"  {next_steps_prefix} print-config")
        print_info(f"  {next_steps_prefix} doctor")
        print_info(f"  {next_steps_prefix} list-addons")


def _config_contains_secret_values(env_config: dict[str, Any]) -> bool:
    """Return True when the generated config contains imported secret-like values."""
    params = env_config.get("odoo_params")
    if not isinstance(params, dict):
        return False
    for key in _SECRET_CONFIG_KEYS:
        value = params.get(key)
        if value not in (None, "", False):
            return True
    return False


def display_dry_run_warnings(
    env_config: dict[str, Any],
    *,
    source_conf: str | None = None,
    import_report: ImportedOdooConfDetails | None = None,
) -> None:
    """Emit dry-run warnings on stderr while keeping stdout pure TOML."""
    if import_report and import_report.unknown_option_keys:
        typer.echo(
            "Warning: unconverted Odoo options remain in the original "
            "`odoo.conf` and will still be read via `--config`: "
            + ", ".join(import_report.unknown_option_keys),
            err=True,
        )
    if source_conf and _config_contains_secret_values(env_config):
        typer.echo(
            "Warning: the generated TOML may contain database or SMTP credentials "
            "imported from your odoo.conf. Review it before committing.",
            err=True,
        )


def init_env_command(
    *,
    env_name: str,
    from_conf: str | None,
    local: bool,
    output_path: Path | None,
    force: bool,
    dry_run: bool,
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
    explicit_python_bin = python_bin
    explicit_odoo_bin = odoo_bin
    explicit_coverage_bin = coverage_bin

    python_bin, odoo_bin, coverage_bin = detect_binaries_fn(
        python_bin, odoo_bin, coverage_bin
    )
    env_config = build_initial_config_fn(python_bin, odoo_bin, coverage_bin)
    import_result = import_or_convert_config_fn(
        env_config,
        from_conf,
        config_loader,
        python_bin,
        odoo_bin,
        coverage_bin,
        explicit_python_bin=explicit_python_bin,
        explicit_odoo_bin=explicit_odoo_bin,
        explicit_coverage_bin=explicit_coverage_bin,
        include_report=True,
    )
    if isinstance(import_result, tuple):
        env_config, import_report = import_result
    else:
        env_config = import_result
        import_report = None
    normalize_addons_path_fn(env_config)
    target_path = resolve_init_target(
        env_name=env_name,
        config_loader=config_loader,
        local=local,
        output_path=output_path,
        force=force,
        dry_run=dry_run,
    )
    try:
        if dry_run:
            display_dry_run_warnings(
                env_config,
                source_conf=from_conf,
                import_report=import_report,
            )
            typer.echo(dumps_config_toml(env_config, config_loader), nl=False)
            return

        if target_path is None:
            raise RuntimeError("Resolved init target missing for non-dry-run save")

        save_config_file_fn(target_path, env_config, config_loader)
        print_info(f"Environment '{env_name}' created successfully")
        print_info(f"Configuration saved to: {target_path}")
        display_config_summary_fn(
            env_config,
            output_path=target_path,
            env_name=env_name,
            local=local,
            source_conf=from_conf,
            import_report=import_report,
        )
    except Exception as exc:
        print_error(f"Failed to save configuration: {exc}")
        raise typer.Exit(1) from None
