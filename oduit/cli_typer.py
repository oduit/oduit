"""Compatibility facade for the canonical Typer app in :mod:`oduit.cli.app`."""

from __future__ import annotations

from .addons_path_manager import AddonsPathManager
from .cli.app import (
    ADDON_TEMPLATE_OPTION,
    DEV_OPTION,
    EXCLUDE_FILTER_OPTION,
    INCLUDE_FILTER_OPTION,
    LANGUAGE_OPTION,
    LOG_LEVEL_OPTION,
    ODOO_SERIES_OPTION,
    SHELL_INTERFACE_OPTION,
    SORT_OPTION,
    agent_app,
    app,
    cli_main,
    create_global_config,
    main,
)
from .cli.init_env import (
    build_initial_config as _build_initial_config,
)
from .cli.init_env import (
    check_environment_exists as _check_environment_exists,
)
from .cli.init_env import detect_binaries as _detect_binaries
from .cli.init_env import display_config_summary as _display_config_summary
from .cli.init_env import import_or_convert_config as _import_or_convert_config
from .cli.init_env import normalize_addons_path as _normalize_addons_path
from .cli.init_env import save_config_file as _save_config_file
from .config_loader import ConfigLoader
from .module_manager import ModuleManager
from .odoo_operations import OdooOperations
from .output import configure_output
from .utils import validate_addon_name

__all__ = [
    "ADDON_TEMPLATE_OPTION",
    "AddonsPathManager",
    "ConfigLoader",
    "DEV_OPTION",
    "EXCLUDE_FILTER_OPTION",
    "INCLUDE_FILTER_OPTION",
    "LANGUAGE_OPTION",
    "LOG_LEVEL_OPTION",
    "ModuleManager",
    "ODOO_SERIES_OPTION",
    "OdooOperations",
    "SHELL_INTERFACE_OPTION",
    "SORT_OPTION",
    "_build_initial_config",
    "_check_environment_exists",
    "_detect_binaries",
    "_display_config_summary",
    "_import_or_convert_config",
    "_normalize_addons_path",
    "_save_config_file",
    "agent_app",
    "app",
    "cli_main",
    "configure_output",
    "create_global_config",
    "main",
    "validate_addon_name",
]


if __name__ == "__main__":
    cli_main()
