# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import sys
from configparser import ConfigParser, SectionProxy
from typing import Any

import yaml

from .config_provider import ConfigProvider


class ConfigLoader:
    """Handles loading and managing Odoo environment configurations."""

    def __init__(self, config_dir: str | None = None):
        """Initialize ConfigLoader with optional custom config directory."""
        self.config_dir = config_dir or os.path.expanduser("~/.config/oduit")

    def _import_toml_libs(self) -> tuple[Any, Any]:
        """Import TOML libraries with fallback handling."""
        tomllib = None
        tomli_w = None

        try:
            if sys.version_info >= (3, 11):
                tomllib = __import__("tomllib")
            else:
                tomllib = __import__("tomli")
        except ImportError:
            pass

        try:
            tomli_w = __import__("tomli_w")
        except ImportError:
            pass

        return tomllib, tomli_w

    def _normalize_sectioned_config(self, raw_config: dict[str, Any]) -> dict[str, Any]:
        """Convert sectioned config format to flat format for backward compatibility.

        Supports both:
        1. Legacy flat format (direct keys at root level)
        2. New sectioned format with 'binaries' and 'odoo_params' sections

        Args:
            raw_config: Raw configuration dictionary from YAML/TOML

        Returns:
            Normalized flat configuration dictionary
        """
        # Check if config uses new sectioned format
        if "binaries" in raw_config or "odoo_params" in raw_config:
            # New sectioned format
            normalized = {}

            # Add binaries section
            if "binaries" in raw_config and isinstance(raw_config["binaries"], dict):
                normalized.update(raw_config["binaries"])

            # Add odoo_params section
            if "odoo_params" in raw_config and isinstance(
                raw_config["odoo_params"], dict
            ):
                normalized.update(raw_config["odoo_params"])

            # Add any other top-level keys (for compatibility)
            for key, value in raw_config.items():
                if key not in ("binaries", "odoo_params"):
                    normalized[key] = value

            return normalized
        else:
            # Legacy flat format - return as-is
            return raw_config

    def _get_boolean_value(self, options: dict | SectionProxy, key: str) -> bool:
        """Helper to get boolean value from both dict and SectionProxy."""
        if isinstance(options, SectionProxy):
            # SectionProxy
            result = options.getboolean(key)
            return result if result is not None else False
        else:
            # Regular dict - convert manually
            value = options[key]
            if isinstance(value, bool):
                return value
            elif isinstance(value, str):
                return value.lower() in ("true", "1", "yes", "on")
            else:
                return bool(value)

    def get_config_path(self, env_name: str, format_type: str = "yaml") -> str:
        """Returns full path to environment-specific config."""
        # If env_name is already an absolute path to a config file, use it directly
        if os.path.isabs(env_name) and os.path.isfile(env_name):
            return env_name

        # If env_name is a relative path to an existing file, use it directly
        if os.path.isfile(env_name):
            return os.path.abspath(env_name)

        # Default behavior: use config_dir
        if format_type == "toml":
            return os.path.join(self.config_dir, f"{env_name}.toml")
        elif format_type == "conf":
            return os.path.join(self.config_dir, f"{env_name}.conf")
        return os.path.join(self.config_dir, f"{env_name}.yaml")

    def _detect_config_format(self, env_name: str) -> tuple[str, str]:
        """Detect config format and return (path, format_type)."""
        # If env_name is already a path to an existing file, detect format
        # from extension
        if os.path.isfile(env_name):
            abs_path = os.path.abspath(env_name)
            if env_name.endswith(".toml"):
                return abs_path, "toml"
            elif env_name.endswith((".yaml", ".yml")):
                return abs_path, "yaml"
            elif env_name.endswith(".conf"):
                return abs_path, "conf"
            else:
                # Default to YAML for files without clear extension
                return abs_path, "yaml"

        # Default behavior: check in config_dir
        toml_path = self.get_config_path(env_name, "toml")
        yaml_path = self.get_config_path(env_name, "yaml")
        conf_path = self.get_config_path(env_name, "conf")

        if os.path.exists(toml_path):
            return toml_path, "toml"
        elif os.path.exists(yaml_path):
            return yaml_path, "yaml"
        elif os.path.exists(conf_path):
            return conf_path, "conf"
        else:
            # Default to YAML for backward compatibility
            return yaml_path, "yaml"

    def has_local_config(self) -> bool:
        """Check if a local .oduit.toml file exists in current directory."""
        return os.path.exists(".oduit.toml")

    def load_local_config(self) -> dict[str, Any]:
        """Load config from .oduit.toml in current directory."""
        config_path = ".oduit.toml"

        if not os.path.exists(config_path):
            raise FileNotFoundError(
                f"Local configuration file not found: {config_path}"
            )

        tomllib, _ = self._import_toml_libs()
        if tomllib is None:
            raise ImportError(
                "TOML support not available. Install with: pip install tomli tomli-w"
            )

        with open(config_path, "rb") as f:
            raw_config = tomllib.load(f)

        if not isinstance(raw_config, dict):
            raise ValueError(f"Invalid config format in: {config_path}")

        # Convert sectioned format to flat format for backward compatibility
        env_config = self._normalize_sectioned_config(raw_config)

        # Join addons_path list into a comma-separated string
        if isinstance(env_config.get("addons_path"), list):
            env_config["addons_path"] = ",".join(env_config["addons_path"])

        return env_config

    def _parse_database_config(
        self, options: dict | SectionProxy, oduit_config: dict[str, Any]
    ) -> None:
        """Parse database-related configuration from Odoo conf."""
        if "db_name" in options and options["db_name"] != "False":
            oduit_config["db_name"] = options["db_name"]
        if "db_user" in options:
            oduit_config["db_user"] = options["db_user"]
        if "db_password" in options:
            oduit_config["db_password"] = options["db_password"]
        if "db_host" in options:
            oduit_config["db_host"] = options["db_host"]
        if "db_port" in options:
            oduit_config["db_port"] = int(options["db_port"])
        if "db_maxconn" in options:
            oduit_config["db_maxconn"] = int(options["db_maxconn"])

    def _parse_server_config(
        self, options: dict | SectionProxy, oduit_config: dict[str, Any]
    ) -> None:
        """Parse server-related configuration from Odoo conf."""
        if "http_port" in options:
            oduit_config["http_port"] = int(options["http_port"])
        if "gevent_port" in options:
            oduit_config["gevent_port"] = int(options["gevent_port"])
        if "workers" in options:
            oduit_config["workers"] = int(options["workers"])
        if "max_cron_threads" in options:
            oduit_config["max_cron_threads"] = int(options["max_cron_threads"])
        if "proxy_mode" in options:
            oduit_config["proxy_mode"] = self._get_boolean_value(options, "proxy_mode")
        if "xmlrpc_interface" in options:
            oduit_config["xmlrpc_interface"] = options["xmlrpc_interface"]
        if "pidfile" in options and options["pidfile"]:
            oduit_config["pidfile"] = options["pidfile"]

    def _parse_limits_config(
        self, options: dict | SectionProxy, oduit_config: dict[str, Any]
    ) -> None:
        """Parse performance limits configuration from Odoo conf."""
        if "limit_memory_hard" in options:
            oduit_config["limit_memory_hard"] = int(options["limit_memory_hard"])
        if "limit_memory_soft" in options:
            oduit_config["limit_memory_soft"] = int(options["limit_memory_soft"])
        if "limit_time_cpu" in options:
            oduit_config["limit_time_cpu"] = int(options["limit_time_cpu"])
        if "limit_time_real" in options:
            oduit_config["limit_time_real"] = int(options["limit_time_real"])
        if (
            "limit_time_real_cron" in options
            and options["limit_time_real_cron"] != "-1"
        ):
            oduit_config["limit_time_real_cron"] = int(options["limit_time_real_cron"])
        if "limit_request" in options:
            oduit_config["limit_request"] = int(options["limit_request"])

    def _parse_misc_config(
        self, options: dict | SectionProxy, oduit_config: dict[str, Any]
    ) -> None:
        """Parse miscellaneous configuration from Odoo conf."""
        self._parse_paths_config(options, oduit_config)
        self._parse_logging_config(options, oduit_config)
        self._parse_security_config(options, oduit_config)
        self._parse_memory_config(options, oduit_config)
        self._parse_email_config(options, oduit_config)

    def _parse_paths_config(
        self, options: dict | SectionProxy, oduit_config: dict[str, Any]
    ) -> None:
        """Parse paths configuration from Odoo conf."""
        if "addons_path" in options:
            oduit_config["addons_path"] = options["addons_path"]
        if "data_dir" in options:
            oduit_config["data_dir"] = options["data_dir"]
        if "pg_path" in options and options["pg_path"]:
            oduit_config["pg_path"] = options["pg_path"]

    def _parse_logging_config(
        self, options: dict | SectionProxy, oduit_config: dict[str, Any]
    ) -> None:
        """Parse logging configuration from Odoo conf."""
        if "logfile" in options:
            oduit_config["logfile"] = options["logfile"]
        if "log_level" in options:
            oduit_config["log_level"] = options["log_level"]
        if "syslog" in options:
            oduit_config["syslog"] = self._get_boolean_value(options, "syslog")

    def _parse_security_config(
        self, options: dict | SectionProxy, oduit_config: dict[str, Any]
    ) -> None:
        """Parse security configuration from Odoo conf."""
        if "admin_passwd" in options:
            oduit_config["admin_passwd"] = options["admin_passwd"]
        if "list_db" in options:
            oduit_config["list_db"] = self._get_boolean_value(options, "list_db")
        if "server_wide_modules" in options:
            oduit_config["server_wide_modules"] = options["server_wide_modules"]

    def _parse_memory_config(
        self, options: dict | SectionProxy, oduit_config: dict[str, Any]
    ) -> None:
        """Parse memory and performance configuration from Odoo conf."""
        if (
            "osv_memory_count_limit" in options
            and options["osv_memory_count_limit"] != "False"
        ):
            oduit_config["osv_memory_count_limit"] = int(
                options["osv_memory_count_limit"]
            )
        if (
            "osv_memory_age_limit" in options
            and options["osv_memory_age_limit"] != "False"
        ):
            oduit_config["osv_memory_age_limit"] = int(options["osv_memory_age_limit"])
        if "csv_internal_sep" in options:
            oduit_config["csv_internal_sep"] = options["csv_internal_sep"]
        if "reportgz" in options:
            oduit_config["reportgz"] = self._get_boolean_value(options, "reportgz")

    def _parse_email_config(
        self, options: dict | SectionProxy, oduit_config: dict[str, Any]
    ) -> None:
        """Parse email configuration from Odoo conf."""
        if "email_from" in options and options["email_from"] != "False":
            oduit_config["email_from"] = options["email_from"]
        if "from_filter" in options and options["from_filter"] != "False":
            oduit_config["from_filter"] = options["from_filter"]
        if "smtp_server" in options:
            oduit_config["smtp_server"] = options["smtp_server"]
        if "smtp_port" in options:
            oduit_config["smtp_port"] = int(options["smtp_port"])
        if "smtp_ssl" in options:
            oduit_config["smtp_ssl"] = self._get_boolean_value(options, "smtp_ssl")
        if "smtp_user" in options and options["smtp_user"] != "False":
            oduit_config["smtp_user"] = options["smtp_user"]
        if "smtp_password" in options and options["smtp_password"] != "False":
            oduit_config["smtp_password"] = options["smtp_password"]

    def import_odoo_conf(
        self, conf_path: str, sectioned: bool = False
    ) -> dict[str, Any]:
        """Import Odoo configuration from .conf file and convert to oduit format.

        Args:
            conf_path: Path to the Odoo .conf file
            sectioned: If True, return configuration in sectioned format

        Returns:
            Dictionary with oduit-compatible configuration

        Raises:
            FileNotFoundError: If conf file doesn't exist
            ValueError: If conf file format is invalid
        """
        if not os.path.exists(conf_path):
            raise FileNotFoundError(f"Odoo configuration file not found: {conf_path}")

        config = ConfigParser()
        config.read(conf_path)

        if "options" not in config:
            raise ValueError(
                f"Invalid Odoo config format - missing [options] section: {conf_path}"
            )

        options = config["options"]
        oduit_config = {}

        # Set required oduit defaults that don't exist in Odoo conf files
        # Use python3 (more likely to work with virtual envs) instead of python
        oduit_config["python_bin"] = "python3"
        oduit_config["coverage_bin"] = "coverage"
        oduit_config["odoo_bin"] = "odoo"  # Default fallback

        # Parse config sections first to get addons_path
        self._parse_database_config(options, oduit_config)
        self._parse_server_config(options, oduit_config)
        self._parse_limits_config(options, oduit_config)
        self._parse_misc_config(options, oduit_config)

        # Try to find odoo-bin based on addons_path
        if "addons_path" in oduit_config:
            odoo_bin_path = self._find_odoo_bin_from_addons_path(
                oduit_config["addons_path"]
            )
            if odoo_bin_path:
                oduit_config["odoo_bin"] = odoo_bin_path

        # Add config_file reference to original conf
        oduit_config["config_file"] = conf_path

        if sectioned:
            # Convert to sectioned format using ConfigProvider
            provider = ConfigProvider(oduit_config)
            return provider.to_sectioned_dict()

        return oduit_config

    def _find_odoo_bin_from_addons_path(self, addons_path: str) -> str | None:
        """Find odoo-bin by looking in parent directories of addons paths.

        Args:
            addons_path: Comma-separated list of addon paths

        Returns:
            Path to odoo-bin if found, None otherwise
        """
        if not addons_path:
            return None

        # Split addons_path and check each directory
        addon_dirs = [path.strip() for path in addons_path.split(",")]

        for addon_dir in addon_dirs:
            if not addon_dir:
                continue

            # Convert to absolute path for consistency
            addon_dir = os.path.abspath(addon_dir)

            # Look for odoo-bin in parent directory (../odoo-bin)
            parent_dir = os.path.dirname(addon_dir)
            potential_odoo_bin = os.path.join(parent_dir, "odoo-bin")

            if os.path.exists(potential_odoo_bin) and os.access(
                potential_odoo_bin, os.X_OK
            ):
                return potential_odoo_bin

            # Also check if the addon_dir itself contains odoo-bin
            potential_odoo_bin = os.path.join(addon_dir, "odoo-bin")
            if os.path.exists(potential_odoo_bin) and os.access(
                potential_odoo_bin, os.X_OK
            ):
                return potential_odoo_bin

            # Check common subdirectories within the addon path
            for subdir in [".", "..", "../..", "../../.."]:
                check_dir = os.path.normpath(os.path.join(addon_dir, subdir))
                potential_odoo_bin = os.path.join(check_dir, "odoo-bin")
                if os.path.exists(potential_odoo_bin) and os.access(
                    potential_odoo_bin, os.X_OK
                ):
                    return potential_odoo_bin

        return None

    def load_config(self, env_name: str) -> dict[str, Any]:
        """Load config from ~/.config/oduit/<env>.(yaml|toml|conf) or from a
        direct file path"""
        config_path, format_type = self._detect_config_format(env_name)

        if not os.path.exists(config_path):
            if os.path.isfile(env_name) or os.path.isabs(env_name):
                raise FileNotFoundError(f"Configuration file not found: {env_name}")
            else:
                raise FileNotFoundError(f"Configuration file not found: {config_path}")

        if format_type == "toml":
            tomllib, _ = self._import_toml_libs()
            if tomllib is None:
                raise ImportError(
                    "TOML support not available. "
                    "Install with: pip install tomli tomli-w"
                )

            with open(config_path, "rb") as f:
                env_config = tomllib.load(f)
        elif format_type == "conf":
            env_config = self.import_odoo_conf(config_path)
        else:
            with open(config_path) as f:
                env_config = yaml.safe_load(f)

        if not isinstance(env_config, dict):
            raise ValueError(f"Invalid config format in: {config_path}")

        # Join addons_path list into a comma-separated string
        if isinstance(env_config.get("addons_path"), list):
            env_config["addons_path"] = ",".join(env_config["addons_path"])

        return env_config

    def get_available_environments(self) -> list[str]:
        """Return a list of available environment names based on config files."""
        if not os.path.exists(self.config_dir):
            return []

        env_files = [
            f
            for f in os.listdir(self.config_dir)
            if f.endswith((".yaml", ".toml", ".conf"))
        ]
        environments = [os.path.splitext(f)[0] for f in env_files]

        return sorted(list(set(environments)))

    def load_demo_config(self, sectioned: bool = False) -> dict[str, Any]:
        """Load a demo configuration for testing without a real Odoo server

        Args:
            sectioned: If True, return configuration in sectioned format

        Returns:
            Dictionary with demo configuration including demo_mode=True flag
        """
        config = {
            "python_bin": "/usr/bin/python3",
            "odoo_bin": "/demo/odoo-bin",
            "config_file": "/demo/odoo.conf",
            "addons_path": "/demo/addons,/demo/enterprise",
            "coverage_bin": "/usr/bin/coverage",  # Add missing coverage_bin
            "db_name": "demo_db",
            "db_host": "localhost",
            "db_port": 5432,
            "db_user": "odoo",
            "db_password": "demo",
            "without_demo": False,
            "log_level": "warn",  # Optional log level for testing
            "demo_mode": True,  # Key flag to enable demo behavior
            "available_modules": [
                "module_ok",  # Always succeeds
                "module_error",  # Always fails
                "module_warning",  # Succeeds with warnings
                "module_slow",  # Takes longer to process
                "test_module_pass",  # All tests pass
                "test_module_one_fail",  # One test fails
                "test_module_multi_fail",  # Multiple tests fail
                "sale",
                "purchase",
                "stock",
                "account",  # Standard modules
            ],
        }

        if sectioned:
            # Convert to sectioned format using ConfigProvider
            provider = ConfigProvider(config)
            return provider.to_sectioned_dict()

        return config
