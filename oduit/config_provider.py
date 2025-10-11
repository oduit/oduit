# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Configuration provider abstraction for oduit.
Provides a clean interface for accessing configuration values with support
for both legacy flat format and new sectioned format.
"""

from typing import Any

from .exceptions import ConfigError


class ConfigProvider:
    """Abstraction layer for configuration access with sectioned support

    Supports both:
    1. Legacy flat format (all keys at root level)
    2. New sectioned format with separate 'binaries' and 'odoo_params' sections
    """

    def __init__(self, config: dict[str, Any]):
        """Initialize ConfigProvider with configuration data.

        Args:
            config: Configuration dictionary, can be either:
                    - Flat format: {"python_bin": "python3", "db_name": "test", ...}
                    - Sectioned format: {"binaries": {...}, "odoo_params": {...}}
                    - Mixed format: some keys at root level, some in sections
        """
        self._raw_config = config
        self._binaries: dict[str, Any] = {}
        self._odoo_params: dict[str, Any] = {}
        self._other_config: dict[str, Any] = {}

        self._parse_config()

    def _parse_config(self) -> None:
        """Parse configuration into separate sections based on key types."""
        # Define which keys belong to which section
        binary_keys = {"python_bin", "odoo_bin", "coverage_bin"}

        # Check if using new sectioned format
        if "binaries" in self._raw_config or "odoo_params" in self._raw_config:
            # New sectioned format
            if "binaries" in self._raw_config and isinstance(
                self._raw_config["binaries"], dict
            ):
                self._binaries.update(self._raw_config["binaries"])

            if "odoo_params" in self._raw_config and isinstance(
                self._raw_config["odoo_params"], dict
            ):
                self._odoo_params.update(self._raw_config["odoo_params"])

            # Handle any other top-level keys
            for key, value in self._raw_config.items():
                if key not in ("binaries", "odoo_params"):
                    if key in binary_keys:
                        self._binaries[key] = value
                    else:
                        self._odoo_params[key] = value
        else:
            # Legacy flat format - categorize keys
            for key, value in self._raw_config.items():
                if key in binary_keys:
                    self._binaries[key] = value
                else:
                    self._odoo_params[key] = value

    def get_required(self, key: str) -> str:
        """Get a required configuration value from any section"""
        value = self.get_optional(key)
        if not value:
            raise ConfigError(f"Missing required configuration: {key}")
        return str(value)

    def get_optional(self, key: str, default: Any = None) -> Any:
        """Get an optional configuration value from any section with default"""
        # Check binaries section first
        if key in self._binaries:
            return self._binaries[key]

        # Check odoo_params section
        if key in self._odoo_params:
            return self._odoo_params[key]

        # Check other config
        if key in self._other_config:
            return self._other_config[key]

        return default

    def get_binaries_config(self) -> dict[str, Any]:
        """Get all binary-related configuration"""
        return self._binaries.copy()

    def get_odoo_params_config(self) -> dict[str, Any]:
        """Get all Odoo parameter configuration"""
        return self._odoo_params.copy()

    def get_odoo_params_list(
        self, skip_keys: list | None = None, replace_underscore: bool = True
    ) -> list[str]:
        """Get Odoo parameters as a list of command line arguments.

        Converts the odoo_params configuration into a list format suitable
        for passing directly to Odoo's parse_config method, e.g.:
        ["--database=test", "--addons-path=/path/to/addons", "--http-port=8069"]

        This method properly maps parameter names to match Odoo's expected
        command-line option names as defined in odoo/tools/config.py.

        Args:
            skip_keys: List of keys to skip when building the parameter list

        Returns:
            List of formatted command line arguments compatible with
            odoo.tools.config.parse_config()
        """
        key_mappings = {
            "db_name": "database",
            "addons_path": "addons-path",
            "upgrade_path": "upgrade-path",
            "pre_upgrade_scripts": "pre-upgrade-scripts",
            "server_wide_modules": "load",
            "data_dir": "data-dir",
            "http_interface": "http-interface",
            "http_port": "http-port",
            "longpolling_port": "longpolling-port",
            "gevent_port": "gevent-port",
            "http_enable": "http-enable",
            "proxy_mode": "proxy-mode",
            "x_sendfile": "x-sendfile",
            "dbfilter": "db-filter",
            "test_file": "test-file",
            "test_enable": "test-enable",
            "test_tags": "test-tags",
            "log_handler": "log-handler",
            "log_web": "log-web",
            "log_sql": "log-sql",
            "log_db": "log-db",
            "log_db_level": "log-db-level",
            "log_level": "log-level",
            "email_from": "email-from",
            "from_filter": "from-filter",
            "smtp_server": "smtp",
            "smtp_port": "smtp-port",
            "smtp_ssl": "smtp-ssl",
            "smtp_user": "smtp-user",
            "smtp_password": "smtp-password",
            "smtp_ssl_certificate_filename": "smtp-ssl-certificate-filename",
            "smtp_ssl_private_key_filename": "smtp-ssl-private-key-filename",
            "db_template": "db-template",
            "load_language": "load-language",
            "translate_out": "i18n-export",
            "translate_in": "i18n-import",
            "overwrite_existing_translations": "i18n-overwrite",
            "translate_modules": "modules",
            "list_db": "database-list",
            "no_http": "no-http",
            "db_user": "db_user",
            "db_host": "db_host",
            "db_port": "db_port",
            "db_password": "db_password",
        }

        params_list = []

        for key, value in self._odoo_params.items():
            if skip_keys and key in skip_keys:
                continue

            if key in key_mappings:
                param_name = key_mappings[key]
            elif replace_underscore:
                param_name = key.replace("_", "-")
            else:
                param_name = key

            if isinstance(value, bool):
                if value:
                    params_list.append(f"--{param_name}")
            elif value is not None and str(value).strip():
                params_list.append(f"--{param_name}={value}")

        return params_list

    def get_full_config(self) -> dict[str, Any]:
        """Get the complete flattened configuration for backward compatibility"""
        result = {}
        result.update(self._binaries)
        result.update(self._odoo_params)
        result.update(self._other_config)
        return result

    def validate_keys(self, required_keys: list[str], command_name: str) -> None:
        """Validate that all required keys exist and have non-empty values"""
        missing_keys = []

        for key in required_keys:
            value = self.get_optional(key)
            # Consider None, empty string, or whitespace-only strings as missing
            if value is None or (isinstance(value, str) and not value.strip()):
                missing_keys.append(key)

        if missing_keys:
            missing_str = ", ".join(missing_keys)
            raise ConfigError(
                f"Missing required configuration for {command_name}: {missing_str}. "
                f"Please check your configuration file."
            )

    def to_sectioned_dict(self) -> dict[str, Any]:
        """Export configuration in sectioned format.

        Returns:
            Dictionary with 'binaries' and 'odoo_params' sections
        """
        result = {}

        if self._binaries:
            result["binaries"] = self._binaries.copy()

        if self._odoo_params:
            result["odoo_params"] = self._odoo_params.copy()

        # Add any other top-level keys
        if self._other_config:
            result.update(self._other_config)

        return result
