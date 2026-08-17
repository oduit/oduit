# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""
New builder pattern implementation for command construction.
Provides proper separation of concerns and fluent interfaces.
"""

import logging
import os
import re
import shlex
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config_provider import ConfigProvider
from .exceptions import ConfigError
from .module_manager import ModuleManager

_logger = logging.getLogger(__name__)


def _split_module_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def extract_test_tag_modules(test_tags: str | None) -> list[str]:
    """Return module names from positive, module-specific Odoo test tags."""
    if not test_tags:
        return []
    modules: list[str] = []
    for raw_tag in test_tags.split(","):
        tag = raw_tag.strip()
        if not tag.startswith("/") or tag.startswith("-/") or len(tag) == 1:
            continue
        module = tag[1:].split(":", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z0-9_]+", module) and module not in modules:
            modules.append(module)
    return modules


def _dedupe_preserving_order(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _normalize_non_empty_values(
    values: Sequence[Any] | Any,
    *,
    value_label: str,
) -> list[str]:
    raw_values = (
        [values]
        if isinstance(values, str) or not isinstance(values, Sequence)
        else list(values)
    )
    if not raw_values:
        raise ConfigError(f"{value_label} list cannot be empty.")

    normalized: list[str] = []
    for raw_value in raw_values:
        value = str(raw_value).strip()
        if not value:
            raise ConfigError(f"{value_label} values must be non-empty.")
        if any(character.isspace() for character in value):
            raise ConfigError(
                f"{value_label} values must not contain whitespace: {value}"
            )
        normalized.append(value)

    return _dedupe_preserving_order(normalized)


def _normalize_languages(values: Sequence[Any] | Any) -> list[str]:
    return _normalize_non_empty_values(values, value_label="Language")


def _normalize_modules(values: Sequence[Any] | Any) -> list[str]:
    return _normalize_non_empty_values(values, value_label="Module")


def _validate_import_files(files: Sequence[Any] | Any) -> list[str]:
    normalized_files = _normalize_non_empty_values(files, value_label="Import file")
    for filename in normalized_files:
        path = Path(filename)
        if path.suffix.lower() not in {".po", ".csv"}:
            raise ConfigError(
                f"Translation import accepts only .po and .csv files: {filename}"
            )
        if not path.exists():
            raise ConfigError(f"Translation import file does not exist: {filename}")
        if not path.is_file():
            raise ConfigError(
                f"Translation import file must be a regular file: {filename}"
            )
    return normalized_files


def _validate_export_output(output: str | None, *, native_i18n: bool) -> str | None:
    if output is None:
        return None

    normalized_output = str(output).strip()
    if not normalized_output:
        raise ConfigError("Export output must be a non-empty path or '-'.")
    if normalized_output == "-":
        if native_i18n:
            return normalized_output
        raise ConfigError("Odoo 18 and older require --output for i18n export.")

    allowed_suffixes = (
        {".po", ".pot", ".tgz", ".csv"}
        if native_i18n
        else {
            ".po",
            ".csv",
            ".tgz",
        }
    )
    if Path(normalized_output).suffix.lower() not in allowed_suffixes:
        if native_i18n:
            raise ConfigError(
                "Odoo 19+ export output must end in .po, .pot, .tgz, .csv, or be '-'."
            )
        raise ConfigError(
            "Odoo 18 and older export output must end in .po, .csv, or .tgz."
        )

    return normalized_output


def odoo_series_major(value: Any | None) -> int | None:
    if value is None:
        return None
    if hasattr(value, "value"):
        return odoo_series_major(value.value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)

    text = str(value).strip()
    if not text:
        return None
    match = re.search(r"(\d+)", text)
    if not match:
        return None
    return int(match.group(1))


def _normalize_odoo_series_label(value: Any | None) -> str | None:
    major = odoo_series_major(value)
    if major is None:
        return None
    return f"{major}.0"


@dataclass
class CommandOperation:
    """Structured command operation containing both command and metadata."""

    command: list[str]
    # Operation types: 'server', 'test', 'shell', 'install', 'update',
    # 'create_db', 'export_language'
    operation_type: str
    database: str | None = None
    modules: list[str] = field(default_factory=list)
    test_tags: str | None = None
    extra_args: list[str] = field(default_factory=list)
    is_odoo_command: bool = True
    test_file: str | None = None

    # Result handling metadata
    expected_result_fields: dict[str, Any] = field(default_factory=dict)
    result_parsers: list[str] = field(default_factory=list)  # e.g., ['install', 'test']


class AbstractCommandBuilder(ABC):
    """Abstract base class for command builders following the Builder pattern"""

    def __init__(self, config_provider: ConfigProvider):
        self.config = config_provider
        self._command_parts: list[dict[str, Any]] = []

    @abstractmethod
    def build(self) -> list[str]:
        """Build and return the final command as a list of strings"""
        pass

    @abstractmethod
    def build_operation(self) -> CommandOperation:
        """Build and return a structured CommandOperation with metadata"""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset the builder to initial state for reuse"""
        pass

    def _set_command(self, command: str) -> "AbstractCommandBuilder":
        """Set a command (like 'shell', 'run', or binary like 'python')"""
        self._command_parts.append({"type": "command", "value": command})
        return self

    def _set_value(self, value: str) -> "AbstractCommandBuilder":
        """Set a value (like 'db_name')"""
        self._command_parts.append({"type": "value", "value": value})
        return self

    def _set_flag(self, flag: str, prefix: str = "--") -> "AbstractCommandBuilder":
        """Set a boolean flag without value (like --no-http, --stop-after-init)"""
        self._remove_by_key(flag)
        self._command_parts.append({"type": "flag", "key": flag, "prefix": prefix})
        return self

    def _set_parameter(
        self,
        key: str,
        value: str,
        prefix: str = "--",
        sep: str = "=",
        unique: bool = True,
    ) -> "AbstractCommandBuilder":
        """Set a parameter with value (like --database=mydb, -i module)"""
        if unique:
            self._remove_by_key(key)
        self._command_parts.append(
            {
                "type": "parameter",
                "key": key,
                "value": value,
                "prefix": prefix,
                "sep": sep,
            }
        )
        return self

    def _remove_by_key(self, key: str) -> "AbstractCommandBuilder":
        """Remove any command part by key"""
        self._command_parts = [
            part for part in self._command_parts if part.get("key") != key
        ]
        return self

    def _build_command_list(self) -> list[str]:
        """Convert command parts to string list"""
        result = []
        for part in self._command_parts:
            part_type = part.get("type")

            if part_type == "command":
                result.append(str(part["value"]))
            elif part_type == "value":
                result.append(str(part["value"]))
            elif part_type == "flag":
                result.append(f"{part['prefix']}{part['key']}")
            elif part_type == "parameter":
                key = part["key"]
                value = part["value"]
                prefix = part["prefix"]
                sep = part["sep"]

                if sep == "=":
                    result.append(f"{prefix}{key}={value}")
                elif sep == " ":
                    if prefix and key:
                        result.append(f"{prefix}{key}")
                    if value:
                        result.append(str(value))
                elif sep == "":
                    # Raw value without prefix/key formatting
                    result.append(str(value))

        return result


class BaseOdooCommandBuilder(AbstractCommandBuilder):
    """Base Odoo command builder with common functionality"""

    def __init__(self, config_provider: ConfigProvider):
        super().__init__(config_provider)

    def _setup_base_command(self) -> None:
        """Setup base python + odoo-bin command structure"""
        python_bin = self.config.get_optional("python_bin")
        odoo_bin = self.config.get_required("odoo_bin")
        if python_bin:
            self._set_command(python_bin)
        self._set_command(odoo_bin)

    def _apply_full_config(self) -> None:
        # Apply default configuration
        self._apply_default_config()
        # Apply logging configuration
        self._apply_log_config()
        # Apply database configuration
        self._appy_database_config()
        # Apply HTTP configuration
        self._apply_http_config()
        # Apply multiprocessing configuration
        self._apply_multiprocessing_config()

    def _expand_addons_path(self, addons_path: str) -> str:
        """Expand relative paths in addons_path with current directory"""
        paths = addons_path.split(",")
        expanded_paths = []
        for path in paths:
            path = path.strip()
            if not os.path.isabs(path):
                path = os.path.abspath(path)
            expanded_paths.append(path)
        return ",".join(expanded_paths)

    def _apply_default_config(self) -> None:
        """Apply default configuration from config provider"""
        if config_file := self.config.get_optional("config_file"):
            self.config_file(config_file)
        if addons_path := self.config.get_optional("addons_path"):
            expanded_path = self._expand_addons_path(addons_path)
            self.addons_path(expanded_path)
        if load := self.config.get_optional("load"):
            self.load(load)
        if data_dir := self.config.get_optional("data_dir"):
            self.data_dir(data_dir)

    def _apply_log_config(self) -> None:
        """Apply default configuration from config provider"""
        if log_level := self.config.get_optional("log_level"):
            self.log_level(log_level)
        if log_sql := self.config.get_optional("log_sql"):
            self.log_sql(log_sql)

    def _appy_database_config(self) -> None:
        """Apply database related configuration"""
        if db_name := self.config.get_optional("db_name"):
            self.database(db_name)
        if db_user := self.config.get_optional("db_user"):
            self.db_user(db_user)
        if db_password := self.config.get_optional("db_password"):
            self.db_password(db_password)
        if db_host := self.config.get_optional("db_host"):
            self.db_host(db_host)
        if db_filter := self.config.get_optional("db_filter"):
            self.db_filter(db_filter)
        if db_template := self.config.get_optional("db_template"):
            self.db_template(db_template)
        if db_maxconn := self.config.get_optional("db_maxconn"):
            self.db_maxconn(db_maxconn)

    def _apply_http_config(self) -> None:
        """Apply HTTP related configuration"""
        if http_interface := self.config.get_optional("http_interface"):
            self.http_interface(http_interface)
        if http_port := self.config.get_optional("http_port"):
            self.http_port(http_port)
        if gevent_port := self.config.get_optional("gevent_port"):
            self.gevent_port(gevent_port)
        if proxy_mode := self.config.get_optional("proxy_mode"):
            self.proxy_mode(proxy_mode)
        if db_maxconn_gevent := self.config.get_optional("db_maxconn_gevent"):
            self.db_maxconn_gevent(db_maxconn_gevent)

    def _remove_http_config(self) -> "BaseOdooCommandBuilder":
        """Disable HTTP server if configured"""
        self._remove_by_key("http-interface")
        self._remove_by_key("http-port")
        self._remove_by_key("gevent-port")
        self._remove_by_key("proxy-mode")
        self._remove_by_key("db_maxconn_gevent")
        return self

    def disable_http(self) -> "BaseOdooCommandBuilder":
        """Disable all HTTP-related options and enable --no-http."""
        self._remove_http_config()
        return self.no_http(True)

    def _apply_multiprocessing_config(self) -> None:
        """Apply multiprocessing related configuration"""
        if workers := self.config.get_optional("workers"):
            self.workers(workers)
        if limit_request := self.config.get_optional("limit_request"):
            self.limit_request(limit_request)
        if limit_memory_soft := self.config.get_optional("limit_memory_soft"):
            self.limit_memory_soft(limit_memory_soft)
        if limit_memory_hard := self.config.get_optional("limit_memory_hard"):
            self.limit_memory_hard(limit_memory_hard)
        if limit_time_cpu := self.config.get_optional("limit_time_cpu"):
            self.limit_time_cpu(limit_time_cpu)
        if limit_time_real := self.config.get_optional("limit_time_real"):
            self.limit_time_real(limit_time_real)
        if max_cron_threads := self.config.get_optional("max_cron_threads"):
            self.max_cron_threads(max_cron_threads)
        if limit_time_worker_cron := self.config.get_optional("limit_time_worker_cron"):
            self.limit_time_worker_cron(limit_time_worker_cron)

    # Core Odoo configuration methods
    def database(self, db_name: str) -> "BaseOdooCommandBuilder":
        """Set database name"""
        self._set_parameter("database", db_name)
        return self

    def addons_path(self, path: str) -> "BaseOdooCommandBuilder":
        """Set addons path"""
        self._set_parameter("addons-path", path)
        return self

    def load(self, modules: str) -> "BaseOdooCommandBuilder":
        """Set list of server-wide modules to load."""
        self._set_parameter("load", modules)
        return self

    def log_level(self, level: str) -> "BaseOdooCommandBuilder":
        """Set log level (info, warn, error, debug)"""
        self._set_parameter("log-level", level)
        return self

    def log_handler(self, handler: str) -> "BaseOdooCommandBuilder":
        """Set LOGGER:LEVEL, enables LOGGER at the provided LEVEL"""
        self._set_parameter("log-handler", handler, unique=False)
        return self

    def log_web(self, enabled: bool = True) -> "BaseOdooCommandBuilder":
        """enables DEBUG logging of HTTP requests and responses"""
        if enabled:
            self._set_flag("log-web")
        else:
            self._remove_by_key("log-web")
        return self

    def log_sql(self, enabled: bool = True) -> "BaseOdooCommandBuilder":
        """enables DEBUG logging of SQL querying"""
        if enabled:
            self._set_flag("log-sql")
        else:
            self._remove_by_key("log-sql")
        return self

    def syslog(self, enabled: bool = True) -> "BaseOdooCommandBuilder":
        """Enable: logs to the system's event logger"""
        if enabled:
            self._set_flag("syslog")
        else:
            self._remove_by_key("syslog")
        return self

    def db_maxconn(self, maxconn: int) -> "BaseOdooCommandBuilder":
        """Set maximum number of database connections"""
        self._set_parameter("db_maxconn", str(maxconn))
        return self

    def db_maxconn_gevent(self, maxconn: int) -> "BaseOdooCommandBuilder":
        """Set maximum number of database connections"""
        self._set_parameter("db_maxconn_gevent", str(maxconn))
        return self

    def db_user(self, user: str) -> "BaseOdooCommandBuilder":
        """Set database user"""
        self._set_parameter("db_user", user)
        return self

    def db_password(self, password: str) -> "BaseOdooCommandBuilder":
        """Set database password"""
        self._set_parameter("db_password", password)
        return self

    def db_host(self, hostname: str) -> "BaseOdooCommandBuilder":
        """Set database host"""
        self._set_parameter("db_host", hostname)
        return self

    def db_filter(self, filter: str) -> "BaseOdooCommandBuilder":
        """Set database filter"""
        self._set_parameter("db-filter", filter)
        return self

    def db_template(self, template: str) -> "BaseOdooCommandBuilder":
        """Set database template"""
        self._set_parameter("db_template", template)
        return self

    def http_port(self, port: int) -> "BaseOdooCommandBuilder":
        """Set HTTP port"""
        self._set_parameter("http-port", str(port))
        return self

    def gevent_port(self, port: int) -> "BaseOdooCommandBuilder":
        """Set GEVENT port"""
        self._set_parameter("gevent-port", str(port))
        return self

    def workers(self, workers: int) -> "BaseOdooCommandBuilder":
        """Set workers"""
        self._set_parameter("workers", str(workers))
        return self

    def limit_request(self, limit: int) -> "BaseOdooCommandBuilder":
        """Set limit-request"""
        self._set_parameter("limit-request", str(limit))
        return self

    def limit_memory_soft(self, limit: int) -> "BaseOdooCommandBuilder":
        """Set limit-memory-soft"""
        self._set_parameter("limit-memory-soft", str(limit))
        return self

    def limit_memory_hard(self, limit: int) -> "BaseOdooCommandBuilder":
        """Set limit-memory-hard"""
        self._set_parameter("limit-memory-hard", str(limit))
        return self

    def limit_time_cpu(self, limit: int) -> "BaseOdooCommandBuilder":
        """Set limit-time-cpu"""
        self._set_parameter("limit-time-cpu", str(limit))
        return self

    def limit_time_real(self, limit: int) -> "BaseOdooCommandBuilder":
        """Set limit-time-real"""
        self._set_parameter("limit-time-real", str(limit))
        return self

    def max_cron_threads(self, threads: int) -> "BaseOdooCommandBuilder":
        """Set max-cron-threads"""
        self._set_parameter("max-cron-threads", str(threads))
        return self

    def limit_time_worker_cron(self, limit: int) -> "BaseOdooCommandBuilder":
        """Set limit-time-worker-cron"""
        self._set_parameter("limit-time-worker-cron", str(limit))
        return self

    def http_interface(self, interface: str) -> "BaseOdooCommandBuilder":
        """Set http interface"""
        self._set_parameter("http-interface", interface)
        return self

    def data_dir(self, path: str) -> "BaseOdooCommandBuilder":
        """Set data directory"""
        self._set_parameter("data-dir", path)
        return self

    def config_file(self, path: str) -> "BaseOdooCommandBuilder":
        """Set config file path"""
        self._set_parameter("config", path)
        return self

    def dev(self, features: str = "all") -> "BaseOdooCommandBuilder":
        """Enable dev mode with specified features"""
        self._set_parameter("dev", features)
        return self

    def load_language(self, languages: str) -> "BaseOdooCommandBuilder":
        """specifies the languages (separated by commas) for the translations"""
        self._set_parameter("load-language", languages)
        return self

    def language(self, language: str) -> "BaseOdooCommandBuilder":
        """Set the language of the translation file
        use it with i18n-export or i18n-import
        """
        self._set_parameter("language", language)
        return self

    def i18n_export(self, filename: str) -> "BaseOdooCommandBuilder":
        """Set i18n export filename"""
        self._set_parameter("i18n-export", filename)
        return self

    def i18n_import(self, filename: str) -> "BaseOdooCommandBuilder":
        """Set i18n import filename"""
        self._set_parameter("i18n-import", filename)
        return self

    def i18n_overwrite(self, enabled: bool = True) -> "BaseOdooCommandBuilder":
        """Enable i18n overwrite"""
        if enabled:
            self._set_flag("i18n-overwrite")
        else:
            self._remove_by_key("i18n-overwrite")
        return self

    def modules(self, modules: str) -> "BaseOdooCommandBuilder":
        """Set list of modules to export"""
        self._set_parameter("modules", modules)
        return self

    def no_http(self, enabled: bool = True) -> "BaseOdooCommandBuilder":
        """Disable HTTP server"""
        if enabled:
            self._set_flag("no-http")
        else:
            self._remove_by_key("no-http")
        return self

    def proxy_mode(self, enabled: bool = True) -> "BaseOdooCommandBuilder":
        """Enables HTTP proxy"""
        if enabled:
            self._set_flag("proxy-mode")
        else:
            self._remove_by_key("proxy-mode")
        return self

    def stop_after_init(self, enabled: bool = True) -> "BaseOdooCommandBuilder":
        """Stop after module initialization"""
        if enabled:
            self._set_flag("stop-after-init")
        else:
            self._remove_by_key("stop-after-init")
        return self

    def install_module(self, module: str) -> "BaseOdooCommandBuilder":
        """Install a module"""
        self._set_parameter("i", module, prefix="-", sep=" ")
        return self

    def update_module(self, module: str) -> "BaseOdooCommandBuilder":
        """Update a module"""
        self._set_parameter("u", module, prefix="-", sep=" ")
        return self

    def shell_interface(self, interface: str) -> "BaseOdooCommandBuilder":
        """Set shell interface (ipython, ptpython, bpython, python)"""
        self._set_parameter("shell-interface", interface)
        return self

    def without_demo(self, modules: str) -> "BaseOdooCommandBuilder":
        """Disable demo data for specified modules"""
        self._set_parameter("without-demo", modules)
        return self

    def with_demo(self, enabled: bool = True) -> "BaseOdooCommandBuilder":
        """Install module with demo data"""
        if enabled:
            self._set_flag("with-demo")
        else:
            self._remove_by_key("with-demo")
        return self

    def reset(self) -> None:
        """Reset builder to initial state"""
        self._command_parts.clear()
        self._setup_base_command()

    def build(self) -> list[str]:
        """Build the final command list"""
        return self._build_command_list()

    def build_operation(self) -> CommandOperation:
        """Build a CommandOperation with base metadata. Subclasses should override."""
        return CommandOperation(
            command=self.build(),
            operation_type="server",  # Default, should be overridden
            database=self.config.get_optional("db_name"),
            modules=[],
            is_odoo_command=True,
            expected_result_fields={"database": self.config.get_optional("db_name")},
            result_parsers=[],
        )


class BaseI18nCommandBuilder(BaseOdooCommandBuilder):
    """Shared base for version-aware i18n command builders."""

    def __init__(self, config_provider: ConfigProvider, odoo_series: Any):
        super().__init__(config_provider)
        config_provider.validate_keys(
            ["odoo_bin", "addons_path", "db_name"], "i18n command"
        )
        self._odoo_series_major = odoo_series_major(odoo_series)
        if self._odoo_series_major is None:
            raise ConfigError(
                "Unable to determine the Odoo series for the i18n command. "
                "Pass --odoo-series 18.0 or --odoo-series 19.0."
            )
        self._odoo_series = _normalize_odoo_series_label(odoo_series)
        self._strategy = (
            "native_i18n" if self._odoo_series_major >= 19 else "legacy_flags"
        )
        self._setup_base_command()

    @property
    def is_native_i18n(self) -> bool:
        return self._strategy == "native_i18n"

    @property
    def strategy(self) -> str:
        return self._strategy

    @property
    def odoo_series(self) -> str:
        assert self._odoo_series is not None
        return self._odoo_series

    def _apply_i18n_environment_config(self) -> None:
        if config_file := self.config.get_optional("config_file"):
            self.config_file(config_file)
        if not self.is_native_i18n:
            if addons_path := self.config.get_optional("addons_path"):
                self.addons_path(self._expand_addons_path(addons_path))
        if db_name := self.config.get_optional("db_name"):
            self.database(db_name)

    def _apply_legacy_i18n_termination(self) -> None:
        self.stop_after_init(True)
        self.no_http(True)

    def _append_native_i18n_command(self, action: str) -> None:
        if addons_path := self.config.get_optional("addons_path"):
            self.addons_path(self._expand_addons_path(addons_path))
        self._set_command("i18n")
        self._set_command(action)

    def overwrite(self, enabled: bool = True) -> "BaseI18nCommandBuilder":
        if enabled:
            self._set_flag("overwrite")
        else:
            self._remove_by_key("overwrite")
        return self

    def log_level(self, level: str) -> "BaseI18nCommandBuilder":
        if self.is_native_i18n:
            return self
        super().log_level(level)
        return self

    def no_http(self, enabled: bool = True) -> "BaseI18nCommandBuilder":
        if self.is_native_i18n:
            self._remove_by_key("no-http")
            return self
        super().no_http(enabled)
        return self

    def stop_after_init(self, enabled: bool = True) -> "BaseI18nCommandBuilder":
        if self.is_native_i18n:
            self._remove_by_key("stop-after-init")
            return self
        super().stop_after_init(enabled)
        return self

    def disable_http(self) -> "BaseI18nCommandBuilder":
        if self.is_native_i18n:
            self._remove_http_config()
            self._remove_by_key("no-http")
            return self
        super().disable_http()
        return self


class RunCommandBuilder(BaseOdooCommandBuilder):
    """Specialized builder for run commands"""

    def __init__(self, config_provider: ConfigProvider):
        super().__init__(config_provider)
        config_provider.validate_keys(["odoo_bin", "db_name"], "Odoo run command")
        self._setup_base_command()
        self._apply_full_config()

    def build_operation(self) -> CommandOperation:
        return CommandOperation(
            command=self.build(),
            operation_type="server",
            database=self.config.get_optional("db_name"),
            modules=[],
            is_odoo_command=True,
            expected_result_fields={"database": self.config.get_optional("db_name")},
            result_parsers=[],
        )


class OdooTestCoverageCommandBuilder(BaseOdooCommandBuilder):
    """Specialized builder for test commands with coverage"""

    def __init__(self, config_provider: ConfigProvider, module: str):
        super().__init__(config_provider)
        # Store module for build_operation method
        self._module = module

        # Ensure required config for tests
        config_provider.validate_keys(
            ["coverage_bin", "odoo_bin", "addons_path", "db_name"], "test command"
        )
        coverage_bin = self.config.get_required("coverage_bin")
        module_manager = ModuleManager(self.config.get_required("addons_path"))
        module_path = module_manager.find_module_path(module)
        if not module_path:
            addons_path = self.config.get_required("addons_path")
            module_path = os.path.join(addons_path.split(",")[0], module)

        self._set_command(coverage_bin)
        self._set_command("run")
        self._command_parts.append(
            {
                "type": "parameter",
                "key": "",
                "value": f"--source={module_path}",
                "prefix": "",
                "sep": "",
            }
        )
        self._command_parts.append(
            {
                "type": "parameter",
                "key": "",
                "value": "--omit=*/__init__.py,*/__manifest__.py,*/tests/test_*.py",
                "prefix": "",
                "sep": "",
            }
        )

        odoo_bin = self.config.get_required("odoo_bin")
        self._set_command(odoo_bin)
        self._apply_full_config()
        self.stop_after_init(True)
        self._set_flag("test-enable")

    def test_module(
        self, module: str, install: bool = False
    ) -> "OdooTestCoverageCommandBuilder":
        """Configure module testing"""
        if install:
            self.install_module(module)
        else:
            self.update_module(module)
        self._set_parameter("test-tags", f"/{module}", prefix="--", sep=" ")
        return self

    def test_file(self, file_path: str) -> "OdooTestCoverageCommandBuilder":
        """Set specific test file"""
        self._set_parameter("test-file", file_path, prefix="--", sep=" ")
        return self

    def test_tags(self, tags: str) -> "OdooTestCoverageCommandBuilder":
        """Set test tags filter"""
        self._set_parameter("test-tags", tags, prefix="--", sep=" ")
        return self

    def build_operation(self) -> CommandOperation:
        # Extract test tags from command parts to populate metadata
        test_tags = None
        for part in self._command_parts:
            if part.get("key") == "test-tags":
                test_tags = part.get("value")
                break

        return CommandOperation(
            command=self.build(),
            operation_type="test",
            database=self.config.get_optional("db_name"),
            modules=[self._module],
            test_file=next(
                (
                    str(part.get("value"))
                    for part in self._command_parts
                    if part.get("key") == "test-file"
                ),
                None,
            ),
            test_tags=test_tags,
            is_odoo_command=True,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "modules_tested": [self._module],
                "test_coverage": True,
            },
            result_parsers=["test", "coverage"],
        )


class OdooTestCommandBuilder(BaseOdooCommandBuilder):
    """Specialized builder for test commands"""

    def __init__(self, config_provider: ConfigProvider):
        super().__init__(config_provider)
        # Ensure required config for tests
        config_provider.validate_keys(
            ["odoo_bin", "addons_path", "db_name"], "test command"
        )

        self._setup_base_command()
        self._apply_full_config()
        self.stop_after_init(True)
        self._set_flag("test-enable")

    def test_module(
        self, module: str, install: bool = False
    ) -> "OdooTestCommandBuilder":
        """Configure module testing"""
        if install:
            self.install_module(module)
        else:
            self.update_module(module)
        self._set_parameter("test-tags", f"/{module}", prefix="--", sep=" ")
        return self

    def test_file(self, file_path: str) -> "OdooTestCommandBuilder":
        """Set specific test file"""
        self._set_parameter("test-file", file_path, prefix="--", sep=" ")
        return self

    def test_tags(self, tags: str) -> "OdooTestCommandBuilder":
        """Set test tags filter"""
        self._set_parameter("test-tags", tags, prefix="--", sep=" ")
        return self

    def build_operation(self) -> CommandOperation:
        # Extract test tags and modules from command parts to populate metadata
        test_tags = None
        modules = []
        for part in self._command_parts:
            if part.get("key") == "test-tags":
                test_tags = part.get("value")
                modules = extract_test_tag_modules(test_tags)
            # Also extract modules from install (-i) and update (-u) parameters
            elif part.get("key") in ("i", "u"):
                module_value = part.get("value")
                if module_value and module_value not in modules:
                    modules.append(module_value)

        return CommandOperation(
            command=self.build(),
            operation_type="test",
            database=self.config.get_optional("db_name"),
            modules=modules,
            test_file=next(
                (
                    str(part.get("value"))
                    for part in self._command_parts
                    if part.get("key") == "test-file"
                ),
                None,
            ),
            test_tags=test_tags,
            is_odoo_command=True,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "modules_tested": modules,
            },
            result_parsers=["test"],
        )


class ShellCommandBuilder(BaseOdooCommandBuilder):
    """Specialized builder for shell commands"""

    def __init__(self, config_provider: ConfigProvider):
        super().__init__(config_provider)
        config_provider.validate_keys(
            ["odoo_bin", "db_name", "addons_path"],
            "Odoo shell command",
        )

        self._setup_base_command()
        self._set_command("shell")
        self._apply_full_config()
        self.no_http(True)  # Shell commands should disable HTTP server

    def build_operation(self) -> CommandOperation:
        return CommandOperation(
            command=self.build(),
            operation_type="shell",
            database=self.config.get_optional("db_name"),
            modules=[],
            is_odoo_command=True,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "shell_enabled": True,
            },
            result_parsers=[],
        )


class UpdateCommandBuilder(BaseOdooCommandBuilder):
    """Specialized builder for update commands"""

    def __init__(self, config_provider: ConfigProvider, module: str):
        super().__init__(config_provider)
        # Store module for build_operation method
        self._module = module

        config_provider.validate_keys(
            ["odoo_bin", "addons_path", "db_name"], "update command"
        )

        self._setup_base_command()
        self._apply_full_config()
        self.update_module(module)

    def build_operation(self) -> CommandOperation:
        split_modules = _split_module_csv(self._module)
        return CommandOperation(
            command=self.build(),
            operation_type="update",
            database=self.config.get_optional("db_name"),
            modules=split_modules,
            is_odoo_command=True,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "modules_updated": split_modules,
            },
            result_parsers=["install"],  # Update operations use install parser
        )


class InstallCommandBuilder(BaseOdooCommandBuilder):
    """Specialized builder for install commands"""

    def __init__(self, config_provider: ConfigProvider, module: str):
        super().__init__(config_provider)
        # Store module for build_operation method
        self._module = module

        config_provider.validate_keys(
            ["odoo_bin", "addons_path", "db_name"], "install command"
        )
        self._setup_base_command()
        self._apply_full_config()
        self.install_module(module)

    def build_operation(self) -> CommandOperation:
        split_modules = _split_module_csv(self._module)
        return CommandOperation(
            command=self.build(),
            operation_type="install",
            database=self.config.get_optional("db_name"),
            modules=split_modules,
            is_odoo_command=True,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "modules_installed": split_modules,
            },
            result_parsers=["install"],
        )


class I18nExportCommandBuilder(BaseI18nCommandBuilder):
    """Build version-aware translation export commands."""

    def __init__(
        self,
        config_provider: ConfigProvider,
        modules: Sequence[str],
        languages: Sequence[str] | None = None,
        output: str | None = None,
        *,
        odoo_series: Any,
    ):
        super().__init__(config_provider, odoo_series)
        self._modules = _normalize_modules(modules)
        self._languages = _normalize_languages(languages or ["pot"])
        self._output = _validate_export_output(output, native_i18n=self.is_native_i18n)

        if self.is_native_i18n:
            if self._output is not None and len(self._languages) != 1:
                raise ConfigError(
                    "--output can be used with exactly one export language on Odoo 19+."
                )
            self._append_native_i18n_command("export")
            for module in self._modules:
                self._set_command(module)
            self._set_flag("languages")
            for language in self._languages:
                self._set_value(language)
            if self._output is not None:
                self._set_parameter("output", self._output)
            self._apply_i18n_environment_config()
            return

        if len(self._languages) != 1:
            raise ConfigError("Odoo 18 and older support exactly one export language.")
        if self._output is None:
            raise ConfigError("Odoo 18 and older require --output for i18n export.")

        self._apply_i18n_environment_config()
        self.modules(",".join(self._modules))
        self.i18n_export(self._output)
        self.language(self._languages[0])
        self._apply_legacy_i18n_termination()

    def build_operation(self) -> CommandOperation:
        return CommandOperation(
            command=self.build(),
            operation_type="i18n_export",
            database=self.config.get_optional("db_name"),
            modules=list(self._modules),
            is_odoo_command=True,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "modules": list(self._modules),
                "languages": list(self._languages),
                "output": self._output,
                "odoo_series": self.odoo_series,
                "strategy": self.strategy,
            },
            result_parsers=[],
        )


class I18nImportCommandBuilder(BaseI18nCommandBuilder):
    """Build version-aware translation import commands."""

    def __init__(
        self,
        config_provider: ConfigProvider,
        files: Sequence[str],
        language: str,
        *,
        overwrite: bool = False,
        odoo_series: Any,
    ):
        super().__init__(config_provider, odoo_series)
        self._files = _validate_import_files(files)
        self._language = _normalize_languages([language])[0]
        self._overwrite = overwrite

        if self.is_native_i18n:
            self._append_native_i18n_command("import")
            for filename in self._files:
                self._set_command(filename)
            self.language(self._language)
            if self._overwrite:
                self.overwrite(True)
            self._apply_i18n_environment_config()
            return

        if len(self._files) != 1:
            raise ConfigError(
                "Odoo 18 and older import one translation file per invocation."
            )

        self._apply_i18n_environment_config()
        self.i18n_import(self._files[0])
        self.language(self._language)
        if self._overwrite:
            self.i18n_overwrite(True)
        self._apply_legacy_i18n_termination()

    def build_operation(self) -> CommandOperation:
        return CommandOperation(
            command=self.build(),
            operation_type="i18n_import",
            database=self.config.get_optional("db_name"),
            modules=[],
            is_odoo_command=True,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "files": list(self._files),
                "language": self._language,
                "overwrite": self._overwrite,
                "odoo_series": self.odoo_series,
                "strategy": self.strategy,
            },
            result_parsers=[],
        )


class I18nLoadLanguageCommandBuilder(BaseI18nCommandBuilder):
    """Build version-aware language-loading commands."""

    def __init__(
        self,
        config_provider: ConfigProvider,
        languages: Sequence[str],
        *,
        odoo_series: Any,
    ):
        super().__init__(config_provider, odoo_series)
        self._languages = _normalize_languages(languages)

        if self.is_native_i18n:
            self._append_native_i18n_command("loadlang")
            for language in self._languages:
                self._set_command(language)
            self._apply_i18n_environment_config()
            return

        self._apply_i18n_environment_config()
        self.load_language(",".join(self._languages))
        self._apply_legacy_i18n_termination()

    def build_operation(self) -> CommandOperation:
        return CommandOperation(
            command=self.build(),
            operation_type="i18n_load_language",
            database=self.config.get_optional("db_name"),
            modules=[],
            is_odoo_command=True,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "languages": list(self._languages),
                "odoo_series": self.odoo_series,
                "strategy": self.strategy,
            },
            result_parsers=[],
        )


class LanguageCommandBuilder(BaseOdooCommandBuilder):
    """Specialized builder for language export commands"""

    def __init__(
        self,
        config_provider: ConfigProvider,
        module: str,
        filename: str,
        language: str,
        odoo_series: Any | None = None,
    ):
        super().__init__(config_provider)
        self._module = module
        self._filename = filename
        self._language = language
        self._delegate = I18nExportCommandBuilder(
            config_provider,
            modules=[module],
            languages=[language],
            output=filename,
            odoo_series=odoo_series or "18.0",
        )
        self._command_parts = self._delegate._command_parts
        self._strategy = self._delegate.strategy
        self._odoo_series = self._delegate.odoo_series

    def log_level(self, level: str) -> "LanguageCommandBuilder":
        self._delegate.log_level(level)
        return self

    def no_http(self, enabled: bool = True) -> "LanguageCommandBuilder":
        self._delegate.no_http(enabled)
        return self

    def stop_after_init(self, enabled: bool = True) -> "LanguageCommandBuilder":
        self._delegate.stop_after_init(enabled)
        return self

    def disable_http(self) -> "LanguageCommandBuilder":
        self._delegate.disable_http()
        return self

    def reset(self) -> None:
        self._delegate.reset()
        self._command_parts = self._delegate._command_parts

    def build_operation(self) -> CommandOperation:
        return CommandOperation(
            command=self.build(),
            operation_type="export_language",
            database=self.config.get_optional("db_name"),
            modules=[self._module],
            extra_args=[self._filename, self._language],
            is_odoo_command=True,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "module": self._module,
                "filename": self._filename,
                "language": self._language,
                "odoo_series": self._odoo_series,
                "strategy": self._strategy,
            },
            result_parsers=[],
        )


class VersionCommandBuilder(BaseOdooCommandBuilder):
    """Specialized builder for version command"""

    def __init__(self, config_provider: ConfigProvider):
        super().__init__(config_provider)
        config_provider.validate_keys(["odoo_bin"], "version command")
        self._setup_base_command()
        self._set_flag("version")

    def build_operation(self) -> CommandOperation:
        return CommandOperation(
            command=self.build(),
            operation_type="version",
            database=None,
            modules=[],
            is_odoo_command=True,
            expected_result_fields={"version": None},
            result_parsers=["version"],
        )


class DatabaseCommandBuilder(AbstractCommandBuilder):
    """Builder for database-related commands"""

    def __init__(self, config_provider: ConfigProvider, with_sudo: bool = True):
        super().__init__(config_provider)
        config_provider.validate_keys(["db_name"], "database command")
        self.with_sudo = with_sudo
        self._setup_base_command()

    def _setup_base_command(self) -> None:
        if self.with_sudo:
            self._setup_sudo_command()

    def _setup_sudo_command(self) -> None:
        """Setup sudo command structure"""
        self._set_command("sudo")
        self._set_flag("S", prefix="-")
        self._set_command("su")
        self._set_command("-")
        self._set_command("postgres")
        self._set_flag("c", prefix="-")

    def _append_raw_tokens(self, tokens: list[str]) -> None:
        """Append raw command tokens in the provided order."""
        for token in tokens:
            self._set_command(str(token))

    def _get_psql_connection_tokens(self, db_user: str | None = None) -> list[str]:
        """Build psql connection arguments from the active configuration."""
        if db_user is None:
            db_user = self.config.get_optional("db_user")

        tokens: list[str] = []

        if db_host := self.config.get_optional("db_host"):
            tokens.extend(["-h", str(db_host)])
        if db_port := self.config.get_optional("db_port"):
            tokens.extend(["-p", str(db_port)])
        if db_user:
            tokens.extend(["-U", str(db_user)])

        return tokens

    def _with_password_env(self, tokens: list[str]) -> list[str]:
        """Prefix commands with PGPASSWORD when configured."""
        if db_password := self.config.get_optional("db_password"):
            return ["env", f"PGPASSWORD={db_password}", *tokens]
        return tokens

    @staticmethod
    def _shell_join(tokens: list[str]) -> str:
        """Render tokens into a shell-safe command string."""
        return " ".join(shlex.quote(str(token)) for token in tokens)

    @staticmethod
    def _sql_literal(value: str) -> str:
        """Escape a string for use as a SQL literal."""
        escaped = value.replace("'", "''")
        return f"'{escaped}'"

    def drop_command(self) -> "DatabaseCommandBuilder":
        """Build database drop command"""
        self.config.validate_keys(["db_name"], "database drop command")
        db_name = self.config.get_required("db_name")
        if self.with_sudo:
            self._set_command(f'dropdb --if-exists "{db_name}"')
        else:
            self._set_command("dropdb")
            self._set_flag("if-exists")
            self._set_value(f"{db_name}")
        return self

    def create_role_command(
        self, db_user: str | None = None
    ) -> "DatabaseCommandBuilder":
        """Build database create role command"""
        if db_user is None:
            self.config.validate_keys(["db_user"], "database create role command")
            db_user = self.config.get_optional("db_user")

        self._set_command(f'psql -c "CREATE ROLE \\"{db_user}\\"";')
        return self

    def create_extension_command(self, extension: str) -> "DatabaseCommandBuilder":
        """Build database create role command"""
        self.config.validate_keys(["db_user"], "database create role command")

        self._set_command(f'psql -c "CREATE EXTENSION \\"{extension}\\"";')
        return self

    def alter_role_command(
        self, db_user: str | None = None
    ) -> "DatabaseCommandBuilder":
        """Build database alter role command to add login and createdb privileges"""
        if db_user is None:
            self.config.validate_keys(["db_user"], "database alter role command")
            db_user = self.config.get_optional("db_user")
        self._set_command(f'psql -c "ALTER ROLE \\"{db_user}\\" WITH LOGIN CREATEDB";')
        return self

    def create_command(self, db_user: str | None = None) -> "DatabaseCommandBuilder":
        """Build database create command"""
        self.config.validate_keys(["db_name"], "database create command")
        db_name = self.config.get_required("db_name")
        if db_user is None:
            db_user = self.config.get_optional("db_user")
        if self.with_sudo and db_user:
            self._set_command(f'createdb -O "{db_user}" "{db_name}"')
        elif self.with_sudo and not db_user:
            self._set_command(f'createdb "{db_name}"')
        else:
            self._set_command("createdb")
            if db_user:
                self._set_parameter("owner", db_user)
            self._set_value(f"{db_name}")
        return self

    def legacy_init_base_command(
        self,
        *,
        with_demo: bool = False,
        without_demo: bool = False,
        language: str | None = None,
    ) -> "DatabaseCommandBuilder":
        """Build legacy-compatible Odoo server init command for base installation."""
        self.config.validate_keys(["odoo_bin", "db_name"], "database base init command")
        if with_demo and without_demo:
            raise ValueError("--with-demo and --without-demo are mutually exclusive")

        if python_bin := self.config.get_optional("python_bin"):
            self._set_command(str(python_bin))
        self._set_command(self.config.get_required("odoo_bin"))

        if config_file := self.config.get_optional("config_file"):
            self._set_parameter("config", str(config_file))
        if addons_path := self.config.get_optional("addons_path"):
            expanded_path = BaseOdooCommandBuilder(self.config)._expand_addons_path(
                str(addons_path)
            )
            self._set_parameter("addons-path", expanded_path)
        if data_dir := self.config.get_optional("data_dir"):
            self._set_parameter("data-dir", str(data_dir))

        if db_user := self.config.get_optional("db_user"):
            self._set_parameter("db_user", str(db_user))
        if db_password := self.config.get_optional("db_password"):
            self._set_parameter("db_password", str(db_password))
        if db_host := self.config.get_optional("db_host"):
            self._set_parameter("db_host", str(db_host))
        if db_port := self.config.get_optional("db_port"):
            self._set_parameter("db_port", str(db_port))
        if db_sslmode := self.config.get_optional("db_sslmode"):
            self._set_parameter("db_sslmode", str(db_sslmode))

        self._set_parameter("database", str(self.config.get_required("db_name")))
        self._set_parameter("i", "base", prefix="-", sep=" ")
        self._set_flag("stop-after-init")
        self._set_flag("no-http")

        if language:
            self._set_parameter("load-language", str(language))

        if with_demo:
            self._set_flag("with-demo")
        else:
            self._set_parameter("without-demo", "all")

        return self

    def native_db_init_command(
        self,
        *,
        with_demo: bool = False,
        without_demo: bool = False,
        country: str | None = None,
        language: str | None = None,
        username: str = "admin",
        password: str = "admin",
        force: bool = False,
    ) -> "DatabaseCommandBuilder":
        """Build native Odoo 19+ db init command."""
        self.config.validate_keys(["odoo_bin", "db_name"], "database init command")
        if with_demo and without_demo:
            raise ValueError("--with-demo and --without-demo are mutually exclusive")

        if python_bin := self.config.get_optional("python_bin"):
            self._set_command(str(python_bin))
        self._set_command(self.config.get_required("odoo_bin"))
        self._set_command("db")

        if config_file := self.config.get_optional("config_file"):
            self._set_parameter("config", str(config_file))
        if data_dir := self.config.get_optional("data_dir"):
            self._set_parameter("data-dir", str(data_dir))
        if addons_path := self.config.get_optional("addons_path"):
            expanded_path = BaseOdooCommandBuilder(self.config)._expand_addons_path(
                str(addons_path)
            )
            self._set_parameter("addons-path", expanded_path)
        if db_user := self.config.get_optional("db_user"):
            self._set_parameter("db_user", str(db_user))
        if db_password := self.config.get_optional("db_password"):
            self._set_parameter("db_password", str(db_password))
        if db_host := self.config.get_optional("db_host"):
            self._set_parameter("db_host", str(db_host))
        if db_port := self.config.get_optional("db_port"):
            self._set_parameter("db_port", str(db_port))
        if db_sslmode := self.config.get_optional("db_sslmode"):
            self._set_parameter("db_sslmode", str(db_sslmode))

        self._set_command("init")
        self._set_value(str(self.config.get_required("db_name")))

        if with_demo:
            self._set_flag("with-demo")
        if force:
            self._set_flag("force")
        if country:
            self._set_parameter("country", str(country), sep=" ")
        if language:
            self._set_parameter("language", str(language), sep=" ")
        if username:
            self._set_parameter("username", str(username), sep=" ")
        if password:
            self._set_parameter("password", str(password), sep=" ")

        return self

    def init_command(
        self,
        *,
        with_demo: bool = False,
        without_demo: bool = False,
        country: str | None = None,
        language: str | None = None,
    ) -> "DatabaseCommandBuilder":
        """Backward-compatible wrapper for legacy base initialization."""
        _ = country
        self.legacy_init_base_command(
            with_demo=with_demo,
            without_demo=without_demo,
            language=language,
        )
        return self

    def list_db_command(self, db_user: str | None = None) -> "DatabaseCommandBuilder":
        """Build database list command"""
        if db_user is None:
            db_user = self.config.get_optional("db_user")

        if self.with_sudo:
            if db_user:
                self._set_command(f'psql -l -U "{db_user}"')
            else:
                self._set_command("psql -l")
        else:
            self._set_command("psql")
            self._set_flag("l", prefix="-")
            if db_user:
                self._set_parameter("U", str(db_user), prefix="-", sep=" ")
        return self

    def exists_db_command(self, db_user: str | None = None) -> "DatabaseCommandBuilder":
        """Build database exists check command"""
        self.config.validate_keys(["db_name"], "database exists command")
        db_name = self.config.get_required("db_name")

        query = (
            f"SELECT 1 FROM pg_database WHERE datname = {self._sql_literal(db_name)};"
        )
        connection_tokens = self._get_psql_connection_tokens(db_user)
        tokens = ["psql", "-d", "postgres", "-tAc", query, *connection_tokens]

        if self.with_sudo:
            self._set_command(self._shell_join(self._with_password_env(tokens)))
        else:
            self._append_raw_tokens(self._with_password_env(tokens))
        return self

    def reset(self) -> None:
        """Reset builder to initial state"""
        self._command_parts.clear()
        self._setup_base_command()

    def build(self) -> list[str]:
        """Build the final command list"""
        return self._build_command_list()

    def build_operation(self) -> CommandOperation:
        # Determine operation type based on command structure
        operation_type = "create_db"
        for part in self._command_parts:
            if part.get("type") == "command":
                command_value = str(part.get("value", "")).lower()
                if "dropdb" in command_value:
                    operation_type = "drop_db"
                    break
                elif "createdb" in command_value:
                    operation_type = "create_db"
                    break
                elif "create role" in command_value:
                    operation_type = "create_role"
                    break
                elif "alter role" in command_value:
                    operation_type = "alter_role"
                    break
                elif "create extension" in command_value:
                    operation_type = "create_extension"
                    break
                elif "psql -l" in command_value:
                    operation_type = "list_db"
                    break
                elif "from pg_database" in command_value or "grep -qw" in command_value:
                    operation_type = "exists_db"
                    break
            elif part.get("type") == "flag" and part.get("key") == "l":
                operation_type = "list_db"
                break

        return CommandOperation(
            command=self.build(),
            operation_type=operation_type,
            database=self.config.get_optional("db_name"),
            modules=[],
            is_odoo_command=False,
            expected_result_fields={
                "database": self.config.get_optional("db_name"),
                "with_sudo": self.with_sudo,
            },
            result_parsers=[],
        )
