# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

"""Type definitions for the CLI application."""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from manifestoo_core.odoo_series import OdooSeries


class OutputFormat(str, Enum):
    """Output format options."""

    TEXT = "text"
    JSON = "json"


class AddonTemplate(str, Enum):
    """Available addon templates."""

    BASIC = "basic"
    WEBSITE = "website"


class AddonListType(str, Enum):
    """Types of addons to list."""

    ALL = "all"
    INSTALLED = "installed"
    AVAILABLE = "available"


class ShellInterface(str, Enum):
    """Available shell interfaces."""

    IPYTHON = "ipython"
    PTPYTHON = "ptpython"
    BPYTHON = "bpython"
    PYTHON = "python"


class SortingChoice(str, Enum):
    """Sorting options for addon lists."""

    ALPHABETICAL = "alphabetical"
    TOPOLOGICAL = "topological"


class DevFeature(str, Enum):
    """Development features for --dev option.

    For development purposes only. Do not use in production.
    """

    ALL = "all"
    XML = "xml"
    RELOAD = "reload"
    QWEB = "qweb"
    IPDB = "ipdb"
    PDB = "pdb"
    PUDB = "pudb"
    WERKZEUG = "werkzeug"


class LogLevel(str, Enum):
    """Odoo log levels."""

    INFO = "info"
    DEBUG = "debug"
    WARN = "warn"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class GlobalConfig:
    """Global configuration context for commands."""

    env: str | None = None
    non_interactive: bool = False
    format: OutputFormat = OutputFormat.TEXT
    verbose: bool = False
    no_http: bool = False
    env_config: dict[str, Any] | None = None
    env_name: str | None = None
    odoo_series: OdooSeries | None = None


@dataclass
class CommandResult:
    """Result of a command execution."""

    success: bool
    message: str | None = None
    exit_code: int = 0
    data: dict[str, Any] | None = None
