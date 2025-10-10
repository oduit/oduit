# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.


"""Oduit - Odoo development utilities."""

from ._version import __version__, version_tuple
from .config_loader import ConfigLoader
from .demo_process_manager import DemoProcessManager
from .exceptions import (
    ConfigError,
    OdooOperationError,
    ModuleOperationError,
    ModuleUpdateError,
    ModuleInstallError,
    ModuleNotFoundError,
    DatabaseOperationError,
)
from .manifest import (
    Manifest,
    ManifestError,
    InvalidManifestError,
    ManifestNotFoundError,
)
from .manifest_collection import ManifestCollection
from .addons_path_manager import AddonsPathManager
from .module_manager import ModuleManager
from .odoo_operations import OdooOperations
from .odoo_embedded_manager import OdooEmbeddedManager
from .odoo_code_executor import OdooCodeExecutor
from .output import (
    OutputFormatter,
    configure_output,
    print_error,
    print_error_result,
    print_info,
    print_result,
    print_success,
    print_warning,
)
from .process_manager import ProcessManager
from .operation_result import OperationResult

__all__ = [
    "__version__",
    "version_tuple",
    "ConfigLoader",
    "Manifest",
    "ManifestError",
    "InvalidManifestError",
    "ManifestNotFoundError",
    "ManifestCollection",
    "AddonsPathManager",
    "ModuleManager",
    "ConfigError",
    "OdooOperationError",
    "ModuleOperationError",
    "ModuleUpdateError",
    "ModuleInstallError",
    "ModuleNotFoundError",
    "DatabaseOperationError",
    "DemoProcessManager",
    "OdooOperations",
    "OdooEmbeddedManager",
    "OdooCodeExecutor",
    "ProcessManager",
    "OperationResult",
    "OutputFormatter",
    "configure_output",
    "print_info",
    "print_success",
    "print_warning",
    "print_error",
    "print_result",
    "print_error_result",
]
