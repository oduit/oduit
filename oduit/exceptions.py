# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.


class ConfigError(Exception):
    """Error for missing configuration values"""

    pass


class OdooOperationError(Exception):
    """Base exception for Odoo operations"""

    def __init__(self, message: str, operation_result: dict | None = None):
        super().__init__(message)
        self.operation_result = operation_result


class ModuleOperationError(OdooOperationError):
    """Base exception for module operations"""

    pass


class ModuleUpdateError(ModuleOperationError):
    """Raised when module update fails"""

    pass


class ModuleInstallError(ModuleOperationError):
    """Raised when module installation fails"""

    pass


class ModuleNotFoundError(ModuleOperationError):
    """Raised when module doesn't exist"""

    pass


class DatabaseOperationError(OdooOperationError):
    """Raised when database operations fail"""

    pass
