from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..odoo_operations import OdooOperations


class OperationsService:
    """Base class for internal OdooOperations service groups."""

    def __init__(self, operations: OdooOperations):
        self.operations = operations
