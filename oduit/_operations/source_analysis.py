from __future__ import annotations

from typing import Any

from .. import output as _output_module
from ..api_models import (
    AddonModelInventory,
    AddonTestInventory,
    FieldSourceLocation,
    InstalledModelField,
    InstalledViewExtension,
    ModelExtensionInventory,
    ModelSourceLocation,
)
from ..exceptions import ConfigError, ModuleNotFoundError
from ..output import print_error, print_error_result, print_info
from ..source_locator import (
    list_addon_models,
    list_addon_tests,
    list_model_extensions,
    locate_field_sources,
    locate_model_sources,
    recommend_tests,
)
from ..utils import validate_addon_name
from .base import OperationsService


class SourceAnalysisOperationsService(OperationsService):
    """Addon source inspection and scaffolding helpers."""

    def create_addon(
        self,
        addon_name: str,
        destination: str | None = None,
        template: str | None = None,
        suppress_output: bool = False,
    ) -> dict:
        """Create a new Odoo addon using the scaffold command.

        Creates a new Odoo addon with basic structure using odoo-bin scaffold.
        The addon name is validated to ensure it follows Odoo naming conventions.
        If no destination is specified, the first path in addons_path is used.

        Args:
            addon_name (str): Name for the new addon (must follow naming conventions)
            destination (str | None, optional): Target directory for the new addon.
                If None, uses first path from addons_path. Defaults to None.
            template (str | None, optional): Template name to use for scaffolding.
                Defaults to None (uses default template).

        Returns:
            dict: Operation result with success status and command details

        Raises:
            ConfigError: If the environment configuration is invalid

        Example:
            >>> env_config = {'python_bin': '/usr/bin/python3',
            ...               'odoo_bin': '/path/to/odoo-bin',
            ...               'addons_path': '/path/to/addons'}
            >>> ops = OdooOperations(env_config)
            >>> result = ops.create_addon('my_custom_module')
            >>> if result['success']:
            ...     print("Addon created successfully")
        """
        if not suppress_output:
            print_info(f"Creating addon: {addon_name}")

        if not validate_addon_name(addon_name):
            error_msg = (
                f"Invalid addon name: {addon_name}. "
                f"Must be lowercase letters, numbers, and underscores only."
            )
            result = {
                "success": False,
                "error": error_msg,
                "error_type": "ValidationError",
            }
            if suppress_output:
                return result
            if _output_module._formatter.format_type == "json":
                print_error_result(error_msg, 1)
            else:
                print_error(error_msg)
            return result

        cmd = [
            self.operations.config.get_required("python_bin"),
            self.operations.config.get_required("odoo_bin"),
            "scaffold",
            addon_name,
        ]

        if destination:
            cmd.append(destination)
        elif self.operations.config.get_required("addons_path"):
            first_addon_path = (
                self.operations.config.get_required("addons_path").split(",")[0].strip()
            )
            cmd.append(first_addon_path)

        if template:
            cmd.extend(["-t", template])

        try:
            result = self.operations.process_manager.run_command(
                cmd,
                verbose=self.operations.verbose and not suppress_output,
                suppress_output=suppress_output,
            )

            if result:
                result.update(
                    {
                        "operation": "create_addon",
                        "addon_name": addon_name,
                        "command": cmd,
                    }
                )
            else:
                result = {"success": False, "error": "Failed to create addon"}

        except ConfigError as e:
            result = {"success": False, "error": str(e), "error_type": "ConfigError"}
            if suppress_output:
                return result
            if _output_module._formatter.format_type == "json":
                print_error_result(str(e), 1)
            else:
                print_error(str(e))

        return result

    def locate_model(
        self,
        module_name: str,
        model: str,
    ) -> ModelSourceLocation:
        """Return static source candidates for a model extension."""
        module_manager = self.operations._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return locate_model_sources(addon_root, module_name, model)

    def locate_field(
        self,
        module_name: str,
        model: str,
        field_name: str,
    ) -> FieldSourceLocation:
        """Return static field source candidates inside one addon."""
        module_manager = self.operations._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return locate_field_sources(addon_root, module_name, model, field_name)

    def list_addon_tests(
        self,
        module_name: str,
        model: str | None = None,
        field_name: str | None = None,
    ) -> AddonTestInventory:
        """Return likely addon test files for one addon."""
        module_manager = self.operations._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return list_addon_tests(
            addon_root, module_name, model=model, field_name=field_name
        )

    def list_addon_models(self, module_name: str) -> AddonModelInventory:
        """Return a static model inventory for one addon."""
        module_manager = self.operations._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return list_addon_models(addon_root, module_name)

    def recommend_tests(
        self,
        module_name: str,
        paths: list[str],
    ) -> dict[str, Any]:
        """Return changed-file to test recommendations for one addon."""
        module_manager = self.operations._get_module_manager()
        addon_root = module_manager.find_module_path(module_name)
        if addon_root is None:
            raise ModuleNotFoundError(
                f"Module '{module_name}' was not found in addons_path"
            )
        return recommend_tests(addon_root, module_name, paths).to_dict()

    def find_model_extensions(
        self,
        model: str,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> ModelExtensionInventory:
        """Return combined source and installed metadata for one model."""
        addons_path = self.operations.config.get_required("addons_path")
        inventory = list_model_extensions(addons_path, model)

        field_result = self.operations.query_model(
            "ir.model.fields",
            domain=[["model", "=", model]],
            fields=["name", "ttype", "relation", "modules", "state"],
            limit=500,
            database=database,
            timeout=timeout,
        )
        if field_result.success:
            inventory.installed_fields = [
                InstalledModelField(
                    name=str(record.get("name", "")),
                    ttype=str(record.get("ttype", "")),
                    relation=(
                        str(record["relation"])
                        if isinstance(record.get("relation"), str)
                        else None
                    ),
                    modules=(
                        str(record["modules"])
                        if isinstance(record.get("modules"), str)
                        else None
                    ),
                    state=(
                        str(record["state"])
                        if isinstance(record.get("state"), str)
                        else None
                    ),
                )
                for record in field_result.records
                if record.get("name")
            ]
        elif field_result.error:
            inventory.warnings.append(
                f"Failed to query installed field metadata: {field_result.error}"
            )

        view_result = self.operations.query_model(
            "ir.ui.view",
            domain=[["model", "=", model], ["inherit_id", "!=", False]],
            fields=["name", "key", "priority", "inherit_id"],
            limit=200,
            database=database,
            timeout=timeout,
        )
        if view_result.success:
            inventory.installed_view_extensions = [
                InstalledViewExtension(
                    name=str(record.get("name", "")),
                    key=(
                        str(record["key"])
                        if isinstance(record.get("key"), str)
                        else None
                    ),
                    priority=(
                        int(record["priority"])
                        if isinstance(record.get("priority"), int)
                        and not isinstance(record.get("priority"), bool)
                        else None
                    ),
                    inherit_id=(
                        list(record["inherit_id"])
                        if isinstance(record.get("inherit_id"), list)
                        else None
                    ),
                )
                for record in view_result.records
                if record.get("name")
            ]
        elif view_result.error:
            inventory.warnings.append(
                f"Failed to query installed view metadata: {view_result.error}"
            )

        declared_modules = {item.module for item in inventory.base_declarations}
        inventory.installed_extension_fields = [
            field
            for field in inventory.installed_fields
            if field.modules and field.modules not in declared_modules
        ]
        inventory.installed_extension_modules = sorted(
            {
                field.modules
                for field in inventory.installed_extension_fields
                if field.modules
            }
        )
        inventory.warnings = sorted(dict.fromkeys(inventory.warnings))
        return inventory
