from __future__ import annotations

from typing import Any

from ..api_models import (
    AddonInstallState,
    DocumentationRuntimeInventory,
    InstalledAddonInventory,
    ModelFieldsResult,
    ModelViewInventory,
    ModelViewRecord,
    QueryModelResult,
    RecordReadResult,
    SearchCountResult,
)
from .base import OperationsService


class QueryOperationsService(OperationsService):
    """Typed runtime query helpers."""

    def get_addon_install_state(
        self,
        module: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> AddonInstallState:
        """Return the runtime install state for one addon."""
        result = self.operations.query_model(
            "ir.module.module",
            domain=[["name", "=", module]],
            fields=["name", "state"],
            limit=1,
            database=database,
            timeout=timeout,
        )
        if not result.success:
            return AddonInstallState(
                success=False,
                operation="get_addon_install_state",
                module=module,
                database=type(self.operations)._normalize_optional_str(
                    getattr(result, "database", None)
                ),
                error=result.error,
                error_type=result.error_type,
            )

        record = result.records[0] if result.records else {}
        state = str(record.get("state") or "uninstalled")
        return AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module=module,
            record_found=bool(result.records),
            state=state,
            installed=state == "installed",
            database=type(self.operations)._normalize_optional_str(
                getattr(result, "database", None)
            ),
        )

    def list_installed_dependents(
        self,
        module: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> InstalledAddonInventory:
        """Return installed addons that depend on the target module."""
        reverse_dependencies = (
            self.operations._get_module_manager().get_reverse_dependencies(module)
        )
        if not reverse_dependencies:
            return InstalledAddonInventory(
                success=True,
                operation="list_installed_dependents",
                addons=[],
                total=0,
                states=["installed"],
                modules_filter=[],
                database=database,
            )

        result = self.operations.list_installed_addons(
            modules=reverse_dependencies,
            states=["installed"],
            database=database,
            timeout=timeout,
        )
        if not result.success:
            return InstalledAddonInventory(
                success=False,
                operation="list_installed_dependents",
                addons=[],
                total=0,
                states=["installed"],
                modules_filter=reverse_dependencies,
                database=result.database,
                error=result.error,
                error_type=result.error_type,
                warnings=list(result.warnings),
                remediation=list(result.remediation),
            )

        return InstalledAddonInventory(
            success=True,
            operation="list_installed_dependents",
            addons=list(result.addons),
            total=result.total,
            states=list(result.states),
            modules_filter=reverse_dependencies,
            database=result.database,
            warnings=list(result.warnings),
            remediation=list(result.remediation),
        )

    def list_installed_addons(
        self,
        *,
        modules: list[str] | None = None,
        states: list[str] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> InstalledAddonInventory:
        """Return runtime addon inventory from ``ir.module.module``."""
        modules_filter = list(dict.fromkeys(modules or []))
        states_filter = list(dict.fromkeys(states or ["installed"]))
        domain: list[list[Any]] = [["state", "in", states_filter]]
        if modules_filter:
            domain.append(["name", "in", modules_filter])

        result = self.operations.query_model(
            "ir.module.module",
            domain=domain,
            fields=["name", "state", "shortdesc", "application", "auto_install"],
            limit=500,
            database=database,
            timeout=timeout,
        )
        if not result.success:
            return InstalledAddonInventory(
                success=False,
                operation="list_installed_addons",
                states=states_filter,
                modules_filter=modules_filter,
                database=result.database,
                error=result.error,
                error_type=result.error_type,
                remediation=[
                    "Verify database access and retry the runtime addon inventory "
                    "query."
                ],
            )

        addons = sorted(
            (
                type(self.operations)._normalize_installed_addon_record(record)
                for record in result.records
            ),
            key=lambda addon: addon.module,
        )
        return InstalledAddonInventory(
            success=True,
            operation="list_installed_addons",
            addons=addons,
            total=len(addons),
            states=states_filter,
            modules_filter=modules_filter,
            database=result.database,
        )

    def query_model(
        self,
        model: str,
        domain: list[Any] | tuple[Any, ...] | None = None,
        fields: list[str] | tuple[str, ...] | None = None,
        limit: int = 80,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> QueryModelResult:
        """Delegate typed read-only model queries to ``OdooQuery``."""
        return QueryModelResult.from_dict(
            self.operations._get_query_helper().query_model(
                model,
                domain=domain,
                fields=fields,
                limit=limit,
                database=database,
                timeout=timeout,
            )
        )

    def read_record(
        self,
        model: str,
        record_id: int,
        fields: list[str] | tuple[str, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> RecordReadResult:
        """Delegate typed single-record reads to ``OdooQuery``."""
        return RecordReadResult.from_dict(
            self.operations._get_query_helper().read_record(
                model,
                record_id,
                fields=fields,
                database=database,
                timeout=timeout,
            )
        )

    def search_count(
        self,
        model: str,
        domain: list[Any] | tuple[Any, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> SearchCountResult:
        """Delegate typed count queries to ``OdooQuery``."""
        return SearchCountResult.from_dict(
            self.operations._get_query_helper().search_count(
                model,
                domain=domain,
                database=database,
                timeout=timeout,
            )
        )

    def get_model_fields(
        self,
        model: str,
        attributes: list[str] | tuple[str, ...] | None = None,
        module: str | None = None,
        database: str | None = None,
        timeout: float = 30.0,
    ) -> ModelFieldsResult:
        """Delegate typed field metadata queries to ``OdooQuery``."""
        return ModelFieldsResult.from_dict(
            self.operations._get_query_helper().get_model_fields(
                model,
                attributes=attributes,
                module=module,
                database=database,
                timeout=timeout,
            )
        )

    def get_model_views(
        self,
        model: str,
        view_types: list[str] | tuple[str, ...] | None = None,
        database: str | None = None,
        timeout: float = 30.0,
        include_arch: bool = True,
    ) -> ModelViewInventory:
        """Return primary and extension DB views for one model."""
        fields = ["name", "type", "mode", "priority", "inherit_id", "key", "active"]
        if include_arch:
            fields.append("arch_db")

        result = self.operations.query_model(
            "ir.ui.view",
            domain=[["model", "=", model]],
            fields=fields,
            limit=500,
            database=database,
            timeout=timeout,
        )
        warnings: list[str] = []
        remediation: list[str] = []
        requested_types = list(view_types or [])

        if not result.success:
            return ModelViewInventory(
                model=model,
                requested_types=requested_types,
                database=database,
                error=result.error,
                error_type=result.error_type,
                warnings=(
                    [f"Failed to query model views: {result.error}"]
                    if result.error
                    else warnings
                ),
                remediation=(
                    [
                        "Verify database access and model name, then retry the "
                        "view query."
                    ]
                    if result.error
                    else remediation
                ),
            )

        normalized_types = {value for value in requested_types}
        records: list[ModelViewRecord] = []
        for record in result.records:
            raw_type = record.get("type")
            if not isinstance(raw_type, str):
                continue
            if normalized_types and raw_type not in normalized_types:
                continue

            raw_inherit_id = record.get("inherit_id")
            inherit_id = (
                list(raw_inherit_id) if isinstance(raw_inherit_id, list) else None
            )
            records.append(
                ModelViewRecord(
                    id=int(record.get("id", 0) or 0),
                    name=str(record.get("name", "")),
                    view_type=raw_type,
                    mode=(
                        str(record["mode"])
                        if isinstance(record.get("mode"), str)
                        else None
                    ),
                    priority=(
                        int(record["priority"])
                        if isinstance(record.get("priority"), int)
                        and not isinstance(record.get("priority"), bool)
                        else None
                    ),
                    inherit_id=inherit_id,
                    key=(
                        str(record["key"])
                        if isinstance(record.get("key"), str)
                        else None
                    ),
                    active=(
                        bool(record["active"])
                        if isinstance(record.get("active"), bool)
                        else None
                    ),
                    arch_db=(
                        str(record["arch_db"])
                        if isinstance(record.get("arch_db"), str)
                        else None
                    ),
                )
            )

        records.sort(
            key=lambda item: (
                item.view_type,
                0 if item.mode == "primary" and not item.inherit_id else 1,
                item.priority if item.priority is not None else 9999,
                item.id,
            )
        )
        primary_views = [
            record
            for record in records
            if record.mode == "primary" and not record.inherit_id
        ]
        extension_views = [record for record in records if record not in primary_views]
        view_counts = {
            "total": len(records),
            "primary": len(primary_views),
            "extension": len(extension_views),
        }
        for view_type in sorted(
            {record.view_type for record in records} | normalized_types
        ):
            view_counts[view_type] = sum(
                1 for record in records if record.view_type == view_type
            )

        if not records:
            remediation.append(
                "No views were found for the model in the selected database."
            )

        return ModelViewInventory(
            model=model,
            requested_types=requested_types,
            primary_views=primary_views,
            extension_views=extension_views,
            view_counts=view_counts,
            database=database,
            warnings=warnings,
            remediation=remediation,
        )

    def get_models_documentation_runtime(
        self,
        models: list[str],
        *,
        attributes: list[str] | tuple[str, ...] | None = None,
        view_types: list[str] | tuple[str, ...] | None = None,
        include_arch: bool = False,
        database: str | None = None,
        timeout: float = 60.0,
    ) -> DocumentationRuntimeInventory:
        """Return batched model field/view runtime metadata for docs generation."""
        selected_models = [model for model in dict.fromkeys(models) if model]
        requested_attributes = [
            item for item in dict.fromkeys(attributes or []) if item
        ]
        requested_view_types = [
            item for item in dict.fromkeys(view_types or []) if item
        ]
        fields_by_model: dict[str, ModelFieldsResult] = {
            model: ModelFieldsResult(
                success=True,
                operation="get_model_fields",
                model=model,
                attributes=requested_attributes or None,
                field_names=[],
                field_definitions={},
                database=database,
            )
            for model in selected_models
        }
        views_by_model: dict[str, ModelViewInventory] = {
            model: ModelViewInventory(
                model=model,
                requested_types=requested_view_types,
                primary_views=[],
                extension_views=[],
                view_counts={"total": 0, "primary": 0, "extension": 0},
                database=database,
            )
            for model in selected_models
        }
        warnings: list[str] = []
        remediation: list[str] = []
        if not selected_models:
            return DocumentationRuntimeInventory(
                models=fields_by_model,
                views=views_by_model,
                warnings=[],
                remediation=[],
            )

        field_query_fields = ["model", "name"]
        field_query_fields.extend(
            item
            for item in requested_attributes
            if item and item not in {"model", "name"}
        )
        field_result = self.operations.query_model(
            "ir.model.fields",
            domain=[["model", "in", selected_models]],
            fields=field_query_fields,
            limit=10000,
            database=database,
            timeout=timeout,
        )
        if not field_result.success:
            if field_result.error:
                warnings.append(
                    "Failed to query runtime field metadata batch: "
                    f"{field_result.error}"
                )
            remediation.append(
                "Verify database access if runtime field metadata is required."
            )
        else:
            grouped_field_names: dict[str, list[str]] = {
                model: [] for model in selected_models
            }
            grouped_field_defs: dict[str, dict[str, dict[str, Any]]] = {
                model: {} for model in selected_models
            }
            for record in field_result.records:
                model_name = record.get("model")
                field_name = record.get("name")
                if (
                    not isinstance(model_name, str)
                    or model_name not in grouped_field_defs
                ):
                    continue
                if not isinstance(field_name, str) or not field_name:
                    continue
                grouped_field_names[model_name].append(field_name)
                grouped_field_defs[model_name][field_name] = {
                    attribute: record.get(attribute)
                    for attribute in requested_attributes
                    if attribute in record
                }
            for model_name in selected_models:
                unique_names = list(dict.fromkeys(grouped_field_names[model_name]))
                fields_by_model[model_name] = ModelFieldsResult(
                    success=True,
                    operation="get_model_fields",
                    model=model_name,
                    attributes=requested_attributes or None,
                    field_names=unique_names,
                    field_definitions=grouped_field_defs[model_name],
                    database=database,
                )

        view_fields = [
            "id",
            "model",
            "name",
            "type",
            "mode",
            "priority",
            "inherit_id",
            "key",
            "active",
        ]
        if include_arch:
            view_fields.append("arch_db")
        views_result = self.operations.query_model(
            "ir.ui.view",
            domain=[["model", "in", selected_models]],
            fields=view_fields,
            limit=10000,
            database=database,
            timeout=timeout,
        )
        if not views_result.success:
            if views_result.error:
                warnings.append(
                    f"Failed to query runtime view metadata batch: {views_result.error}"
                )
            remediation.append("Verify database access and retry runtime view queries.")
        else:
            grouped_views: dict[str, list[ModelViewRecord]] = {
                model: [] for model in selected_models
            }
            normalized_types = set(requested_view_types)
            for record in views_result.records:
                model_name = record.get("model")
                raw_type = record.get("type")
                if not isinstance(model_name, str) or model_name not in grouped_views:
                    continue
                if not isinstance(raw_type, str):
                    continue
                if normalized_types and raw_type not in normalized_types:
                    continue
                raw_inherit_id = record.get("inherit_id")
                inherit_id = (
                    list(raw_inherit_id) if isinstance(raw_inherit_id, list) else None
                )
                grouped_views[model_name].append(
                    ModelViewRecord(
                        id=int(record.get("id", 0) or 0),
                        name=str(record.get("name", "")),
                        view_type=raw_type,
                        mode=str(record["mode"])
                        if isinstance(record.get("mode"), str)
                        else None,
                        priority=(
                            int(record["priority"])
                            if isinstance(record.get("priority"), int)
                            and not isinstance(record.get("priority"), bool)
                            else None
                        ),
                        inherit_id=inherit_id,
                        key=str(record["key"])
                        if isinstance(record.get("key"), str)
                        else None,
                        active=(
                            bool(record["active"])
                            if isinstance(record.get("active"), bool)
                            else None
                        ),
                        arch_db=(
                            str(record["arch_db"])
                            if isinstance(record.get("arch_db"), str)
                            else None
                        ),
                    )
                )
            for model_name in selected_models:
                model_records = grouped_views[model_name]
                model_records.sort(
                    key=lambda item: (
                        item.view_type,
                        0 if item.mode == "primary" and not item.inherit_id else 1,
                        item.priority if item.priority is not None else 9999,
                        item.id,
                    )
                )
                primary_views = [
                    record
                    for record in model_records
                    if record.mode == "primary" and not record.inherit_id
                ]
                extension_views = [
                    record for record in model_records if record not in primary_views
                ]
                view_counts = {
                    "total": len(model_records),
                    "primary": len(primary_views),
                    "extension": len(extension_views),
                }
                for view_type in sorted(
                    {record.view_type for record in model_records} | normalized_types
                ):
                    view_counts[view_type] = sum(
                        1 for record in model_records if record.view_type == view_type
                    )
                views_by_model[model_name] = ModelViewInventory(
                    model=model_name,
                    requested_types=requested_view_types,
                    primary_views=primary_views,
                    extension_views=extension_views,
                    view_counts=view_counts,
                    database=database,
                    warnings=[],
                    remediation=(
                        ["No views were found for the model in the selected database."]
                        if not model_records
                        else []
                    ),
                )

        return DocumentationRuntimeInventory(
            models=fields_by_model,
            views=views_by_model,
            warnings=sorted(dict.fromkeys(warnings)),
            remediation=sorted(dict.fromkeys(remediation)),
        )
