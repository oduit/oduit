from __future__ import annotations

from collections import defaultdict
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any

from manifestoo_core.odoo_series import OdooSeries

from ..api_models import (
    AddonContributionSummary,
    AddonDocumentation,
    AddonDocumentationModel,
    AddonInfo,
    AddonInstallState,
    DependencyGraphDocumentation,
    DocumentationDiagram,
    ModelDocumentation,
    ModelExtensionInventory,
    ModelFieldsResult,
    MultiAddonDocumentation,
    SharedModelDocumentation,
)
from ..documentation_renderer import (
    build_addon_sections,
    build_dependency_graph_sections,
    build_model_sections,
    render_addon_markdown,
    render_addon_markdown_deduplicated,
    render_addon_model_graph_mermaid,
    render_dependency_graph_markdown,
    render_dependency_graph_mermaid,
    render_model_inheritance_mermaid,
    render_model_markdown,
    render_multi_addon_index_markdown,
    render_shared_model_markdown,
)
from ..source_locator import list_addon_languages, list_model_extensions
from .base import OperationsService


def _unique_strings(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


PATH_STRING_FIELDS = {"addon_root", "module_path", "path"}
PATH_LIST_FIELDS = {"paths", "related_files", "related_paths", "scanned_python_files"}


def _normalize_path_prefix(path_prefix: str | None) -> Path | None:
    if not path_prefix:
        return None
    prefix = Path(path_prefix).expanduser()
    if not prefix.is_absolute():
        prefix = (Path.cwd() / prefix).resolve(strict=False)
    return prefix


def _relativize_path(value: str, *, path_prefix: Path | None) -> str:
    if path_prefix is None or not value:
        return value

    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        return value

    try:
        relative = candidate.relative_to(path_prefix)
    except ValueError:
        return candidate.as_posix()

    relative_value = relative.as_posix()
    return relative_value or "."


def _normalize_path_list(
    values: list[Any],
    *,
    path_prefix: Path | None,
) -> list[Any]:
    normalized: list[Any] = []
    for item in values:
        if isinstance(item, str):
            normalized.append(_relativize_path(item, path_prefix=path_prefix))
        else:
            _apply_path_prefix(item, path_prefix=path_prefix)
            normalized.append(item)
    return normalized


def _apply_path_prefix(value: Any, *, path_prefix: Path | None) -> None:
    if path_prefix is None:
        return

    if isinstance(value, dict):
        for key, item in value.items():
            if key in PATH_STRING_FIELDS and isinstance(item, str):
                value[key] = _relativize_path(item, path_prefix=path_prefix)
                continue
            if key in PATH_LIST_FIELDS and isinstance(item, list):
                value[key] = _normalize_path_list(item, path_prefix=path_prefix)
                continue
            _apply_path_prefix(item, path_prefix=path_prefix)
        return

    if isinstance(value, list):
        for item in value:
            _apply_path_prefix(item, path_prefix=path_prefix)
        return

    if not is_dataclass(value):
        return

    for data_field in fields(value):
        current = getattr(value, data_field.name)
        if data_field.name in PATH_STRING_FIELDS and isinstance(current, str):
            setattr(
                value,
                data_field.name,
                _relativize_path(current, path_prefix=path_prefix),
            )
            continue
        if data_field.name in PATH_LIST_FIELDS and isinstance(current, list):
            setattr(
                value,
                data_field.name,
                _normalize_path_list(current, path_prefix=path_prefix),
            )
            continue
        _apply_path_prefix(current, path_prefix=path_prefix)


def _filter_extension_inventory(
    inventory: ModelExtensionInventory,
    *,
    source_modules: set[str],
) -> tuple[ModelExtensionInventory, list[str]]:
    omitted_modules = sorted(
        {
            item.module
            for item in inventory.base_declarations
            if item.module not in source_modules
        }
        | {
            item.module
            for item in inventory.source_extensions
            if item.module not in source_modules
        }
        | {
            item.module
            for item in inventory.source_view_extensions
            if item.module not in source_modules
        }
    )
    filtered_base_declarations = [
        item for item in inventory.base_declarations if item.module in source_modules
    ]
    filtered_source_extensions = [
        item for item in inventory.source_extensions if item.module in source_modules
    ]
    filtered_source_view_extensions = [
        item
        for item in inventory.source_view_extensions
        if item.module in source_modules
    ]
    return (
        ModelExtensionInventory(
            model=inventory.model,
            base_declarations=filtered_base_declarations,
            source_extensions=filtered_source_extensions,
            source_extension_modules=sorted(
                {item.module for item in filtered_source_extensions}
            ),
            installed_fields=list(inventory.installed_fields),
            installed_extension_fields=list(inventory.installed_extension_fields),
            source_view_extensions=filtered_source_view_extensions,
            installed_view_extensions=list(inventory.installed_view_extensions),
            installed_extension_modules=list(inventory.installed_extension_modules),
            scanned_python_files=list(inventory.scanned_python_files),
            warnings=list(inventory.warnings),
            remediation=list(inventory.remediation),
        ),
        omitted_modules,
    )


class DocumentationOperationsService(OperationsService):
    """Documentation bundle assembly on top of existing inspection services."""

    DEFAULT_FIELD_ATTRIBUTES = [
        "string",
        "type",
        "required",
        "readonly",
        "store",
        "relation",
    ]

    def build_addon_documentation(
        self,
        module_name: str,
        *,
        odoo_series: OdooSeries | None = None,
        database: str | None = None,
        timeout: float = 30.0,
        source_only: bool = False,
        include_arch: bool = False,
        field_attributes: list[str] | tuple[str, ...] | None = None,
        view_types: list[str] | tuple[str, ...] | None = None,
        max_models: int | None = None,
        max_fields_per_model: int | None = None,
        path_prefix: str | None = None,
    ) -> AddonDocumentation:
        """Build one addon documentation bundle."""
        requested_field_attributes = list(
            field_attributes or self.DEFAULT_FIELD_ATTRIBUTES
        )
        requested_view_types = list(view_types or [])
        inspection = self.operations.inspect_addon(
            module_name,
            odoo_series=odoo_series,
        )
        model_inventory = self.operations.list_addon_models(module_name)
        test_inventory = self.operations.list_addon_tests(module_name)
        dependency_graph = self.operations.dependency_graph([module_name])
        addon_root = inspection.module_path or model_inventory.addon_root
        languages, language_warnings = list_addon_languages(addon_root)
        addon_info = self._build_addon_info(
            inspection=inspection,
            model_inventory=model_inventory,
            test_inventory=test_inventory,
            addon_root=addon_root,
            languages=languages,
            source_only=source_only,
            database=database,
            timeout=timeout,
        )

        duplicate_modules = self.operations.list_duplicates()
        warnings = list(addon_info.warnings) + list(model_inventory.warnings)
        warnings.extend(test_inventory.warnings)
        warnings.extend(language_warnings)
        remediation = list(addon_info.remediation) + list(model_inventory.remediation)
        remediation.extend(test_inventory.remediation)
        if module_name in duplicate_modules:
            warnings.append(
                "Duplicate addon names were found across configured addon paths for "
                f"`{module_name}`."
            )
            remediation.append(
                "Remove or reorder duplicate addon paths so documentation resolves the "
                "expected addon root unambiguously."
            )

        grouped_entries: dict[str, list[Any]] = defaultdict(list)
        for entry in model_inventory.models:
            grouped_entries[entry.model].append(entry)

        model_names = sorted(grouped_entries)
        if max_models is not None and max_models >= 0:
            model_names = model_names[:max_models]
            if model_inventory.model_count > len(model_names):
                warnings.append(
                    "Model details were limited to the first "
                    f"{len(model_names)} model(s)."
                )

        documented_models: list[AddonDocumentationModel] = []
        for model_name in model_names:
            entries = sorted(
                grouped_entries[model_name],
                key=lambda item: (item.relation_kind, item.path, item.class_name),
            )
            model_doc = self.build_model_documentation(
                model_name,
                database=database,
                timeout=timeout,
                source_only=source_only,
                include_arch=include_arch,
                field_attributes=requested_field_attributes,
                view_types=requested_view_types,
                max_fields=max_fields_per_model,
                path_prefix=path_prefix,
            )
            warnings.extend(model_doc.warnings)
            remediation.extend(model_doc.remediation)
            relation_kinds = _unique_strings([entry.relation_kind for entry in entries])
            documented_models.append(
                AddonDocumentationModel(
                    model=model_name,
                    relation_kinds=relation_kinds,
                    source_entries=entries,
                    documentation=model_doc,
                )
            )

        diagrams: list[DocumentationDiagram] = [
            render_dependency_graph_mermaid(
                dependency_graph,
                title=f"Dependency graph: {module_name}",
            )
        ]
        if model_inventory.models:
            diagrams.append(
                render_addon_model_graph_mermaid(
                    module_name,
                    model_inventory.models,
                    title=f"Model graph: {module_name}",
                )
            )

        recommended_tests = self.operations.recommend_tests(module_name, [])
        bundle = AddonDocumentation(
            module=module_name,
            database=database,
            source_only=source_only,
            addon_info=addon_info,
            dependency_graph=dependency_graph,
            model_inventory=model_inventory,
            models=documented_models,
            recommended_tests=recommended_tests,
            diagrams=diagrams,
            warnings=_unique_strings(warnings + dependency_graph.get("warnings", [])),
            remediation=_unique_strings(remediation),
        )
        _apply_path_prefix(
            bundle,
            path_prefix=_normalize_path_prefix(path_prefix),
        )
        bundle.sections = build_addon_sections(bundle)
        bundle.markdown = render_addon_markdown(bundle)
        return bundle

    def build_model_documentation(
        self,
        model: str,
        *,
        database: str | None = None,
        timeout: float = 30.0,
        source_only: bool = False,
        include_arch: bool = False,
        field_attributes: list[str] | tuple[str, ...] | None = None,
        view_types: list[str] | tuple[str, ...] | None = None,
        max_fields: int | None = None,
        source_modules: list[str] | tuple[str, ...] | None = None,
        path_prefix: str | None = None,
    ) -> ModelDocumentation:
        """Build one model documentation bundle."""
        requested_field_attributes = list(
            field_attributes or self.DEFAULT_FIELD_ATTRIBUTES
        )
        requested_view_types = list(view_types or [])
        requested_source_modules = _unique_strings(list(source_modules or []))
        addons_path = self.operations.config.get_required("addons_path")
        extension_inventory = (
            list_model_extensions(addons_path, model)
            if source_only
            else self.operations.find_model_extensions(
                model,
                database=database,
                timeout=timeout,
            )
        )
        if requested_source_modules:
            extension_inventory, omitted_modules = _filter_extension_inventory(
                extension_inventory,
                source_modules=set(requested_source_modules),
            )
        else:
            omitted_modules = []

        field_metadata: ModelFieldsResult | None = None
        view_inventory = None
        warnings = list(extension_inventory.warnings)
        remediation = list(extension_inventory.remediation)
        if omitted_modules:
            warnings.append(
                "Source contributions were limited to selected modules: "
                + ", ".join(requested_source_modules)
            )

        if not source_only:
            field_metadata = self.operations.get_model_fields(
                model,
                attributes=requested_field_attributes,
                database=database,
                timeout=timeout,
            )
            if max_fields is not None and field_metadata.success:
                field_metadata = self._limit_field_metadata(field_metadata, max_fields)
            if not field_metadata.success and field_metadata.error:
                warnings.append(
                    f"Failed to query runtime field metadata: {field_metadata.error}"
                )
                remediation.append(
                    "Verify database access if runtime field metadata is required."
                )

            view_inventory = self.operations.get_model_views(
                model,
                view_types=requested_view_types,
                database=database,
                timeout=timeout,
                include_arch=include_arch,
            )
            warnings.extend(view_inventory.warnings)
            remediation.extend(view_inventory.remediation)
            if view_inventory.error:
                warnings.append(
                    f"Failed to query runtime views: {view_inventory.error}"
                )

        diagrams = [
            render_model_inheritance_mermaid(
                extension_inventory,
                title=f"Model graph: {model}",
            )
        ]
        bundle = ModelDocumentation(
            model=model,
            database=database,
            source_only=source_only,
            field_attributes=requested_field_attributes,
            requested_view_types=requested_view_types,
            extension_inventory=extension_inventory,
            field_metadata=field_metadata,
            view_inventory=view_inventory,
            diagrams=diagrams,
            warnings=_unique_strings(warnings),
            remediation=_unique_strings(remediation),
        )
        _apply_path_prefix(
            bundle,
            path_prefix=_normalize_path_prefix(path_prefix),
        )
        bundle.sections = build_model_sections(bundle)
        bundle.markdown = render_model_markdown(bundle)
        return bundle

    def build_addons_documentation(
        self,
        module_names: list[str],
        *,
        odoo_series: OdooSeries | None = None,
        database: str | None = None,
        timeout: float = 30.0,
        source_only: bool = False,
        include_arch: bool = False,
        field_attributes: list[str] | tuple[str, ...] | None = None,
        view_types: list[str] | tuple[str, ...] | None = None,
        max_models: int | None = None,
        max_fields_per_model: int | None = None,
        path_prefix: str | None = None,
    ) -> MultiAddonDocumentation:
        """Build one documentation bundle spanning multiple selected addons."""
        requested_field_attributes = list(
            field_attributes or self.DEFAULT_FIELD_ATTRIBUTES
        )
        requested_view_types = list(view_types or [])
        selected_modules = _unique_strings(module_names)
        bundle = MultiAddonDocumentation(
            modules=selected_modules,
            database=database,
            source_only=source_only,
        )
        if not selected_modules:
            bundle.index_markdown = render_multi_addon_index_markdown(bundle)
            return bundle

        module_manager = self.operations._get_module_manager()
        missing_modules = [
            module_name
            for module_name in selected_modules
            if module_manager.find_module_path(module_name) is None
        ]
        if missing_modules:
            missing_list = ", ".join(missing_modules)
            raise ModuleNotFoundError(
                f"Modules not found in addons_path: {missing_list}"
            )

        duplicate_modules = self.operations.list_duplicates()
        addon_contexts: dict[str, dict[str, Any]] = {}
        warnings: list[str] = []
        remediation: list[str] = []

        for module_name in selected_modules:
            inspection = self.operations.inspect_addon(
                module_name,
                odoo_series=odoo_series,
            )
            model_inventory = self.operations.list_addon_models(module_name)
            test_inventory = self.operations.list_addon_tests(module_name)
            dependency_graph = self.operations.dependency_graph([module_name])
            addon_root = inspection.module_path or model_inventory.addon_root
            languages, language_warnings = list_addon_languages(addon_root)
            addon_info = self._build_addon_info(
                inspection=inspection,
                model_inventory=model_inventory,
                test_inventory=test_inventory,
                addon_root=addon_root,
                languages=languages,
                source_only=source_only,
                database=database,
                timeout=timeout,
            )
            addon_warnings = list(addon_info.warnings) + list(model_inventory.warnings)
            addon_warnings.extend(test_inventory.warnings)
            addon_warnings.extend(language_warnings)
            addon_remediation = list(addon_info.remediation) + list(
                model_inventory.remediation
            )
            addon_remediation.extend(test_inventory.remediation)
            if module_name in duplicate_modules:
                addon_warnings.append(
                    "Duplicate addon names were found across configured addon paths "
                    "for "
                    f"`{module_name}`."
                )
                addon_remediation.append(
                    "Remove or reorder duplicate addon paths so documentation resolves "
                    "the expected addon root unambiguously."
                )

            addon_contexts[module_name] = {
                "addon_info": addon_info,
                "dependency_graph": dependency_graph,
                "model_inventory": model_inventory,
                "recommended_tests": self.operations.recommend_tests(module_name, []),
                "warnings": _unique_strings(
                    addon_warnings + dependency_graph.get("warnings", [])
                ),
                "remediation": _unique_strings(addon_remediation),
            }
            warnings.extend(addon_contexts[module_name]["warnings"])
            remediation.extend(addon_contexts[module_name]["remediation"])

        model_to_entries, shared_model_names = self._classify_models_across_addons(
            {
                module_name: addon_contexts[module_name]["model_inventory"]
                for module_name in selected_modules
            }
        )

        shared_models: dict[str, SharedModelDocumentation] = {}
        for model_name in sorted(shared_model_names):
            shared_doc = self._build_shared_model_documentation(
                model_name,
                entries=model_to_entries[model_name],
                selected_modules=selected_modules,
                database=database,
                timeout=timeout,
                source_only=source_only,
                include_arch=include_arch,
                field_attributes=requested_field_attributes,
                view_types=requested_view_types,
                max_fields_per_model=max_fields_per_model,
                path_prefix=path_prefix,
            )
            shared_models[model_name] = shared_doc
            if shared_doc.documentation is not None:
                warnings.extend(shared_doc.documentation.warnings)
                remediation.extend(shared_doc.documentation.remediation)

        addon_docs: list[AddonDocumentation] = []
        normalized_path_prefix = _normalize_path_prefix(path_prefix)
        for module_name in selected_modules:
            context = addon_contexts[module_name]
            model_inventory = context["model_inventory"]
            grouped_entries: dict[str, list[Any]] = defaultdict(list)
            for entry in model_inventory.models:
                grouped_entries[entry.model].append(entry)

            model_names = sorted(grouped_entries)
            addon_warnings = list(context["warnings"])
            addon_remediation = list(context["remediation"])
            if max_models is not None and max_models >= 0:
                original_count = len(model_names)
                model_names = model_names[:max_models]
                if original_count > len(model_names):
                    addon_warnings.append(
                        "Model details were limited to the first "
                        f"{len(model_names)} model(s)."
                    )

            documented_models: list[AddonDocumentationModel] = []
            shared_contributions: list[AddonContributionSummary] = []
            for model_name in model_names:
                entries = sorted(
                    grouped_entries[model_name],
                    key=lambda item: (item.relation_kind, item.path, item.class_name),
                )
                relation_kinds = _unique_strings(
                    [entry.relation_kind for entry in entries]
                )
                if model_name in shared_models:
                    shared_contributions.append(
                        self._build_addon_contribution_summary(
                            module_name,
                            model_name,
                            entries,
                            shared_output_path=shared_models[model_name].output_path,
                        )
                    )
                    continue

                model_doc = self.build_model_documentation(
                    model_name,
                    database=database,
                    timeout=timeout,
                    source_only=source_only,
                    include_arch=include_arch,
                    field_attributes=requested_field_attributes,
                    view_types=requested_view_types,
                    max_fields=max_fields_per_model,
                    source_modules=selected_modules,
                    path_prefix=path_prefix,
                )
                addon_warnings.extend(model_doc.warnings)
                addon_remediation.extend(model_doc.remediation)
                documented_models.append(
                    AddonDocumentationModel(
                        model=model_name,
                        relation_kinds=relation_kinds,
                        source_entries=entries,
                        documentation=model_doc,
                    )
                )

            diagrams: list[DocumentationDiagram] = [
                render_dependency_graph_mermaid(
                    context["dependency_graph"],
                    title=f"Dependency graph: {module_name}",
                )
            ]
            if model_inventory.models:
                diagrams.append(
                    render_addon_model_graph_mermaid(
                        module_name,
                        model_inventory.models,
                        title=f"Model graph: {module_name}",
                    )
                )

            addon_bundle = AddonDocumentation(
                module=module_name,
                database=database,
                source_only=source_only,
                addon_info=context["addon_info"],
                dependency_graph=context["dependency_graph"],
                model_inventory=model_inventory,
                models=documented_models,
                shared_model_contributions=shared_contributions,
                recommended_tests=context["recommended_tests"],
                diagrams=diagrams,
                output_path=f"addons/{module_name}.md",
                warnings=_unique_strings(addon_warnings),
                remediation=_unique_strings(addon_remediation),
            )
            _apply_path_prefix(addon_bundle, path_prefix=normalized_path_prefix)
            addon_bundle.markdown = render_addon_markdown_deduplicated(addon_bundle)
            addon_docs.append(addon_bundle)
            warnings.extend(addon_bundle.warnings)
            remediation.extend(addon_bundle.remediation)

        bundle = MultiAddonDocumentation(
            modules=selected_modules,
            database=database,
            source_only=source_only,
            addon_docs=addon_docs,
            shared_models=[shared_models[name] for name in sorted(shared_models)],
            warnings=_unique_strings(warnings),
            remediation=_unique_strings(remediation),
        )
        bundle.index_markdown = render_multi_addon_index_markdown(bundle)
        return bundle

    def build_dependency_graph_documentation(
        self,
        module_names: list[str],
        *,
        database: str | None = None,
        timeout: float = 30.0,
        source_only: bool = False,
        installed_only: bool = False,
        transitive: bool = True,
        path_prefix: str | None = None,
    ) -> DependencyGraphDocumentation:
        """Build dependency-graph documentation for one or more addons."""
        normalized_modules = _unique_strings(module_names)
        dependency_graph = (
            self.operations.dependency_graph(normalized_modules)
            if transitive
            else self._build_direct_dependency_graph(normalized_modules)
        )
        installed_addons = None
        warnings = list(dependency_graph.get("warnings", []))
        remediation: list[str] = []

        if installed_only and not source_only:
            installed_addons = self.operations.list_installed_addons(
                modules=dependency_graph.get("nodes", []),
                states=["installed"],
                database=database,
                timeout=timeout,
            )
            if installed_addons.success:
                installed_modules = {addon.module for addon in installed_addons.addons}
                dependency_graph = self._filter_graph_to_modules(
                    dependency_graph,
                    installed_modules,
                )
            else:
                warnings.append(
                    "Failed to filter the dependency graph to installed addons only."
                )
                if installed_addons.error:
                    warnings.append(installed_addons.error)
                remediation.extend(installed_addons.remediation)

        bundle = DependencyGraphDocumentation(
            modules=normalized_modules,
            database=database,
            source_only=source_only,
            installed_only=installed_only,
            transitive=transitive,
            dependency_graph=dependency_graph,
            installed_addons=installed_addons,
            diagrams=[
                render_dependency_graph_mermaid(
                    dependency_graph,
                    title="Dependency graph",
                )
            ],
            warnings=_unique_strings(warnings),
            remediation=_unique_strings(remediation),
        )
        _apply_path_prefix(
            bundle,
            path_prefix=_normalize_path_prefix(path_prefix),
        )
        bundle.sections = build_dependency_graph_sections(bundle)
        bundle.markdown = render_dependency_graph_markdown(bundle)
        return bundle

    def _build_addon_info(
        self,
        *,
        inspection: Any,
        model_inventory: Any,
        test_inventory: Any,
        addon_root: str,
        languages: list[str],
        source_only: bool,
        database: str | None,
        timeout: float,
    ) -> AddonInfo:
        manifest = inspection.manifest
        installed_state: AddonInstallState | None = None
        warnings = list(inspection.warnings)
        remediation = list(inspection.remediation)
        if not source_only:
            installed_state = self.operations.get_addon_install_state(
                inspection.module,
                database=database,
                timeout=timeout,
            )
            if not installed_state.success and installed_state.error:
                warnings.append(
                    f"Failed to query runtime install state: {installed_state.error}"
                )
                remediation.append(
                    "Verify database access if installed-state enrichment is required."
                )

        declared_models = sorted(
            {
                entry.model
                for entry in model_inventory.models
                if entry.relation_kind == "declares"
            }
        )
        inherited_models = _unique_strings(
            [
                inherited_model
                for entry in model_inventory.models
                for inherited_model in (
                    list(entry.inherited_models) + list(entry.delegated_models)
                )
            ]
        )
        return AddonInfo(
            module=inspection.module,
            module_path=inspection.module_path,
            addon_type=inspection.addon_type,
            version_display=inspection.version_display,
            summary=str(manifest.get("summary") or ""),
            description=str(manifest.get("description") or ""),
            license=str(manifest.get("license") or ""),
            depends=list(inspection.direct_dependencies),
            reverse_dependencies=list(inspection.reverse_dependencies),
            reverse_dependency_count=inspection.reverse_dependency_count,
            missing_dependencies=list(inspection.missing_dependencies),
            installable=bool(manifest.get("installable", True)),
            auto_install=bool(manifest.get("auto_install", False)),
            models=declared_models,
            inherit_models=inherited_models,
            model_count=model_inventory.model_count,
            test_cases=list(test_inventory.tests),
            test_count=len(test_inventory.tests),
            languages=list(languages),
            installed_state=installed_state,
            warnings=_unique_strings(warnings),
            remediation=_unique_strings(remediation),
        )

    def _limit_field_metadata(
        self,
        field_metadata: ModelFieldsResult,
        max_fields: int,
    ) -> ModelFieldsResult:
        if max_fields < 0 or len(field_metadata.field_names) <= max_fields:
            return field_metadata
        limited_field_names = field_metadata.field_names[:max_fields]
        return ModelFieldsResult(
            success=field_metadata.success,
            operation=field_metadata.operation,
            model=field_metadata.model,
            attributes=field_metadata.attributes,
            field_names=limited_field_names,
            field_definitions={
                name: field_metadata.field_definitions[name]
                for name in limited_field_names
                if name in field_metadata.field_definitions
            },
            database=field_metadata.database,
            error=field_metadata.error,
            error_type=field_metadata.error_type,
        )

    def _classify_models_across_addons(
        self,
        inventories: dict[str, Any],
    ) -> tuple[dict[str, list[tuple[str, Any]]], set[str]]:
        model_to_entries: dict[str, list[tuple[str, Any]]] = defaultdict(list)
        for module_name, inventory in inventories.items():
            for entry in inventory.models:
                model_to_entries[entry.model].append((module_name, entry))

        shared_model_names: set[str] = set()
        for model_name, contributions in model_to_entries.items():
            contributing_modules = {module for module, _ in contributions}
            declaring_modules = {
                module
                for module, entry in contributions
                if entry.relation_kind == "declares"
            }
            if len(contributing_modules) > 1 or not declaring_modules:
                shared_model_names.add(model_name)

        for _model_name, entries in model_to_entries.items():
            entries.sort(
                key=lambda item: (
                    item[0],
                    item[1].relation_kind,
                    item[1].path,
                    item[1].class_name,
                )
            )
        return model_to_entries, shared_model_names

    def _build_shared_model_documentation(
        self,
        model_name: str,
        *,
        entries: list[tuple[str, Any]],
        selected_modules: list[str],
        database: str | None,
        timeout: float,
        source_only: bool,
        include_arch: bool,
        field_attributes: list[str],
        view_types: list[str],
        max_fields_per_model: int | None,
        path_prefix: str | None,
    ) -> SharedModelDocumentation:
        model_doc = self.build_model_documentation(
            model_name,
            database=database,
            timeout=timeout,
            source_only=source_only,
            include_arch=include_arch,
            field_attributes=field_attributes,
            view_types=view_types,
            max_fields=max_fields_per_model,
            source_modules=selected_modules,
            path_prefix=path_prefix,
        )
        shared_doc = SharedModelDocumentation(
            model=model_name,
            owning_modules=sorted(
                {
                    module
                    for module, entry in entries
                    if entry.relation_kind == "declares"
                }
            ),
            contributing_modules=sorted({module for module, _ in entries}),
            documentation=model_doc,
            output_path=f"models/{self._sanitize_model_doc_filename(model_name)}",
        )
        shared_doc.markdown = render_shared_model_markdown(shared_doc)
        return shared_doc

    def _build_addon_contribution_summary(
        self,
        module_name: str,
        model_name: str,
        entries: list[Any],
        *,
        shared_output_path: str | None,
    ) -> AddonContributionSummary:
        return AddonContributionSummary(
            model=model_name,
            module=module_name,
            relation_kinds=_unique_strings([entry.relation_kind for entry in entries]),
            class_names=_unique_strings([entry.class_name for entry in entries]),
            added_fields=_unique_strings(
                [field_name for entry in entries for field_name in entry.added_fields]
            ),
            added_methods=_unique_strings(
                [
                    method_name
                    for entry in entries
                    for method_name in entry.added_methods
                ]
            ),
            source_paths=_unique_strings([entry.path for entry in entries]),
            line_hints=sorted(
                {
                    entry.line_hint
                    for entry in entries
                    if isinstance(entry.line_hint, int)
                }
            ),
            shared_model_doc_path=(
                f"../{shared_output_path}" if shared_output_path is not None else None
            ),
        )

    def _sanitize_model_doc_filename(self, model_name: str) -> str:
        return f"{model_name}.md"

    def _build_direct_dependency_graph(self, module_names: list[str]) -> dict[str, Any]:
        module_manager = self.operations._get_module_manager()
        edges: list[dict[str, str]] = []
        nodes: set[str] = set(module_names)
        missing_dependencies: dict[str, list[str]] = {}
        warnings: list[str] = []
        for module_name in module_names:
            try:
                dependencies = sorted(
                    module_manager.get_direct_dependencies(module_name)
                )
            except ValueError as exc:
                warnings.append(str(exc))
                dependencies = []
            missing_dependencies[module_name] = (
                module_manager.find_missing_dependencies(module_name)
            )
            for dependency in dependencies:
                nodes.add(dependency)
                edges.append({"source": module_name, "target": dependency})
        return {
            "modules": module_names,
            "nodes": sorted(nodes),
            "edges": sorted(edges, key=lambda item: (item["source"], item["target"])),
            "missing_dependencies": missing_dependencies,
            "cycles": [],
            "install_order": [],
            "warnings": warnings,
        }

    def _filter_graph_to_modules(
        self,
        graph: dict[str, Any],
        allowed_modules: set[str],
    ) -> dict[str, Any]:
        filtered_edges = [
            edge
            for edge in graph.get("edges", [])
            if isinstance(edge, dict)
            and edge.get("source") in allowed_modules
            and edge.get("target") in allowed_modules
        ]
        filtered_nodes = sorted(
            {
                node
                for node in graph.get("nodes", [])
                if isinstance(node, str) and node in allowed_modules
            }
            | {
                edge[key]
                for edge in filtered_edges
                for key in ("source", "target")
                if isinstance(edge.get(key), str)
            }
        )
        filtered_missing = {
            module: [
                dependency
                for dependency in dependencies
                if dependency in allowed_modules
            ]
            for module, dependencies in graph.get("missing_dependencies", {}).items()
            if module in allowed_modules and isinstance(dependencies, list)
        }
        return {
            **graph,
            "nodes": filtered_nodes,
            "edges": filtered_edges,
            "missing_dependencies": filtered_missing,
        }
