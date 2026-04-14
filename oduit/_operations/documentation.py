from __future__ import annotations

from collections import defaultdict
from typing import Any

from manifestoo_core.odoo_series import OdooSeries

from ..api_models import (
    AddonDocumentation,
    AddonDocumentationModel,
    AddonInfo,
    AddonInstallState,
    DependencyGraphDocumentation,
    DocumentationDiagram,
    ModelDocumentation,
    ModelFieldsResult,
)
from ..documentation_renderer import (
    build_addon_sections,
    build_dependency_graph_sections,
    build_model_sections,
    render_addon_markdown,
    render_addon_model_graph_mermaid,
    render_dependency_graph_markdown,
    render_dependency_graph_mermaid,
    render_model_inheritance_mermaid,
    render_model_markdown,
)
from ..source_locator import list_addon_languages, list_model_extensions
from .base import OperationsService


def _unique_strings(values: list[str]) -> list[str]:
    return sorted({value for value in values if value})


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
    ) -> ModelDocumentation:
        """Build one model documentation bundle."""
        requested_field_attributes = list(
            field_attributes or self.DEFAULT_FIELD_ATTRIBUTES
        )
        requested_view_types = list(view_types or [])
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

        field_metadata: ModelFieldsResult | None = None
        view_inventory = None
        warnings = list(extension_inventory.warnings)
        remediation = list(extension_inventory.remediation)

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
        bundle.sections = build_model_sections(bundle)
        bundle.markdown = render_model_markdown(bundle)
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
