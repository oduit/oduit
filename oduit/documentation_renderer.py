"""Pure rendering helpers for documentation bundles."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any

from .api_models import (
    AddonContributionSummary,
    AddonDocumentation,
    AddonModelEntry,
    DependencyGraphDocumentation,
    DocumentationDiagram,
    DocumentSection,
    ModelDocumentation,
    ModelExtensionInventory,
    MultiAddonDocumentation,
    SharedModelDocumentation,
)


def _unique_strings(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if value})


def _sanitize_mermaid_identifier(value: str) -> str:
    identifier = re.sub(r"[^0-9A-Za-z_]", "_", value)
    if not identifier:
        identifier = "node"
    if identifier[0].isdigit():
        identifier = f"n_{identifier}"
    return identifier


def _build_mermaid_ids(labels: Sequence[str]) -> dict[str, str]:
    identifiers: dict[str, str] = {}
    used: set[str] = set()
    for label in labels:
        base = _sanitize_mermaid_identifier(label)
        identifier = base
        suffix = 2
        while identifier in used:
            identifier = f"{base}_{suffix}"
            suffix += 1
        identifiers[label] = identifier
        used.add(identifier)
    return identifiers


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    separator = "| " + " | ".join(["---"] * len(headers)) + " |"
    lines = ["| " + " | ".join(headers) + " |", separator]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def _mermaid_block(diagram: DocumentationDiagram | None) -> str:
    if diagram is None or not diagram.content.strip():
        return ""
    return f"```mermaid\n{diagram.content}\n```"


def _bullet_lines(items: Sequence[str]) -> str:
    if not items:
        return "- none"
    return "\n".join(f"- {item}" for item in items)


def _render_field_rows(field_metadata: Any) -> list[list[str]]:
    if field_metadata is None or not getattr(field_metadata, "success", False):
        return []
    rows: list[list[str]] = []
    field_definitions = getattr(field_metadata, "field_definitions", {})
    for field_name in getattr(field_metadata, "field_names", []):
        definition = field_definitions.get(field_name, {})
        rows.append(
            [
                field_name,
                str(definition.get("type", definition.get("ttype", "-"))),
                str(definition.get("string", "-")),
                str(definition.get("required", "-")),
                str(definition.get("readonly", "-")),
                str(definition.get("relation", "-")),
            ]
        )
    return rows


def _render_view_rows(view_inventory: Any) -> list[list[str]]:
    if view_inventory is None:
        return []
    rows: list[list[str]] = []
    for collection_name in ("primary_views", "extension_views"):
        for view in getattr(view_inventory, collection_name, []):
            inherit_id = "-"
            if view.inherit_id:
                inherit_id = str(view.inherit_id[0])
            rows.append(
                [
                    view.name,
                    view.view_type,
                    view.mode or "-",
                    str(view.priority) if view.priority is not None else "-",
                    inherit_id,
                    view.key or "-",
                ]
            )
    return rows


def render_dependency_graph_mermaid(
    graph: dict[str, Any],
    *,
    title: str = "Dependency graph",
) -> DocumentationDiagram:
    """Render a dependency graph as Mermaid."""
    missing_dependencies = graph.get("missing_dependencies", {})
    labels = list(graph.get("nodes", []))
    for values in missing_dependencies.values():
        if isinstance(values, list):
            labels.extend(value for value in values if isinstance(value, str))
    labels = sorted(dict.fromkeys(labels))
    identifier_map = _build_mermaid_ids(labels)

    lines = ["flowchart LR"]
    missing_set = {
        dependency
        for values in missing_dependencies.values()
        if isinstance(values, list)
        for dependency in values
        if isinstance(dependency, str)
    }
    for label in labels:
        rendered_label = f"{label} (missing)" if label in missing_set else label
        lines.append(f'    {identifier_map[label]}["{rendered_label}"]')

    for edge in sorted(
        graph.get("edges", []),
        key=lambda item: (str(item.get("source", "")), str(item.get("target", ""))),
    ):
        source = edge.get("source")
        target = edge.get("target")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        if source not in identifier_map or target not in identifier_map:
            continue
        lines.append(f"    {identifier_map[source]} --> {identifier_map[target]}")

    return DocumentationDiagram(
        kind="dependency_graph",
        title=title,
        format="mermaid",
        content="\n".join(lines),
    )


def render_addon_model_graph_mermaid(
    module: str,
    entries: Sequence[AddonModelEntry],
    *,
    title: str = "Model graph",
) -> DocumentationDiagram:
    """Render addon model relations as Mermaid."""
    labels: set[str] = set()
    node_labels: dict[str, str] = {}
    edges: list[tuple[str, str, str]] = []
    for entry in entries:
        if entry.relation_kind == "declares":
            source_label = entry.model
        else:
            source_label = f"{module}: {entry.class_name}"
        labels.add(source_label)
        node_labels[source_label] = source_label

        inherited_targets = entry.inherited_models or []
        delegated_targets = entry.delegated_models or []
        if entry.relation_kind == "extends" and not inherited_targets:
            inherited_targets = [entry.model]

        for target in inherited_targets:
            labels.add(target)
            node_labels[target] = target
            edge_kind = "extends" if entry.relation_kind != "declares" else "inherits"
            edges.append((source_label, target, edge_kind))
        for target in delegated_targets:
            labels.add(target)
            node_labels[target] = target
            edges.append((source_label, target, "delegates"))

    sorted_labels = sorted(labels)
    identifier_map = _build_mermaid_ids(sorted_labels)
    lines = ["flowchart LR"]
    for label in sorted_labels:
        lines.append(f'    {identifier_map[label]}["{node_labels[label]}"]')
    for source, target, edge_kind in sorted(edges):
        lines.append(
            f"    {identifier_map[source]} -->|{edge_kind}| {identifier_map[target]}"
        )

    return DocumentationDiagram(
        kind="model_graph",
        title=title,
        format="mermaid",
        content="\n".join(lines),
    )


def render_model_inheritance_mermaid(
    inventory: ModelExtensionInventory,
    *,
    title: str | None = None,
) -> DocumentationDiagram:
    """Render cross-addon model declarations and extensions as Mermaid."""
    title = title or f"Model graph: {inventory.model}"
    labels: set[str] = {inventory.model}
    edges: list[tuple[str, str, str]] = []

    for declaration in inventory.base_declarations:
        source_label = declaration.module
        labels.add(source_label)
        edges.append((source_label, inventory.model, "declares"))

    for extension in inventory.source_extensions:
        source_label = f"{extension.module}: {extension.class_name}"
        labels.add(source_label)
        target = inventory.model
        edges.append((source_label, target, extension.relation_kind))
        for inherited_model in extension.inherited_models:
            labels.add(inherited_model)
            if inherited_model != inventory.model:
                edges.append((source_label, inherited_model, "inherits"))
        for delegated_model in extension.delegated_models:
            labels.add(delegated_model)
            edges.append((source_label, delegated_model, "delegates"))

    sorted_labels = sorted(labels)
    identifier_map = _build_mermaid_ids(sorted_labels)
    lines = ["flowchart LR"]
    for label in sorted_labels:
        lines.append(f'    {identifier_map[label]}["{label}"]')
    for source, target, edge_kind in sorted(edges):
        lines.append(
            f"    {identifier_map[source]} -->|{edge_kind}| {identifier_map[target]}"
        )

    return DocumentationDiagram(
        kind="model_inheritance",
        title=title,
        format="mermaid",
        content="\n".join(lines),
    )


def build_model_sections(bundle: ModelDocumentation) -> list[DocumentSection]:
    """Build top-level Markdown sections for one model bundle."""
    sections: list[DocumentSection] = []
    runtime_mode = (
        "source only" if bundle.source_only else (bundle.database or "default")
    )

    summary_lines = [
        f"- model: `{bundle.model}`",
        f"- runtime: `{runtime_mode}`",
        (
            "- source extensions: "
            f"`{len(bundle.extension_inventory.source_extensions)}`"
            if bundle.extension_inventory
            else "- source extensions: `0`"
        ),
        (
            "- base declarations: "
            f"`{len(bundle.extension_inventory.base_declarations)}`"
            if bundle.extension_inventory
            else "- base declarations: `0`"
        ),
    ]
    sections.append(
        DocumentSection(
            title="Summary",
            summary=f"Documentation summary for {bundle.model}",
            order=1,
            markdown="## Summary\n" + "\n".join(summary_lines),
        )
    )

    diagram = next(
        (item for item in bundle.diagrams if item.kind == "model_inheritance"),
        None,
    )
    diagram_block = _mermaid_block(diagram)
    declaration_rows: list[list[str]] = []
    if bundle.extension_inventory is not None:
        for declaration in bundle.extension_inventory.base_declarations:
            declaration_rows.append(
                [
                    declaration.module,
                    declaration.class_name,
                    declaration.path,
                    str(declaration.line_hint or "-"),
                ]
            )
        for extension in bundle.extension_inventory.source_extensions:
            declaration_rows.append(
                [
                    extension.module,
                    extension.class_name,
                    extension.path,
                    str(extension.line_hint or "-"),
                ]
            )
    declaration_table = _markdown_table(
        ["Module", "Class", "Path", "Line"],
        declaration_rows,
    )
    relation_body = "## Source declarations and extensions\n" + (
        declaration_table if declaration_table else "No source declarations found."
    )
    if diagram_block:
        relation_body = relation_body + "\n\n" + diagram_block
    sections.append(
        DocumentSection(
            title="Source declarations and extensions",
            summary="Static source declarations and extensions",
            order=2,
            markdown=relation_body,
        )
    )

    field_rows = _render_field_rows(bundle.field_metadata)
    sections.append(
        DocumentSection(
            title="Field metadata",
            summary="Runtime model field metadata",
            order=3,
            markdown=(
                "## Field metadata\n"
                + (
                    _markdown_table(
                        ["Field", "Type", "Label", "Required", "Readonly", "Relation"],
                        field_rows,
                    )
                    if field_rows
                    else "Runtime field metadata is unavailable."
                )
            ),
        )
    )

    view_rows = _render_view_rows(bundle.view_inventory)
    sections.append(
        DocumentSection(
            title="Views",
            summary="Runtime view inventory",
            order=4,
            markdown=(
                "## Views\n"
                + (
                    _markdown_table(
                        ["Name", "Type", "Mode", "Priority", "Inherit", "Key"],
                        view_rows,
                    )
                    if view_rows
                    else "Runtime view metadata is unavailable."
                )
            ),
        )
    )

    warning_lines = list(bundle.warnings)
    remediation_lines = list(bundle.remediation)
    if warning_lines or remediation_lines:
        markdown = ["## Warnings and remediation"]
        if warning_lines:
            markdown.append("\n### Warnings\n" + _bullet_lines(warning_lines))
        if remediation_lines:
            markdown.append("\n### Remediation\n" + _bullet_lines(remediation_lines))
        sections.append(
            DocumentSection(
                title="Warnings and remediation",
                summary="Warnings and follow-up guidance",
                order=5,
                markdown="\n".join(markdown),
            )
        )
    return sections


def build_addon_sections(bundle: AddonDocumentation) -> list[DocumentSection]:
    """Build top-level Markdown sections for one addon bundle."""
    sections: list[DocumentSection] = []
    addon_info = bundle.addon_info
    if addon_info is None:
        return sections

    installed_state = (
        addon_info.installed_state.state if addon_info.installed_state else "n/a"
    )
    summary_lines = [
        f"- module: `{bundle.module}`",
        f"- path: `{addon_info.module_path or '-'}`",
        f"- version: `{addon_info.version_display}`",
        f"- addon type: `{addon_info.addon_type}`",
        f"- installed state: `{installed_state}`",
        f"- source only: `{'yes' if bundle.source_only else 'no'}`",
    ]
    sections.append(
        DocumentSection(
            title="Summary",
            summary=f"Summary for addon {bundle.module}",
            order=1,
            markdown="## Summary\n" + "\n".join(summary_lines),
        )
    )

    manifest_rows = [
        ["Depends", ", ".join(addon_info.depends) or "-"],
        ["Reverse dependencies", ", ".join(addon_info.reverse_dependencies) or "-"],
        ["Missing dependencies", ", ".join(addon_info.missing_dependencies) or "-"],
        ["Installable", "yes" if addon_info.installable else "no"],
        ["Auto install", "yes" if addon_info.auto_install else "no"],
        ["License", addon_info.license or "-"],
        ["Summary", addon_info.summary or "-"],
    ]
    sections.append(
        DocumentSection(
            title="Manifest",
            summary="Manifest summary",
            order=2,
            markdown="## Manifest\n"
            + _markdown_table(["Field", "Value"], manifest_rows),
        )
    )

    dependency_diagram = next(
        (item for item in bundle.diagrams if item.kind == "dependency_graph"),
        None,
    )
    dependency_rows = [
        [
            edge.get("source", "-"),
            edge.get("target", "-"),
        ]
        for edge in bundle.dependency_graph.get("edges", [])
        if isinstance(edge, dict)
    ]
    dependency_markdown = "## Dependency overview\n"
    dependency_markdown += (
        _markdown_table(["Source", "Target"], dependency_rows)
        if dependency_rows
        else "No dependency edges found."
    )
    dependency_graph_block = _mermaid_block(dependency_diagram)
    if dependency_graph_block:
        dependency_markdown += "\n\n" + dependency_graph_block
    sections.append(
        DocumentSection(
            title="Dependency overview",
            summary="Dependency graph and edge list",
            order=3,
            markdown=dependency_markdown,
        )
    )

    model_rows = [
        [
            item.model,
            ", ".join(item.relation_kinds) or "-",
            (
                ", ".join(sorted({entry.class_name for entry in item.source_entries}))
                or "-"
            ),
        ]
        for item in bundle.models
    ]
    model_diagram = next(
        (item for item in bundle.diagrams if item.kind == "model_graph"),
        None,
    )
    model_markdown = "## Models declared or extended\n"
    model_markdown += (
        _markdown_table(["Model", "Relation kinds", "Classes"], model_rows)
        if model_rows
        else "No Python model declarations or extensions were found."
    )
    model_graph_block = _mermaid_block(model_diagram)
    if model_graph_block:
        model_markdown += "\n\n" + model_graph_block
    sections.append(
        DocumentSection(
            title="Models declared or extended",
            summary="Addon model inventory",
            order=4,
            markdown=model_markdown,
        )
    )

    model_details = ["## Model details"]
    for model_entry in bundle.models:
        model_details.append(f"\n### {model_entry.model}")
        model_details.append(
            f"Relation kinds: {', '.join(model_entry.relation_kinds) or '-'}"
        )
        if model_entry.documentation is not None:
            field_rows = _render_field_rows(model_entry.documentation.field_metadata)
            model_details.append("\n#### Fields")
            model_details.append(
                _markdown_table(
                    ["Field", "Type", "Label", "Required", "Readonly", "Relation"],
                    field_rows,
                )
                if field_rows
                else "Runtime field metadata is unavailable."
            )
            view_rows = _render_view_rows(model_entry.documentation.view_inventory)
            model_details.append("\n#### Views")
            model_details.append(
                _markdown_table(
                    ["Name", "Type", "Mode", "Priority", "Inherit", "Key"],
                    view_rows,
                )
                if view_rows
                else "Runtime view metadata is unavailable."
            )
            source_extension_rows = []
            inventory = model_entry.documentation.extension_inventory
            if inventory is not None:
                for extension in inventory.source_extensions:
                    source_extension_rows.append(
                        [
                            extension.module,
                            extension.class_name,
                            extension.relation_kind,
                            extension.path,
                        ]
                    )
            model_details.append("\n#### Source extensions")
            model_details.append(
                _markdown_table(
                    ["Module", "Class", "Relation", "Path"],
                    source_extension_rows,
                )
                if source_extension_rows
                else "No cross-addon source extensions found."
            )
    sections.append(
        DocumentSection(
            title="Model details",
            summary="Per-model field, view, and extension details",
            order=5,
            markdown="\n".join(model_details),
        )
    )

    tests = (
        bundle.recommended_tests.get("tests", []) if bundle.recommended_tests else []
    )
    test_rows = [
        [
            str(test.get("path", "-")),
            str(test.get("test_type", "-")),
            ", ".join(test.get("ranking_signals", []))
            if isinstance(test.get("ranking_signals"), list)
            else "-",
        ]
        for test in tests
        if isinstance(test, dict)
    ]
    sections.append(
        DocumentSection(
            title="Tests",
            summary="Recommended addon tests",
            order=6,
            markdown=(
                "## Tests\n"
                + (
                    _markdown_table(["Path", "Type", "Signals"], test_rows)
                    if test_rows
                    else "No tests were discovered."
                )
            ),
        )
    )

    warning_lines = list(bundle.warnings)
    remediation_lines = list(bundle.remediation)
    if warning_lines or remediation_lines:
        markdown = ["## Warnings and remediation"]
        if warning_lines:
            markdown.append("\n### Warnings\n" + _bullet_lines(warning_lines))
        if remediation_lines:
            markdown.append("\n### Remediation\n" + _bullet_lines(remediation_lines))
        sections.append(
            DocumentSection(
                title="Warnings and remediation",
                summary="Warnings and follow-up guidance",
                order=7,
                markdown="\n".join(markdown),
            )
        )
    return sections


def build_dependency_graph_sections(
    bundle: DependencyGraphDocumentation,
) -> list[DocumentSection]:
    """Build Markdown sections for dependency graph documentation."""
    sections: list[DocumentSection] = []
    summary_lines = [
        f"- modules: `{', '.join(bundle.modules)}`",
        f"- source only: `{'yes' if bundle.source_only else 'no'}`",
        f"- installed only: `{'yes' if bundle.installed_only else 'no'}`",
        f"- transitive: `{'yes' if bundle.transitive else 'no'}`",
    ]
    sections.append(
        DocumentSection(
            title="Summary",
            summary="Dependency graph summary",
            order=1,
            markdown="## Summary\n" + "\n".join(summary_lines),
        )
    )

    edge_rows = [
        [str(edge.get("source", "-")), str(edge.get("target", "-"))]
        for edge in bundle.dependency_graph.get("edges", [])
        if isinstance(edge, dict)
    ]
    diagram = next(
        (item for item in bundle.diagrams if item.kind == "dependency_graph"),
        None,
    )
    markdown = "## Dependency graph\n"
    markdown += (
        _markdown_table(["Source", "Target"], edge_rows)
        if edge_rows
        else "No dependency edges were found."
    )
    diagram_block = _mermaid_block(diagram)
    if diagram_block:
        markdown += "\n\n" + diagram_block
    sections.append(
        DocumentSection(
            title="Dependency graph",
            summary="Dependency edges and Mermaid diagram",
            order=2,
            markdown=markdown,
        )
    )

    warning_lines = list(bundle.warnings)
    remediation_lines = list(bundle.remediation)
    if warning_lines or remediation_lines:
        warning_markdown = ["## Warnings and remediation"]
        if warning_lines:
            warning_markdown.append("\n### Warnings\n" + _bullet_lines(warning_lines))
        if remediation_lines:
            warning_markdown.append(
                "\n### Remediation\n" + _bullet_lines(remediation_lines)
            )
        sections.append(
            DocumentSection(
                title="Warnings and remediation",
                summary="Warnings and follow-up guidance",
                order=3,
                markdown="\n".join(warning_markdown),
            )
        )
    return sections


def render_model_markdown(bundle: ModelDocumentation) -> str:
    """Render a model documentation bundle as Markdown."""
    sections = bundle.sections or build_model_sections(bundle)
    sorted_sections = sorted(sections, key=lambda item: item.order)
    return "\n\n".join(
        [f"# Model documentation: {bundle.model}"]
        + [section.markdown for section in sorted_sections]
    )


def render_addon_markdown(bundle: AddonDocumentation) -> str:
    """Render an addon documentation bundle as Markdown."""
    sections = bundle.sections or build_addon_sections(bundle)
    sorted_sections = sorted(sections, key=lambda item: item.order)
    return "\n\n".join(
        [f"# Addon documentation: {bundle.module}"]
        + [section.markdown for section in sorted_sections]
    )


def _shared_model_link(
    contribution: AddonContributionSummary,
    *,
    relative_models_dir: str,
) -> str:
    if contribution.shared_model_doc_path:
        return f"[{contribution.model}]({contribution.shared_model_doc_path})"
    return f"[{contribution.model}]({relative_models_dir}/{contribution.model}.md)"


def render_addon_markdown_deduplicated(
    addon_doc: AddonDocumentation,
    *,
    relative_models_dir: str = "../models",
) -> str:
    """Render one addon page for the multi-addon documentation bundle."""
    addon_info = addon_doc.addon_info
    if addon_info is None:
        return f"# Addon documentation: {addon_doc.module}"

    installed_state = (
        addon_info.installed_state.state if addon_info.installed_state else "n/a"
    )
    sections = [
        "## Summary\n"
        + "\n".join(
            [
                f"- module: `{addon_doc.module}`",
                f"- path: `{addon_info.module_path or '-'}`",
                f"- version: `{addon_info.version_display}`",
                f"- addon type: `{addon_info.addon_type}`",
                f"- installed state: `{installed_state}`",
                f"- source only: `{'yes' if addon_doc.source_only else 'no'}`",
                f"- local models inline: `{len(addon_doc.models)}`",
                "- shared models linked: "
                f"`{len(addon_doc.shared_model_contributions)}`",
            ]
        )
    ]

    manifest_rows = [
        ["Depends", ", ".join(addon_info.depends) or "-"],
        ["Reverse dependencies", ", ".join(addon_info.reverse_dependencies) or "-"],
        ["Missing dependencies", ", ".join(addon_info.missing_dependencies) or "-"],
        ["Installable", "yes" if addon_info.installable else "no"],
        ["Auto install", "yes" if addon_info.auto_install else "no"],
        ["License", addon_info.license or "-"],
        ["Summary", addon_info.summary or "-"],
    ]
    sections.append(
        "## Manifest\n" + _markdown_table(["Field", "Value"], manifest_rows)
    )

    dependency_diagram = next(
        (item for item in addon_doc.diagrams if item.kind == "dependency_graph"),
        None,
    )
    dependency_rows = [
        [str(edge.get("source", "-")), str(edge.get("target", "-"))]
        for edge in addon_doc.dependency_graph.get("edges", [])
        if isinstance(edge, dict)
    ]
    dependency_markdown = "## Dependency overview\n"
    dependency_markdown += (
        _markdown_table(["Source", "Target"], dependency_rows)
        if dependency_rows
        else "No dependency edges found."
    )
    dependency_graph_block = _mermaid_block(dependency_diagram)
    if dependency_graph_block:
        dependency_markdown += "\n\n" + dependency_graph_block
    sections.append(dependency_markdown)

    model_rows: list[list[str]] = []
    for model_entry in addon_doc.models:
        model_rows.append(
            [
                model_entry.model,
                ", ".join(model_entry.relation_kinds) or "-",
                (
                    ", ".join(
                        sorted(
                            {entry.class_name for entry in model_entry.source_entries}
                        )
                    )
                    or "-"
                ),
                "inline",
            ]
        )
    for contribution in addon_doc.shared_model_contributions:
        model_rows.append(
            [
                contribution.model,
                ", ".join(contribution.relation_kinds) or "-",
                ", ".join(contribution.class_names) or "-",
                _shared_model_link(
                    contribution,
                    relative_models_dir=relative_models_dir,
                ),
            ]
        )
    sections.append(
        "## Models declared or extended\n"
        + (
            _markdown_table(
                ["Model", "Relation kinds", "Classes", "Detail"], model_rows
            )
            if model_rows
            else "No Python model declarations or extensions were found."
        )
    )

    if addon_doc.models:
        local_model_sections = ["## Local model details"]
        for model_entry in addon_doc.models:
            local_model_sections.append(f"\n### {model_entry.model}")
            local_model_sections.append(
                f"Relation kinds: {', '.join(model_entry.relation_kinds) or '-'}"
            )
            if model_entry.documentation is None:
                local_model_sections.append("No model documentation is available.")
                continue

            model_diagram = next(
                (
                    item
                    for item in model_entry.documentation.diagrams
                    if item.kind == "model_inheritance"
                ),
                None,
            )
            diagram_block = _mermaid_block(model_diagram)
            if diagram_block:
                local_model_sections.append("\n#### Model graph")
                local_model_sections.append(diagram_block)

            field_rows = _render_field_rows(model_entry.documentation.field_metadata)
            local_model_sections.append("\n#### Fields")
            local_model_sections.append(
                _markdown_table(
                    ["Field", "Type", "Label", "Required", "Readonly", "Relation"],
                    field_rows,
                )
                if field_rows
                else "Runtime field metadata is unavailable."
            )

            view_rows = _render_view_rows(model_entry.documentation.view_inventory)
            local_model_sections.append("\n#### Views")
            local_model_sections.append(
                _markdown_table(
                    ["Name", "Type", "Mode", "Priority", "Inherit", "Key"],
                    view_rows,
                )
                if view_rows
                else "Runtime view metadata is unavailable."
            )

            source_extension_rows = []
            inventory = model_entry.documentation.extension_inventory
            if inventory is not None:
                for extension in inventory.source_extensions:
                    source_extension_rows.append(
                        [
                            extension.module,
                            extension.class_name,
                            extension.relation_kind,
                            extension.path,
                        ]
                    )
            local_model_sections.append("\n#### Source extensions")
            local_model_sections.append(
                _markdown_table(
                    ["Module", "Class", "Relation", "Path"],
                    source_extension_rows,
                )
                if source_extension_rows
                else "No cross-addon source extensions found."
            )
        sections.append("\n".join(local_model_sections))

    shared_rows = [
        [
            contribution.model,
            ", ".join(contribution.relation_kinds) or "-",
            ", ".join(contribution.class_names) or "-",
            ", ".join(contribution.added_fields) or "-",
            ", ".join(contribution.added_methods) or "-",
            ", ".join(contribution.source_paths) or "-",
            _shared_model_link(
                contribution,
                relative_models_dir=relative_models_dir,
            ),
        ]
        for contribution in addon_doc.shared_model_contributions
    ]
    sections.append(
        "## Shared model contributions\n"
        + (
            _markdown_table(
                [
                    "Model",
                    "Relation kinds",
                    "Classes",
                    "Added fields",
                    "Added methods",
                    "Paths",
                    "Shared doc",
                ],
                shared_rows,
            )
            if shared_rows
            else "No shared model contributions were found."
        )
    )

    tests = (
        addon_doc.recommended_tests.get("tests", [])
        if addon_doc.recommended_tests
        else []
    )
    test_rows = [
        [
            str(test.get("path", "-")),
            str(test.get("test_type", "-")),
            ", ".join(test.get("ranking_signals", []))
            if isinstance(test.get("ranking_signals"), list)
            else "-",
        ]
        for test in tests
        if isinstance(test, dict)
    ]
    sections.append(
        "## Tests\n"
        + (
            _markdown_table(["Path", "Type", "Signals"], test_rows)
            if test_rows
            else "No tests were discovered."
        )
    )

    if addon_doc.warnings or addon_doc.remediation:
        warning_section = ["## Warnings and remediation"]
        if addon_doc.warnings:
            warning_section.append(
                "\n### Warnings\n" + _bullet_lines(addon_doc.warnings)
            )
        if addon_doc.remediation:
            warning_section.append(
                "\n### Remediation\n" + _bullet_lines(addon_doc.remediation)
            )
        sections.append("\n".join(warning_section))

    return "\n\n".join([f"# Addon documentation: {addon_doc.module}"] + sections)


def render_shared_model_markdown(
    shared: SharedModelDocumentation,
    *,
    relative_addons_dir: str = "../addons",
) -> str:
    """Render one shared model page for the multi-addon bundle."""
    sections = [
        "## Summary\n"
        + "\n".join(
            [
                f"- model: `{shared.model}`",
                "- owning addons: "
                + (
                    f"`{', '.join(shared.owning_modules)}`"
                    if shared.owning_modules
                    else "`external/outside selected scope`"
                ),
                "- contributing addons: "
                + (
                    f"`{', '.join(shared.contributing_modules)}`"
                    if shared.contributing_modules
                    else "`-`"
                ),
            ]
        )
    ]

    backlink_rows = [
        [
            module,
            "owner" if module in shared.owning_modules else "contributor",
            f"[{module}]({relative_addons_dir}/{module}.md)",
        ]
        for module in shared.contributing_modules
    ]
    sections.append(
        "## Contributing addons\n"
        + (
            _markdown_table(["Addon", "Role", "Page"], backlink_rows)
            if backlink_rows
            else "No contributing addons were recorded."
        )
    )

    if shared.documentation is None:
        sections.append("No model documentation is available.")
        return "\n\n".join([f"# Shared model: {shared.model}"] + sections)

    model_sections = shared.documentation.sections or build_model_sections(
        shared.documentation
    )
    sections.extend(
        section.markdown
        for section in sorted(model_sections, key=lambda item: item.order)
        if section.title != "Summary"
    )
    return "\n\n".join([f"# Shared model: {shared.model}"] + sections)


def render_multi_addon_index_markdown(bundle: MultiAddonDocumentation) -> str:
    """Render the index page for a multi-addon documentation bundle."""
    summary_lines = [
        f"- selected addons: `{', '.join(bundle.modules) or '-'}`",
        f"- addon pages: `{len(bundle.addon_docs)}`",
        f"- shared model pages: `{len(bundle.shared_models)}`",
        f"- database: `{bundle.database or 'default'}`",
        f"- source only: `{'yes' if bundle.source_only else 'no'}`",
    ]
    sections = ["## Summary\n" + "\n".join(summary_lines)]

    addon_rows = [
        [
            addon.module,
            f"[{addon.module}]({addon.output_path})"
            if addon.output_path
            else addon.module,
        ]
        for addon in bundle.addon_docs
    ]
    sections.append(
        "## Addon pages\n"
        + (
            _markdown_table(["Addon", "Path"], addon_rows)
            if addon_rows
            else "No addon pages were generated."
        )
    )

    shared_rows = [
        [
            shared.model,
            ", ".join(shared.owning_modules) or "external",
            ", ".join(shared.contributing_modules) or "-",
            (
                f"[{shared.model}]({shared.output_path})"
                if shared.output_path
                else shared.model
            ),
        ]
        for shared in bundle.shared_models
    ]
    sections.append(
        "## Shared models\n"
        + (
            _markdown_table(
                ["Model", "Owning addons", "Contributing addons", "Path"],
                shared_rows,
            )
            if shared_rows
            else "No shared model pages were generated."
        )
    )

    if bundle.warnings or bundle.remediation:
        warning_section = ["## Warnings and remediation"]
        if bundle.warnings:
            warning_section.append("\n### Warnings\n" + _bullet_lines(bundle.warnings))
        if bundle.remediation:
            warning_section.append(
                "\n### Remediation\n" + _bullet_lines(bundle.remediation)
            )
        sections.append("\n".join(warning_section))

    return "\n\n".join(["# Multi-addon documentation bundle"] + sections)


def render_dependency_graph_markdown(bundle: DependencyGraphDocumentation) -> str:
    """Render dependency graph documentation as Markdown."""
    sections = bundle.sections or build_dependency_graph_sections(bundle)
    sorted_sections = sorted(sections, key=lambda item: item.order)
    return "\n\n".join(
        ["# Dependency graph documentation"]
        + [section.markdown for section in sorted_sections]
    )
