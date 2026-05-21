import re
from pathlib import Path

from oduit.api_models import (
    AddonContributionSummary,
    AddonDocTarget,
    AddonDocumentation,
    AddonDocumentationModel,
    AddonHttpRoute,
    AddonInfo,
    AddonModelEntry,
    AddonModelInventory,
    AddonTechnicalFile,
    AddonTechnicalInventory,
    AddonXmlRecord,
    DocumentationDiagram,
    ModelDocumentation,
    ModelExtensionInventory,
    MultiAddonDocumentation,
    SharedModelDocumentation,
    SourceEvidence,
    TechnicalDocumentation,
)
from oduit.arc42_renderer import (
    inspect_generated_markdown_quality,
    render_arc42_addon_markdown,
)
from oduit.documentation_renderer import (
    render_addon_markdown,
    render_addon_markdown_deduplicated,
    render_dependency_graph_mermaid,
    render_model_inheritance_mermaid,
    render_multi_addon_index_markdown,
    render_shared_model_markdown,
)


def test_render_dependency_graph_mermaid_is_deterministic_and_marks_missing() -> None:
    graph = {
        "nodes": ["my_partner", "base"],
        "edges": [{"source": "my_partner", "target": "base"}],
        "missing_dependencies": {"my_partner": ["mail"]},
    }

    diagram = render_dependency_graph_mermaid(graph)

    assert diagram.kind == "dependency_graph"
    assert 'my_partner["my_partner"]' in diagram.content
    assert 'mail["mail (missing)"]' in diagram.content
    assert "my_partner --> base" in diagram.content


def test_render_model_inheritance_mermaid_mentions_extensions() -> None:
    inventory = ModelExtensionInventory(
        model="res.partner",
        source_extensions=[],
    )
    diagram = render_model_inheritance_mermaid(inventory)

    assert diagram.kind == "model_inheritance"
    assert 'res_partner["res.partner"]' in diagram.content


def test_render_addon_markdown_contains_expected_sections() -> None:
    addon_info = AddonInfo(
        module="my_partner",
        module_path="/addons/my_partner",
        addon_type="custom",
        version_display="17.0.1.0.0",
        summary="Partner customizations",
        depends=["base"],
    )
    bundle = AddonDocumentation(
        module="my_partner",
        source_only=True,
        addon_info=addon_info,
        dependency_graph={
            "nodes": ["base", "my_partner"],
            "edges": [{"source": "my_partner", "target": "base"}],
            "missing_dependencies": {},
        },
        models=[
            AddonDocumentationModel(
                model="res.partner",
                relation_kinds=["extends"],
                source_entries=[
                    AddonModelEntry(
                        model="res.partner",
                        relation_kind="extends",
                        class_name="ResPartner",
                        path="models/res_partner.py",
                    )
                ],
                documentation=ModelDocumentation(
                    model="res.partner",
                    source_only=True,
                    extension_inventory=ModelExtensionInventory(model="res.partner"),
                ),
            )
        ],
        recommended_tests={
            "tests": [
                {
                    "path": "tests/test_partner.py",
                    "test_type": "python",
                }
            ]
        },
        diagrams=[
            DocumentationDiagram(
                kind="dependency_graph",
                title="Dependency graph",
                format="mermaid",
                content=(
                    'flowchart LR\n    my_partner["my_partner"]\n'
                    '    base["base"]\n    my_partner --> base'
                ),
            )
        ],
    )

    markdown = render_addon_markdown(bundle)

    assert "# Addon documentation: my_partner" in markdown
    assert "## Summary" in markdown
    assert "## Dependency overview" in markdown
    assert "## Models declared or extended" in markdown
    assert "## Tests" in markdown


def test_render_addon_markdown_deduplicates_shared_models() -> None:
    addon_info = AddonInfo(
        module="my_partner",
        module_path="/addons/my_partner",
        addon_type="custom",
        version_display="17.0.1.0.0",
        summary="Partner customizations",
        depends=["base"],
    )
    bundle = AddonDocumentation(
        module="my_partner",
        source_only=True,
        addon_info=addon_info,
        dependency_graph={"edges": [], "missing_dependencies": {}},
        models=[
            AddonDocumentationModel(
                model="x.demo",
                relation_kinds=["declares"],
                source_entries=[
                    AddonModelEntry(
                        model="x.demo",
                        relation_kind="declares",
                        class_name="DemoModel",
                        path="models/demo.py",
                    )
                ],
                documentation=ModelDocumentation(
                    model="x.demo",
                    source_only=True,
                    extension_inventory=ModelExtensionInventory(model="x.demo"),
                ),
            )
        ],
        shared_model_contributions=[
            AddonContributionSummary(
                model="res.partner",
                module="my_partner",
                relation_kinds=["extends"],
                class_names=["ResPartner"],
                added_fields=["score"],
                source_paths=["models/partner.py"],
                shared_model_doc_path="../models/res.partner.md",
            )
        ],
    )

    markdown = render_addon_markdown_deduplicated(bundle)

    assert "## Shared model contributions" in markdown
    assert "[res.partner](../models/res.partner.md)" in markdown
    assert "### x.demo" in markdown
    assert "\n### res.partner\n" not in markdown


def test_render_shared_model_markdown_contains_backlinks() -> None:
    shared = SharedModelDocumentation(
        model="res.partner",
        owning_modules=[],
        contributing_modules=["my_partner", "my_partner_crm"],
        documentation=ModelDocumentation(
            model="res.partner",
            source_only=True,
            extension_inventory=ModelExtensionInventory(model="res.partner"),
        ),
        output_path="models/res.partner.md",
    )

    markdown = render_shared_model_markdown(shared)

    assert "# Shared model: res.partner" in markdown
    assert "## Contributing addons" in markdown
    assert "[my_partner](../addons/my_partner.md)" in markdown
    assert "## Field metadata" in markdown


def test_render_multi_addon_index_markdown_links_bundle_pages() -> None:
    bundle = MultiAddonDocumentation(
        modules=["my_partner", "my_partner_crm"],
        addon_docs=[
            AddonDocumentation(
                module="my_partner",
                output_path="addons/my_partner.md",
            )
        ],
        shared_models=[
            SharedModelDocumentation(
                model="res.partner",
                contributing_modules=["my_partner", "my_partner_crm"],
                output_path="models/res.partner.md",
            )
        ],
    )

    markdown = render_multi_addon_index_markdown(bundle)

    assert "# Multi-addon documentation bundle" in markdown
    assert "[my_partner](addons/my_partner.md)" in markdown
    assert "[res.partner](models/res.partner.md)" in markdown


def _technical_bundle(*, include_routes: bool = True) -> TechnicalDocumentation:
    addon_info = AddonInfo(
        module="has_base",
        module_path="addons/has_base",
        addon_type="custom",
        version_display="17.0.1.0.0",
        name="Has Base",
        summary="Demo addon",
        category="Tools",
        license="LGPL-3",
        depends=["base"],
        languages=["de"],
    )
    addon_doc = AddonDocumentation(
        module="has_base",
        source_only=True,
        addon_info=addon_info,
        dependency_graph={
            "nodes": ["base", "has_base"],
            "edges": [{"source": "has_base", "target": "base"}],
            "missing_dependencies": {},
        },
        model_inventory=AddonModelInventory(
            module="has_base",
            addon_root="addons/has_base",
            models=[
                AddonModelEntry(
                    model="res.partner",
                    relation_kind="extends",
                    class_name="ResPartner",
                    path="addons/has_base/models/res_partner.py",
                    added_methods=["action_sync"],
                )
            ],
            model_count=1,
        ),
        recommended_tests={
            "tests": [
                {
                    "path": "addons/has_base/tests/test_has_base.py",
                    "test_type": "python",
                    "references_model": True,
                    "confidence": 0.91,
                }
            ]
        },
        warnings=["Missing runtime inspection details."],
        remediation=["Use runtime tracing for confirmed business flows."],
    )
    inventory = AddonTechnicalInventory(
        module="has_base",
        addon_root="addons/has_base",
        files=[
            AddonTechnicalFile(
                path="addons/has_base/models/res_partner.py",
                category="model",
                size_bytes=128,
            ),
            AddonTechnicalFile(
                path="addons/has_base/views/res_partner.xml",
                category="view",
                size_bytes=256,
            ),
        ],
        xml_records=[
            AddonXmlRecord(
                path="addons/has_base/views/res_partner.xml",
                record_id="view_partner_form",
                model="ir.ui.view",
                name="res.partner.form",
            ),
            AddonXmlRecord(
                path="addons/has_base/data/cron.xml",
                record_id="ir_cron_sync",
                model="ir.cron",
                name="Sync cron",
            ),
        ],
        http_routes=[
            AddonHttpRoute(
                path="addons/has_base/controllers/main.py",
                class_name="HasBaseController",
                method_name="portal_page",
                route="/has_base",
                auth="public",
                route_type="http",
                methods=["GET"],
            )
        ]
        if include_routes
        else [],
        todo_markers=[
            SourceEvidence(
                kind="TODO",
                message="TODO: tighten portal security",
                path="addons/has_base/models/res_partner.py",
                line_hint=42,
            )
        ],
        warnings=[
            "Failed to parse XML file addons/has_base/views/broken.xml: parse error"
        ],
        remediation=[
            (
                "Controllers or routes were detected without matching"
                " security files; review access control manually."
            )
        ],
    )
    return TechnicalDocumentation(
        module="has_base",
        addon_root="addons/has_base",
        target=AddonDocTarget(
            module="has_base",
            addon_root="addons/has_base",
            target_kind="module",
            manifest_path="addons/has_base/__manifest__.py",
        ),
        source_only=True,
        addon_documentation=addon_doc,
        technical_inventory=inventory,
        sections=[],
        warnings=[
            (
                "Public or unauthenticated HTTP routes were detected"
                " and require manual security review."
            )
        ],
        remediation=list(inventory.remediation),
    )


def test_render_arc42_addon_markdown_contains_arc42_sections() -> None:
    markdown = render_arc42_addon_markdown(_technical_bundle())

    assert "# Architecture Documentation: has_base" in markdown
    assert "## 1. Introduction and Goals" in markdown
    assert "## 5. Building Block View" in markdown
    assert "## 11. Risks and Technical Debt" in markdown
    assert "## Appendix A: oduit Evidence" in markdown


def test_render_arc42_addon_markdown_marks_unknown_business_context_as_todo() -> None:
    markdown = render_arc42_addon_markdown(_technical_bundle(include_routes=False))

    assert (
        "No HTTP controllers or explicit external integration"
        " files were detected by oduit."
    ) in markdown
    assert "TODO: Confirm whether integrations are implemented indirectly" in markdown


def test_render_arc42_addon_markdown_includes_security_and_route_warnings() -> None:
    markdown = render_arc42_addon_markdown(_technical_bundle())

    assert "Public or unauthenticated HTTP routes were detected" in markdown
    assert (
        "Controllers or routes were detected without matching security files"
        in markdown
    )
    assert "`/has_base`" in markdown


def test_render_arc42_markdown_has_no_joined_wrapped_words() -> None:
    markdown = render_arc42_addon_markdown(_technical_bundle(include_routes=False))
    normalized = markdown.replace("\n", " ")
    forbidden_fragments = [
        "thisaddon",
        "projectowner",
        "maintenanceroles",
        "processowner",
        "manifestchanges",
        "monitorsthe",
        "deliberatearchitectural",
        "backendworkflows",
        "norelevant",
        "staticevidence",
        "boundaryfor",
        "androllback",
        "suchas",
        "andprivileged",
        "inviews",
        "migrationexpectations",
        "datamigrations",
        "stringsremain",
        "operatorrunbooks",
        "oduitevidence",
        "duringmaintenance",
        "aftera",
        "keepsunknown",
        "ACLcoverage",
        "evidenceremain",
        "theaffected",
        "existsoutside",
    ]
    for fragment in forbidden_fragments:
        assert fragment not in normalized


def test_arc42_renderer_wrapped_literals_keep_word_spacing() -> None:
    source = Path("oduit/arc42_renderer.py").read_text(encoding="utf-8")
    pattern = re.compile(
        r'(["\'])([^"\']*?[A-Za-z0-9`.,):])\1\s*\n\s*(["\'])([a-z][^"\']*)\3'
    )
    matches = list(pattern.finditer(source))
    assert not matches, [source[: match.start()].count("\n") + 1 for match in matches]


def test_generated_markdown_quality_reports_expected_counts() -> None:
    markdown = render_arc42_addon_markdown(_technical_bundle(include_routes=False))
    quality = inspect_generated_markdown_quality(markdown)

    assert quality["todo_count"] > 0
    assert "formatting_issue_count" in quality
    assert "warnings" in quality
