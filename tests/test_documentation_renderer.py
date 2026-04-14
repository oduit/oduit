from oduit.api_models import (
    AddonDocumentation,
    AddonDocumentationModel,
    AddonInfo,
    AddonModelEntry,
    DocumentationDiagram,
    ModelDocumentation,
    ModelExtensionInventory,
)
from oduit.documentation_renderer import (
    render_addon_markdown,
    render_dependency_graph_mermaid,
    render_model_inheritance_mermaid,
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
