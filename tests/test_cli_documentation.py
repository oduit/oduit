import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from oduit.api_models import (
    AddonContributionSummary,
    AddonDocumentation,
    AddonDocumentationModel,
    AddonInfo,
    AddonInstallState,
    DependencyGraphDocumentation,
    ModelDocumentation,
    ModelExtensionInventory,
    MultiAddonDocumentation,
    SharedModelDocumentation,
)
from oduit.cli.app import app


def _documentation_bundle(module: str = "my_partner") -> AddonDocumentation:
    addon_info = AddonInfo(
        module=module,
        module_path=f"/addons/{module}",
        addon_type="custom",
        version_display="17.0.1.0.0",
        depends=["base"],
        installed_state=AddonInstallState(
            success=True,
            operation="get_addon_install_state",
            module=module,
            record_found=True,
            state="installed",
            installed=True,
        ),
    )
    return AddonDocumentation(
        module=module,
        addon_info=addon_info,
        source_only=False,
        dependency_graph={
            "nodes": ["base", module],
            "edges": [{"source": module, "target": "base"}],
            "missing_dependencies": {},
        },
        models=[
            AddonDocumentationModel(
                model="res.partner",
                relation_kinds=["extends"],
                documentation=ModelDocumentation(
                    model="res.partner",
                    extension_inventory=ModelExtensionInventory(model="res.partner"),
                ),
            )
        ],
        markdown=f"# Addon documentation: {module}\n",
    )


def _dependency_graph_bundle() -> DependencyGraphDocumentation:
    return DependencyGraphDocumentation(
        modules=["my_partner"],
        dependency_graph={
            "nodes": ["base", "my_partner"],
            "edges": [{"source": "my_partner", "target": "base"}],
            "missing_dependencies": {},
        },
        markdown="# Dependency graph documentation\n",
    )


def _multi_addon_documentation_bundle() -> MultiAddonDocumentation:
    addon_doc = AddonDocumentation(
        module="my_partner",
        addon_info=AddonInfo(
            module="my_partner",
            module_path="/addons/my_partner",
            addon_type="custom",
            version_display="17.0.1.0.0",
            depends=["base"],
        ),
        shared_model_contributions=[
            AddonContributionSummary(
                model="res.partner",
                module="my_partner",
                relation_kinds=["extends"],
                class_names=["ResPartner"],
                shared_model_doc_path="../models/res.partner.md",
            )
        ],
        output_path="addons/my_partner.md",
        markdown="# Addon documentation: my_partner\n",
    )
    shared_doc = SharedModelDocumentation(
        model="res.partner",
        contributing_modules=["my_partner"],
        output_path="models/res.partner.md",
        markdown="# Shared model: res.partner\n",
    )
    return MultiAddonDocumentation(
        modules=["my_partner"],
        addon_docs=[addon_doc],
        shared_models=[shared_doc],
        index_markdown="# Multi-addon documentation bundle\n",
    )


def test_docs_addon_command_emits_json_payload(tmp_path: Path) -> None:
    runner = CliRunner()
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = MagicMock()
    loader.load_config.return_value = config

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.build_addon_documentation.return_value = _documentation_bundle()
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "addon",
                "my_partner",
                "--path",
                "/my/long/path",
                "--format",
                "json",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "addon_documentation"
    assert payload["operation"] == "docs_addon"
    assert payload["module"] == "my_partner"
    assert (
        ops.build_addon_documentation.call_args.kwargs["path_prefix"] == "/my/long/path"
    )


def test_docs_addon_command_writes_markdown_output(tmp_path: Path) -> None:
    runner = CliRunner()
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = MagicMock()
    loader.load_config.return_value = config
    output_path = tmp_path / "addon-doc.md"

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.build_addon_documentation.return_value = _documentation_bundle()
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "addon",
                "my_partner",
                "--output",
                str(output_path),
            ],
        )

    assert result.exit_code == 0
    assert output_path.read_text() == "# Addon documentation: my_partner\n"
    assert str(output_path) in result.output


def test_docs_dependency_graph_command_emits_json_payload(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    (addons_dir / "base").mkdir()
    (addons_dir / "base" / "__manifest__.py").write_text(
        "{'name': 'Base', 'depends': []}"
    )
    (addons_dir / "my_partner").mkdir()
    (addons_dir / "my_partner" / "__manifest__.py").write_text(
        "{'name': 'My Partner', 'depends': ['base']}"
    )

    config = {
        "db_name": "test_db",
        "addons_path": str(addons_dir),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = MagicMock()
    loader.load_config.return_value = config

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.build_dependency_graph_documentation.return_value = (
            _dependency_graph_bundle()
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "dependency-graph",
                "--modules",
                "my_partner",
                "--format",
                "json",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "dependency_graph_documentation"
    assert payload["operation"] == "docs_dependency_graph"
    assert payload["modules"] == ["my_partner"]


def test_docs_addons_command_writes_markdown_bundle(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    (addons_dir / "base").mkdir()
    (addons_dir / "base" / "__manifest__.py").write_text("{'name': 'Base'}")
    (addons_dir / "my_partner").mkdir()
    (addons_dir / "my_partner" / "__manifest__.py").write_text(
        "{'name': 'My Partner', 'depends': ['base']}"
    )
    config = {
        "db_name": "test_db",
        "addons_path": str(addons_dir),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = MagicMock()
    loader.load_config.return_value = config
    output_dir = tmp_path / "docs-out"

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.build_addons_documentation.return_value = (
            _multi_addon_documentation_bundle()
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "addons",
                "--modules",
                "my_partner",
                "--output-dir",
                str(output_dir),
            ],
        )

    assert result.exit_code == 0
    assert (
        output_dir / "index.md"
    ).read_text() == "# Multi-addon documentation bundle\n"
    assert (
        output_dir / "addons" / "my_partner.md"
    ).read_text() == "# Addon documentation: my_partner\n"
    assert (
        output_dir / "models" / "res.partner.md"
    ).read_text() == "# Shared model: res.partner\n"
    assert json.loads((output_dir / "bundle.json").read_text())["modules"] == [
        "my_partner"
    ]


def test_docs_addons_command_uses_select_dir_resolution(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_root = tmp_path / "addons"
    selected_dir = addons_root / "myaddons"
    selected_dir.mkdir(parents=True)
    (selected_dir / "my_partner").mkdir()
    (selected_dir / "my_partner" / "__manifest__.py").write_text(
        "{'name': 'My Partner', 'depends': []}"
    )
    config = {
        "db_name": "test_db",
        "addons_path": str(selected_dir),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = MagicMock()
    loader.load_config.return_value = config

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.build_addons_documentation.return_value = (
            _multi_addon_documentation_bundle()
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "addons",
                "--select-dir",
                "myaddons",
                "--output-dir",
                str(tmp_path / "docs-out"),
            ],
        )

    assert result.exit_code == 0
    assert ops.build_addons_documentation.call_args.args[0] == ["my_partner"]


def test_docs_addons_command_rejects_modules_and_select_dir(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = {
        "db_name": "test_db",
        "addons_path": str(addons_dir),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = MagicMock()
    loader.load_config.return_value = config

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "addons",
                "--modules",
                "my_partner",
                "--select-dir",
                "myaddons",
                "--output-dir",
                str(tmp_path / "docs-out"),
            ],
        )

    assert result.exit_code == 1
    assert "Cannot use both module names and --select-dir option" in result.output


def test_docs_addons_command_rejects_empty_select_dir(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    config = {
        "db_name": "test_db",
        "addons_path": str(addons_dir),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = MagicMock()
    loader.load_config.return_value = config

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "addons",
                "--select-dir",
                "missing_dir",
                "--output-dir",
                str(tmp_path / "docs-out"),
            ],
        )

    assert result.exit_code == 1
    assert "No modules found in directory 'missing_dir'" in result.output


def test_docs_addons_command_requires_output_dir_for_markdown(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_dir = tmp_path / "addons"
    addons_dir.mkdir()
    (addons_dir / "my_partner").mkdir()
    (addons_dir / "my_partner" / "__manifest__.py").write_text("{'name': 'My Partner'}")
    config = {
        "db_name": "test_db",
        "addons_path": str(addons_dir),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = MagicMock()
    loader.load_config.return_value = config

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "addons",
                "--modules",
                "my_partner",
            ],
        )

    assert result.exit_code == 1
    assert "--output-dir is required for markdown output" in result.output
