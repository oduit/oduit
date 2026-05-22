import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from oduit.api_models import (
    AddonContributionSummary,
    AddonDocTarget,
    AddonDocumentation,
    AddonDocumentationModel,
    AddonInfo,
    AddonInstallState,
    DependencyGraphDocumentation,
    ModelDocumentation,
    ModelExtensionInventory,
    MultiAddonDocumentation,
    SharedModelDocumentation,
    TechnicalDocumentation,
)
from oduit.cli.app import app
from oduit.cli.commands.documentation import _format_progress_message


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


def _technical_documentation_bundle(addon_root: Path) -> TechnicalDocumentation:
    return TechnicalDocumentation(
        module="my_partner",
        addon_root=str(addon_root),
        source_addon_root=str(addon_root),
        target=AddonDocTarget(
            module="my_partner",
            addon_root=str(addon_root),
            target_kind="module",
            manifest_path=str(addon_root / "__manifest__.py"),
        ),
        markdown="# Architecture Documentation: my_partner\n",
    )


def _local_loader(config: dict[str, str], root: Path) -> MagicMock:
    loader = MagicMock()
    loader.has_local_config.return_value = True
    loader.get_local_config_path.return_value = str(root / ".oduit.toml")
    loader.load_local_config.return_value = config
    return loader


def _make_technical_addon_root(addon_root: Path) -> None:
    addon_root.mkdir(parents=True, exist_ok=True)
    (addon_root / "__manifest__.py").write_text(
        "{'name': 'My Partner', 'version': '17.0.1.0.0', 'depends': ['base']}\n"
    )
    (addon_root / "models").mkdir(exist_ok=True)
    (addon_root / "models" / "res_partner.py").write_text(
        "from odoo import fields, models\n\n"
        "class ResPartner(models.Model):\n"
        "    _inherit = 'res.partner'\n"
        "    email3 = fields.Char()\n"
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


def test_docs_technical_prints_markdown(tmp_path: Path) -> None:
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
        ops.build_technical_documentation.return_value = (
            _technical_documentation_bundle(tmp_path / "addons" / "my_partner")
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical",
                "my_partner",
                "--template",
                "arc42",
                "--source-only",
            ],
        )

    assert result.exit_code == 0
    assert "# Architecture Documentation: my_partner" in result.output


def test_docs_technical_writes_to_addon_docs(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.build_technical_documentation.return_value = (
            _technical_documentation_bundle(addon_root)
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical",
                "my_partner",
                "--output-in-addon",
            ],
        )

    output_path = addon_root / "docs" / "architecture.md"
    metadata_path = addon_root / "docs" / "architecture.oduit.json"
    assert result.exit_code == 0
    assert output_path.exists()
    assert "Metadata: docs/architecture.oduit.json" in output_path.read_text()
    assert metadata_path.exists()
    assert output_path.as_posix() in result.output
    assert metadata_path.as_posix() in result.output


def test_docs_technical_refuses_overwrite_without_force(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    output_path = addon_root / "docs" / "architecture.md"
    output_path.parent.mkdir(parents=True)
    output_path.write_text("existing\n")
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.build_technical_documentation.return_value = (
            _technical_documentation_bundle(addon_root)
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical",
                "my_partner",
                "--output-in-addon",
            ],
        )

    assert result.exit_code == 1
    assert "Output file already exists" in result.output


def test_docs_technical_accepts_at_path_target(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    addon_root.mkdir(parents=True)
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
        "odoo_bin": "/usr/bin/python3",
        "python_bin": "/usr/bin/python3",
    }
    loader = MagicMock()
    loader.load_config.return_value = config

    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.build_technical_documentation.return_value = (
            _technical_documentation_bundle(addon_root)
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical",
                "@addons/my_partner",
            ],
        )

    assert result.exit_code == 0
    assert ops.build_technical_documentation.call_args.args[0] == "@addons/my_partner"
    assert (
        ops.build_technical_documentation.call_args.kwargs["progress_level"]
        == "compact"
    )


def test_docs_technical_writes_metadata_sidecar(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.build_technical_documentation.return_value = (
            _technical_documentation_bundle(addon_root)
        )
        mock_ops_class.return_value = ops

        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical",
                "my_partner",
                "--output-in-addon",
            ],
        )

    metadata_path = addon_root / "docs" / "architecture.oduit.json"
    assert result.exit_code == 0
    metadata = json.loads(metadata_path.read_text())
    assert metadata["module"] == "my_partner"
    assert metadata["created_at"]
    assert metadata["last_generated_at"]
    assert metadata["source_snapshot"]["fingerprint"].startswith("sha256:")
    assert metadata["document_snapshot"]["fingerprint"].startswith("sha256:")


def test_docs_technical_preserves_created_at_on_force_regeneration(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.build_technical_documentation.return_value = (
            _technical_documentation_bundle(addon_root)
        )
        mock_ops_class.return_value = ops

        first = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical",
                "my_partner",
                "--output-in-addon",
            ],
        )
        created_at = json.loads(
            (addon_root / "docs" / "architecture.oduit.json").read_text()
        )["created_at"]
        second = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical",
                "my_partner",
                "--output-in-addon",
                "--force",
            ],
        )

    metadata_path = addon_root / "docs" / "architecture.oduit.json"
    assert first.exit_code == 0
    assert second.exit_code == 0
    metadata = json.loads(metadata_path.read_text())
    assert metadata["created_at"] == created_at
    assert metadata["generation_count"] == 2


def test_docs_technical_status_reports_document_edit(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.build_technical_documentation.return_value = (
            _technical_documentation_bundle(addon_root)
        )
        mock_ops_class.return_value = ops
        generate = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical",
                "my_partner",
                "--output-in-addon",
            ],
        )

    assert generate.exit_code == 0
    doc_path = addon_root / "docs" / "architecture.md"
    doc_path.write_text(doc_path.read_text() + "\nHuman edit\n")

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical-status",
                "my_partner",
                "--format",
                "json",
                "--include-files",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    status = payload["statuses"][0]
    assert status["document_edited_since_last_generation"] is True


def test_docs_technical_status_reports_source_change(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.build_technical_documentation.return_value = (
            _technical_documentation_bundle(addon_root)
        )
        mock_ops_class.return_value = ops
        generate = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical",
                "my_partner",
                "--output-in-addon",
            ],
        )

    assert generate.exit_code == 0
    source_path = addon_root / "models" / "res_partner.py"
    source_path.write_text(source_path.read_text() + "\n# source change\n")

    with patch("oduit.cli.app.ConfigLoader", return_value=loader):
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical-status",
                "my_partner",
                "--format",
                "json",
                "--include-files",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    status = payload["statuses"][0]
    assert status["source_changed_since_last_generation"] is True
    assert "models/res_partner.py" in status["changed_files"]


def test_docs_technical_status_reports_untracked_generated_doc(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    (addon_root / "docs").mkdir(exist_ok=True)
    (addon_root / "docs" / "architecture.md").write_text(
        "<!--\nGenerated by oduit.\n-->\n"
    )
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
                "technical-status",
                "my_partner",
                "--format",
                "json",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    status = payload["statuses"][0]
    assert status["status"] == "untracked"


def test_docs_technical_writes_relative_metadata_when_local_config_base_exists(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    (tmp_path / ".oduit.toml").write_text('[odoo_params]\naddons_path = "./addons"\n')
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with (
            patch("oduit.cli.app.ConfigLoader", return_value=loader),
            patch("oduit.cli.app.OdooOperations") as mock_ops_class,
        ):
            ops = MagicMock()
            ops.build_technical_documentation.return_value = (
                _technical_documentation_bundle(addon_root)
            )
            mock_ops_class.return_value = ops

            result = runner.invoke(
                app,
                [
                    "docs",
                    "technical",
                    "my_partner",
                    "--output-in-addon",
                ],
            )
    finally:
        os.chdir(cwd)

    metadata = json.loads((addon_root / "docs" / "architecture.oduit.json").read_text())
    assert result.exit_code == 0
    assert metadata["addon_root"] == "addons/my_partner"
    assert metadata["doc_path"] == "addons/my_partner/docs/architecture.md"
    assert metadata["metadata_path"] == "addons/my_partner/docs/architecture.oduit.json"
    assert metadata["generation_options"]["path_prefix"] == "."
    assert metadata["generation_options"]["path_base"]["source"] == "local_config"
    assert '"/tmp/' not in json.dumps(metadata)


def test_docs_technical_progress_writes_to_stderr_without_corrupting_stdout(
    tmp_path: Path,
) -> None:
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    (tmp_path / ".oduit.toml").write_text('[odoo_params]\naddons_path = "./addons"\n')
    cli_path = shutil.which("oduit")
    assert cli_path is not None
    env = dict(os.environ)
    result = subprocess.run(
        [
            cli_path,
            "docs",
            "technical",
            "addons/my_partner",
            "--source-only",
            "--progress",
            "--format",
            "json",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "[oduit docs] resolving project path base:" in result.stderr
    assert "[oduit docs]" not in result.stdout
    assert json.loads(result.stdout)["type"] == "technical_documentation"


def test_docs_progress_formatter_includes_model_index_suffix() -> None:
    message = _format_progress_message(
        "model_documentation",
        {"module": "has_helpdesk", "model": "helpdesk.ticket", "index": 3, "total": 42},
        progress_level="model",
    )
    assert message == "documenting model: has_helpdesk:helpdesk.ticket (3/42)"


def test_docs_progress_formatter_reports_runtime_batch_in_compact_mode() -> None:
    message = _format_progress_message(
        "runtime_metadata_batch",
        {"module": "has_helpdesk", "model_count": 10},
        progress_level="compact",
    )
    assert message == "querying runtime metadata: 10 models"


def test_docs_technical_status_select_dir_relative_addon_path_returns_one_status(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "has_crm"
    other_root = tmp_path / "addons" / "has_sales"
    _make_technical_addon_root(addon_root)
    _make_technical_addon_root(other_root)
    (tmp_path / ".oduit.toml").write_text('[odoo_params]\naddons_path = "./addons"\n')
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            result = runner.invoke(
                app,
                [
                    "docs",
                    "technical-status",
                    "--select-dir",
                    "addons/has_crm",
                    "--format",
                    "json",
                ],
            )
    finally:
        os.chdir(cwd)

    payload = json.loads(result.output)
    assert result.exit_code == 0
    assert [status["module"] for status in payload["statuses"]] == ["has_crm"]


def test_docs_technical_check_exits_for_source_change_and_can_be_waived(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    (tmp_path / ".oduit.toml").write_text('[odoo_params]\naddons_path = "./addons"\n')
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with (
            patch("oduit.cli.app.ConfigLoader", return_value=loader),
            patch("oduit.cli.app.OdooOperations") as mock_ops_class,
        ):
            ops = MagicMock()
            ops.build_technical_documentation.return_value = (
                _technical_documentation_bundle(addon_root)
            )
            mock_ops_class.return_value = ops
            generate = runner.invoke(
                app,
                ["docs", "technical", "my_partner", "--output-in-addon"],
            )
        assert generate.exit_code == 0
        source_path = addon_root / "models" / "res_partner.py"
        source_path.write_text(source_path.read_text() + "\n# source change\n")
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            failing = runner.invoke(
                app,
                ["docs", "technical-check", "my_partner", "--format", "json"],
            )
            passing = runner.invoke(
                app,
                [
                    "docs",
                    "technical-check",
                    "my_partner",
                    "--format",
                    "json",
                    "--no-fail-on-stale",
                ],
            )
    finally:
        os.chdir(cwd)

    assert failing.exit_code == 1
    assert json.loads(failing.output)["status"]["status"] == "generated_blocks_stale"
    assert passing.exit_code == 0
    assert json.loads(passing.output)["success"] is True


def test_docs_technical_next_returns_expected_module_name(tmp_path: Path) -> None:
    runner = CliRunner()
    addons_root = tmp_path / "addons"
    _make_technical_addon_root(addons_root / "has_crm")
    _make_technical_addon_root(addons_root / "z_sales")
    (tmp_path / ".oduit.toml").write_text('[odoo_params]\naddons_path = "./addons"\n')
    config = {
        "db_name": "test_db",
        "addons_path": str(addons_root),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            result = runner.invoke(app, ["docs", "technical-next", "addons"])
    finally:
        os.chdir(cwd)

    assert result.exit_code == 0
    assert result.output.strip() == "has_crm"


def test_docs_technical_next_respects_allowed_addon_dirs(tmp_path: Path) -> None:
    runner = CliRunner()
    native_root = tmp_path / "odoo" / "addons"
    custom_root = tmp_path / "addons"
    _make_technical_addon_root(native_root / "account")
    _make_technical_addon_root(custom_root / "has_crm")
    config = {
        "db_name": "test_db",
        "addons_path": f"{native_root},{custom_root}",
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
        "documentation": {"allowed_addon_dirs": ["./addons"]},
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            result = runner.invoke(app, ["docs", "technical-next"])
    finally:
        os.chdir(cwd)

    assert result.exit_code == 0
    assert result.output.strip() == "has_crm"


def test_docs_technical_next_rejects_select_dir_outside_allowed_addon_dirs(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    native_root = tmp_path / "odoo" / "addons"
    custom_root = tmp_path / "addons"
    _make_technical_addon_root(native_root / "account")
    _make_technical_addon_root(custom_root / "has_crm")
    config = {
        "db_name": "test_db",
        "addons_path": f"{native_root},{custom_root}",
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
        "documentation": {"allowed_addon_dirs": ["./addons"]},
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            result = runner.invoke(
                app,
                ["--json", "docs", "technical-next", "odoo/addons"],
            )
    finally:
        os.chdir(cwd)

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error_type"] == "DocumentationTargetNotAllowedError"


def test_docs_technical_status_filters_to_allowed_addon_dirs(tmp_path: Path) -> None:
    runner = CliRunner()
    native_root = tmp_path / "odoo" / "addons"
    custom_root = tmp_path / "addons"
    _make_technical_addon_root(native_root / "account")
    _make_technical_addon_root(custom_root / "has_crm")
    config = {
        "db_name": "test_db",
        "addons_path": f"{native_root},{custom_root}",
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
        "documentation": {"allowed_addon_dirs": ["./addons"]},
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            result = runner.invoke(
                app, ["docs", "technical-status", "--format", "json"]
            )
    finally:
        os.chdir(cwd)

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert [status["module"] for status in payload["statuses"]] == ["has_crm"]


def test_docs_technical_refuses_native_addon_write_when_not_allowed(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    native_root = tmp_path / "odoo" / "addons"
    custom_root = tmp_path / "addons"
    account_root = native_root / "account"
    _make_technical_addon_root(account_root)
    _make_technical_addon_root(custom_root / "has_crm")
    config = {
        "db_name": "test_db",
        "addons_path": f"{native_root},{custom_root}",
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
        "documentation": {"allowed_addon_dirs": ["./addons"]},
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            result = runner.invoke(
                app,
                [
                    "docs",
                    "technical",
                    "@odoo/addons/account",
                    "--output-in-addon",
                    "--source-only",
                    "--format",
                    "markdown",
                ],
            )
    finally:
        os.chdir(cwd)

    assert result.exit_code == 1
    assert "outside [documentation].allowed_addon_dirs" in result.output
    assert not (account_root / "docs" / "architecture.md").exists()


def test_docs_technical_check_rejects_module_target_outside_allowlist(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    native_root = tmp_path / "odoo" / "addons"
    custom_root = tmp_path / "addons"
    _make_technical_addon_root(native_root / "account")
    _make_technical_addon_root(custom_root / "has_crm")
    config = {
        "db_name": "test_db",
        "addons_path": f"{native_root},{custom_root}",
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
        "documentation": {"allowed_addon_dirs": ["./addons"]},
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            result = runner.invoke(
                app,
                ["--json", "docs", "technical-check", "account"],
            )
    finally:
        os.chdir(cwd)

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["error_type"] == "DocumentationTargetNotAllowedError"


def test_docs_technical_check_omits_file_lists_by_default(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    (tmp_path / ".oduit.toml").write_text('[odoo_params]\naddons_path = "./addons"\n')
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with (
            patch("oduit.cli.app.ConfigLoader", return_value=loader),
            patch("oduit.cli.app.OdooOperations") as mock_ops_class,
        ):
            ops = MagicMock()
            ops.build_technical_documentation.return_value = (
                _technical_documentation_bundle(addon_root)
            )
            mock_ops_class.return_value = ops
            generate = runner.invoke(
                app, ["docs", "technical", "my_partner", "--output-in-addon"]
            )
        assert generate.exit_code == 0
        source_path = addon_root / "models" / "res_partner.py"
        source_path.write_text(source_path.read_text() + "\n# source change\n")
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            result = runner.invoke(
                app, ["docs", "technical-check", "my_partner", "--format", "json"]
            )
    finally:
        os.chdir(cwd)

    status = json.loads(result.output)["status"]
    assert "changed_files" not in status
    assert "added_files" not in status
    assert "removed_files" not in status


def test_docs_technical_check_includes_file_lists_when_requested(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    (tmp_path / ".oduit.toml").write_text('[odoo_params]\naddons_path = "./addons"\n')
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with (
            patch("oduit.cli.app.ConfigLoader", return_value=loader),
            patch("oduit.cli.app.OdooOperations") as mock_ops_class,
        ):
            ops = MagicMock()
            ops.build_technical_documentation.return_value = (
                _technical_documentation_bundle(addon_root)
            )
            mock_ops_class.return_value = ops
            generate = runner.invoke(
                app, ["docs", "technical", "my_partner", "--output-in-addon"]
            )
        assert generate.exit_code == 0
        source_path = addon_root / "models" / "res_partner.py"
        source_path.write_text(source_path.read_text() + "\n# source change\n")
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            result = runner.invoke(
                app,
                [
                    "docs",
                    "technical-check",
                    "my_partner",
                    "--format",
                    "json",
                    "--include-files",
                ],
            )
    finally:
        os.chdir(cwd)

    status = json.loads(result.output)["status"]
    assert "changed_files" in status
    assert "added_files" in status
    assert "removed_files" in status


def test_docs_technical_accept_marks_reviewed_document_as_up_to_date(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    (tmp_path / ".oduit.toml").write_text('[odoo_params]\naddons_path = "./addons"\n')
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
    }
    loader = _local_loader(config, tmp_path)
    cwd = Path.cwd()

    try:
        os.chdir(tmp_path)
        with (
            patch("oduit.cli.app.ConfigLoader", return_value=loader),
            patch("oduit.cli.app.OdooOperations") as mock_ops_class,
        ):
            ops = MagicMock()
            ops.build_technical_documentation.return_value = (
                _technical_documentation_bundle(addon_root)
            )
            mock_ops_class.return_value = ops
            generate = runner.invoke(
                app, ["docs", "technical", "my_partner", "--output-in-addon"]
            )
        assert generate.exit_code == 0
        doc_path = addon_root / "docs" / "architecture.md"
        doc_path.write_text(doc_path.read_text() + "\nManual polish.\n")
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            accept = runner.invoke(app, ["docs", "technical-accept", "my_partner"])
            check = runner.invoke(
                app, ["docs", "technical-check", "my_partner", "--format", "json"]
            )
        source_path = addon_root / "models" / "res_partner.py"
        source_path.write_text(source_path.read_text() + "\n# source change\n")
        with patch("oduit.cli.app.ConfigLoader", return_value=loader):
            stale = runner.invoke(
                app, ["docs", "technical-check", "my_partner", "--format", "json"]
            )
    finally:
        os.chdir(cwd)

    assert accept.exit_code == 0
    assert json.loads(check.output)["status"]["status"] == "up_to_date"
    assert json.loads(stale.output)["status"]["status"] == "generated_blocks_stale"


def test_docs_technical_refresh_dry_run_json_reports_changes(tmp_path: Path) -> None:
    runner = CliRunner()
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.refresh_technical_documentation.return_value = {
            "module": "my_partner",
            "doc_path": "addons/my_partner/docs/architecture.md",
            "metadata_path": "addons/my_partner/docs/architecture.oduit.json",
            "changed": True,
            "block_count": 1,
            "updated_blocks": ["arc42.constraints"],
            "edited_blocks": [],
            "missing_blocks": [],
            "unknown_blocks": [],
            "changes": [],
            "warnings": [],
            "errors": [],
            "metadata_summary": {
                "status": "generated_blocks_stale",
                "generation_count": 1,
            },
        }
        mock_ops_class.return_value = ops
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical-refresh",
                "my_partner",
                "--format",
                "json",
            ],
        )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["type"] == "technical_documentation_refresh"
    assert payload["operation"] == "docs_technical_refresh_preview"
    assert payload["updated_blocks"] == ["arc42.constraints"]


def test_docs_technical_refresh_write_prints_updated_paths(tmp_path: Path) -> None:
    runner = CliRunner()
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.refresh_technical_documentation.return_value = {
            "module": "my_partner",
            "doc_path": "addons/my_partner/docs/architecture.md",
            "metadata_path": "addons/my_partner/docs/architecture.oduit.json",
            "changed": True,
            "block_count": 1,
            "updated_blocks": ["arc42.constraints"],
            "edited_blocks": [],
            "missing_blocks": [],
            "unknown_blocks": [],
            "changes": [],
            "warnings": [],
            "errors": [],
            "metadata_summary": {"status": "up_to_date", "generation_count": 1},
        }
        mock_ops_class.return_value = ops
        result = runner.invoke(
            app, ["--env", "dev", "docs", "technical-refresh", "my_partner", "--write"]
        )

    assert result.exit_code == 0
    assert "Updated 1 generated block(s)" in result.output
    assert "architecture.oduit.json" in result.output


def test_docs_technical_evidence_writes_only_evidence_files(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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

        def _write(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            evidence_path = addon_root / "docs" / "architecture.evidence.md"
            metadata_path = addon_root / "docs" / "architecture.evidence.oduit.json"
            evidence_path.parent.mkdir(parents=True, exist_ok=True)
            evidence_path.write_text("# evidence\n")
            metadata_path.write_text("{}")
            return {
                "module": "my_partner",
                "addon_root": addon_root.as_posix(),
                "evidence_path": evidence_path.as_posix(),
                "metadata_path": metadata_path.as_posix(),
                "evidence_version": 1,
                "generated_block_count": 1,
                "warnings": [],
                "remediation": [],
            }

        ops.write_technical_evidence.side_effect = _write
        mock_ops_class.return_value = ops
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical-evidence",
                "my_partner",
                "--output-in-addon",
            ],
        )
    assert result.exit_code == 0
    assert (addon_root / "docs" / "architecture.evidence.md").exists()
    assert not (addon_root / "docs" / "architecture.md").exists()


def test_docs_technical_report_writes_report_not_evidence(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    docs_dir = addon_root / "docs"
    docs_dir.mkdir()
    evidence_path = docs_dir / "architecture.evidence.md"
    evidence_path.write_text("evidence-before\n")
    (docs_dir / "architecture.evidence.oduit.json").write_text(
        json.dumps({"schema_version": "oduit.technical_evidence.v1"})
    )
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        bundle = _technical_documentation_bundle(addon_root)
        bundle.markdown = "# Architecture Documentation: my_partner\n\nseed\n"
        ops.build_technical_report_seed.return_value = bundle
        mock_ops_class.return_value = ops
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical-report",
                "my_partner",
                "--output-in-addon",
            ],
        )
    assert result.exit_code == 0
    assert (docs_dir / "architecture.md").exists()
    assert evidence_path.read_text() == "evidence-before\n"


def test_docs_technical_diff_json_emits_structured_status(tmp_path: Path) -> None:
    runner = CliRunner()
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.diff_technical_report_evidence.return_value = {
            "module": "my_partner",
            "addon_root": "addons/my_partner",
            "report_path": "addons/my_partner/docs/architecture.md",
            "evidence_path": "addons/my_partner/docs/architecture.evidence.md",
            "evidence_metadata_path": (
                "addons/my_partner/docs/architecture.evidence.oduit.json"
            ),
            "status": "stale",
            "current_evidence_version": 4,
            "snapshot_count": 1,
            "stale_count": 1,
            "edited_snapshot_count": 0,
            "missing_current_block_count": 0,
            "entries": [],
            "warnings": [],
            "remediation": [],
        }
        mock_ops_class.return_value = ops
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical-diff",
                "my_partner",
                "--format",
                "json",
            ],
        )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["status"] == "stale"
    assert payload["module"] == "my_partner"


def test_docs_technical_report_missing_evidence_has_remediation(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
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
        ops.write_technical_evidence.side_effect = ValueError(
            "outside [documentation].allowed_addon_dirs"
        )
        mock_ops_class.return_value = ops
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical-report",
                "my_partner",
                "--output-in-addon",
            ],
        )
    assert result.exit_code == 2
    assert "Run oduit docs technical-evidence" in result.output


def test_docs_technical_evidence_respects_allowed_addon_dirs(tmp_path: Path) -> None:
    runner = CliRunner()
    addon_root = tmp_path / "addons" / "my_partner"
    _make_technical_addon_root(addon_root)
    config = {
        "db_name": "test_db",
        "addons_path": str(tmp_path / "addons"),
        "odoo_bin": "/usr/bin/odoo-bin",
        "python_bin": "/usr/bin/python3",
        "documentation": {"allowed_addon_dirs": ["other_addons"]},
    }
    loader = MagicMock()
    loader.load_config.return_value = config
    with (
        patch("oduit.cli.app.ConfigLoader", return_value=loader),
        patch("oduit.cli.app.OdooOperations") as mock_ops_class,
    ):
        ops = MagicMock()
        ops.write_technical_evidence.side_effect = ValueError(
            "outside [documentation].allowed_addon_dirs"
        )
        mock_ops_class.return_value = ops
        result = runner.invoke(
            app,
            [
                "--env",
                "dev",
                "docs",
                "technical-evidence",
                "my_partner",
                "--output-in-addon",
            ],
        )
    assert result.exit_code == 2
    assert "allowed_addon_dirs" in result.output
