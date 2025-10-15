import os
from pathlib import Path
from typing import Any

import pytest

from oduit.config_loader import ConfigLoader
from oduit.odoo_operations import OdooOperations


def _generate_manifests_from_templates(odoo_version: str) -> None:
    integration_dir = Path(__file__).parent
    myaddons_dir = integration_dir / "myaddons"

    for template_path in myaddons_dir.rglob("__manifest__.py.tmpl"):
        content = template_path.read_text()
        generated_content = content.replace("{odoo_major}", odoo_version)

        manifest_path = template_path.with_suffix("")
        manifest_path.write_text(generated_content)


@pytest.fixture
def integration_config() -> dict[str, Any]:
    integration_dir = Path(__file__).parent
    config_path = integration_dir / ".oduit.toml"

    if not config_path.exists():
        pytest.skip(f"Integration config not found at {config_path}")

    original_dir = os.getcwd()
    try:
        os.chdir(integration_dir)
        config_loader = ConfigLoader()
        config = config_loader.load_local_config()
    finally:
        os.chdir(original_dir)

    odoo_bin = config.get("odoo_bin")
    if not odoo_bin or not Path(odoo_bin).exists():
        pytest.skip(f"Odoo binary not found at {odoo_bin}")

    python_bin = config.get("python_bin")
    if not python_bin or not Path(python_bin).exists():
        pytest.skip(f"Python binary not found at {python_bin}")

    ops = OdooOperations(config, verbose=False)
    result = ops.get_odoo_version(suppress_output=True)

    if result.get("success", False) and result.get("version"):
        odoo_version = result["version"]
        _generate_manifests_from_templates(odoo_version)

    return config


@pytest.fixture
def myaddons_path() -> Path:
    return Path(__file__).parent / "myaddons"


def pytest_configure(config: Any) -> None:
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring real Odoo"
    )
