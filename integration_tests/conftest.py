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


def _ensure_integration_database(config: dict[str, Any]) -> None:
    db_name = config.get("db_name")
    if not db_name:
        return

    ops = OdooOperations(config, verbose=False)
    exists_result = ops.db_exists(with_sudo=False, suppress_output=True)
    create_result: dict[str, Any] = {}
    if not (exists_result.get("success", False) and exists_result.get("exists", False)):
        create_result = ops.create_db(
            with_sudo=True,
            suppress_output=True,
            db_user=str(config.get("db_user")) if config.get("db_user") else None,
        )
        exists_after_create = ops.db_exists(with_sudo=False, suppress_output=True)
        if not (
            exists_after_create.get("success", False)
            and exists_after_create.get("exists", False)
        ):
            reason = (
                create_result.get("error")
                or exists_after_create.get("error")
                or exists_result.get("error")
                or f"Database '{db_name}' is unavailable"
            )
            pytest.skip(f"Integration database is unavailable: {reason}")

    base_state = ops.get_addon_install_state("base")
    if base_state.success and base_state.installed:
        return

    init_result = ops.install_module("base", suppress_output=True)
    base_state_after_init = ops.get_addon_install_state("base")
    if base_state_after_init.success and base_state_after_init.installed:
        return

    reason = (
        init_result.get("error")
        or base_state_after_init.error
        or base_state.error
        or create_result.get("error")
        or exists_result.get("error")
        or f"Database '{db_name}' is unavailable or not initialized"
    )
    pytest.skip(f"Integration database is unavailable: {reason}")


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

    _ensure_integration_database(config)

    return config


@pytest.fixture
def myaddons_path() -> Path:
    return Path(__file__).parent / "myaddons"


def pytest_configure(config: Any) -> None:
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring real Odoo"
    )
