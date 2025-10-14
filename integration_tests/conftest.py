import os
from pathlib import Path
from typing import Any

import pytest

from oduit.config_loader import ConfigLoader


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

    return config


@pytest.fixture
def myaddons_path() -> Path:
    return Path(__file__).parent / "myaddons"


def pytest_configure(config: Any) -> None:
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring real Odoo"
    )
