# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.


from manifestoo_core.odoo_series import OdooSeries

from oduit.module_manager import ModuleManager


def test_detect_odoo_series_from_modules(tmp_path):
    """Test detecting Odoo series from module versions."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "16.0.1.0.0", "depends": ["base"]}'
    )

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "16.0.2.0.0", "depends": ["module_a"]}'
    )

    manager = ModuleManager(str(addon_dir))
    series = manager.detect_odoo_series()

    assert series == OdooSeries.v16_0


def test_detect_odoo_series_returns_none_for_invalid_versions(tmp_path):
    """Test that detect_odoo_series returns None for invalid versions."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0", "depends": ["base"]}'
    )

    manager = ModuleManager(str(addon_dir))
    series = manager.detect_odoo_series()

    assert series is None


def test_detect_odoo_series_empty_directory(tmp_path):
    """Test detect_odoo_series with no modules."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    manager = ModuleManager(str(addon_dir))
    series = manager.detect_odoo_series()

    assert series is None


def test_get_module_version_display_custom_addon(tmp_path):
    """Test version display for custom addons."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.2.3", "depends": ["base"]}'
    )

    manager = ModuleManager(str(addon_dir))
    version = manager.get_module_version_display("module_a")

    assert version == "1.2.3"


def test_get_module_version_display_missing_addon(tmp_path):
    """Test version display for missing addons."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    manager = ModuleManager(str(addon_dir))
    version = manager.get_module_version_display("nonexistent")

    assert version == "✘ not installed"


def test_get_module_version_display_core_ce_addon(tmp_path):
    """Test version display for core CE addons."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    sale_module = addon_dir / "sale"
    sale_module.mkdir()
    (sale_module / "__manifest__.py").write_text(
        '{"name": "Sales", "version": "16.0.1.0.0", "depends": ["base"]}'
    )

    manager = ModuleManager(str(addon_dir))
    series = OdooSeries.v16_0
    version = manager.get_module_version_display("sale", series)

    assert version == "16.0+ce"


def test_get_module_version_display_core_ee_addon(tmp_path):
    """Test version display for core EE addons."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module = addon_dir / "sale_subscription"
    module.mkdir()
    (module / "__manifest__.py").write_text(
        '{"name": "Sale Subscription", "version": "16.0.1.0.0", "depends": ["sale"]}'
    )

    manager = ModuleManager(str(addon_dir))
    series = OdooSeries.v16_0
    version = manager.get_module_version_display("sale_subscription", series)

    assert version == "16.0+ee"


def test_get_module_version_display_auto_detect_series(tmp_path):
    """Test version display with auto-detection of series."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    sale_module = addon_dir / "sale"
    sale_module.mkdir()
    (sale_module / "__manifest__.py").write_text(
        '{"name": "Sales", "version": "16.0.1.0.0", "depends": ["base"]}'
    )

    custom_module = addon_dir / "my_custom"
    custom_module.mkdir()
    (custom_module / "__manifest__.py").write_text(
        '{"name": "My Custom", "version": "1.0.0", "depends": ["sale"]}'
    )

    manager = ModuleManager(str(addon_dir))

    sale_version = manager.get_module_version_display("sale")
    assert sale_version == "16.0+ce"

    custom_version = manager.get_module_version_display("my_custom")
    assert custom_version == "1.0.0"


def test_get_formatted_dependency_tree(tmp_path):
    """Test formatted dependency tree output."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "16.0.1.0.0", "depends": ["base"]}'
    )

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "1.0.0", "depends": ["module_a"]}'
    )

    manager = ModuleManager(str(addon_dir))
    lines = manager.get_formatted_dependency_tree("module_b")

    assert len(lines) > 0
    assert any("module_b" in line for line in lines)
    assert any("module_a" in line for line in lines)
    assert any("1.0.0" in line for line in lines)
    assert any("16.0.1.0.0" in line for line in lines)


def test_get_formatted_dependency_tree_with_max_depth(tmp_path):
    """Test formatted dependency tree with depth limit."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "16.0.1.0.0", "depends": ["base"]}'
    )

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "16.0.2.0.0", "depends": ["module_a"]}'
    )

    module_c = addon_dir / "module_c"
    module_c.mkdir()
    (module_c / "__manifest__.py").write_text(
        '{"name": "Module C", "version": "16.0.3.0.0", "depends": ["module_b"]}'
    )

    manager = ModuleManager(str(addon_dir))
    lines = manager.get_formatted_dependency_tree("module_c", max_depth=1)

    assert len(lines) > 0
    assert any("module_c" in line for line in lines)
    assert any("module_b" in line for line in lines)
