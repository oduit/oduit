# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.


import pytest

from oduit.cli_types import SortingChoice
from oduit.module_manager import ModuleManager


def test_sort_modules_alphabetical(tmp_path):
    """Test alphabetical sorting of modules."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    for name in ["zebra", "apple", "banana"]:
        module = addon_dir / name
        module.mkdir()
        (module / "__manifest__.py").write_text(
            f'{{"name": "{name.title()}", "version": "1.0.0"}}'
        )

    manager = ModuleManager(str(addon_dir))
    modules = ["zebra", "apple", "banana"]

    sorted_modules = manager.sort_modules(modules, SortingChoice.ALPHABETICAL)
    assert sorted_modules == ["apple", "banana", "zebra"]


def test_sort_modules_alphabetical_string(tmp_path):
    """Test alphabetical sorting with string parameter."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    for name in ["c", "a", "b"]:
        module = addon_dir / name
        module.mkdir()
        (module / "__manifest__.py").write_text(
            f'{{"name": "{name}", "version": "1.0.0"}}'
        )

    manager = ModuleManager(str(addon_dir))
    modules = ["c", "a", "b"]

    sorted_modules = manager.sort_modules(modules, "alphabetical")
    assert sorted_modules == ["a", "b", "c"]


def test_sort_modules_topological_no_deps(tmp_path):
    """Test topological sorting with no dependencies."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    for name in ["z", "a", "m"]:
        module = addon_dir / name
        module.mkdir()
        (module / "__manifest__.py").write_text(
            f'{{"name": "{name}", "version": "1.0.0", "depends": []}}'
        )

    manager = ModuleManager(str(addon_dir))
    modules = ["z", "a", "m"]

    sorted_modules = manager.sort_modules(modules, SortingChoice.TOPOLOGICAL)
    assert set(sorted_modules) == {"z", "a", "m"}


def test_sort_modules_topological_with_deps(tmp_path):
    """Test topological sorting with dependencies."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0", "depends": []}'
    )

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "1.0.0", "depends": ["module_a"]}'
    )

    module_c = addon_dir / "module_c"
    module_c.mkdir()
    (module_c / "__manifest__.py").write_text(
        '{"name": "Module C", "version": "1.0.0", "depends": ["module_b"]}'
    )

    manager = ModuleManager(str(addon_dir))
    modules = ["module_c", "module_a", "module_b"]

    sorted_modules = manager.sort_modules(modules, SortingChoice.TOPOLOGICAL)
    assert sorted_modules.index("module_a") < sorted_modules.index("module_b")
    assert sorted_modules.index("module_b") < sorted_modules.index("module_c")


def test_sort_modules_topological_complex(tmp_path):
    """Test topological sorting with complex dependency graph."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    deps = {
        "base_module": [],
        "module_a": ["base_module"],
        "module_b": ["base_module"],
        "module_c": ["module_a", "module_b"],
        "module_d": ["module_c"],
    }

    for name, dependencies in deps.items():
        module = addon_dir / name
        module.mkdir()
        (module / "__manifest__.py").write_text(
            f'{{"name": "{name}", "version": "1.0.0", "depends": {dependencies}}}'
        )

    manager = ModuleManager(str(addon_dir))
    modules = list(deps.keys())

    sorted_modules = manager.sort_modules(modules, SortingChoice.TOPOLOGICAL)

    for module, dependencies in deps.items():
        for dep in dependencies:
            if dep in modules:
                assert sorted_modules.index(dep) < sorted_modules.index(module)


def test_sort_modules_topological_circular_dependency(tmp_path):
    """Test that circular dependencies are detected."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0", "depends": ["module_b"]}'
    )

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "1.0.0", "depends": ["module_a"]}'
    )

    manager = ModuleManager(str(addon_dir))
    modules = ["module_a", "module_b"]

    with pytest.raises(ValueError, match="Circular dependency"):
        manager.sort_modules(modules, SortingChoice.TOPOLOGICAL)


def test_sort_modules_topological_ignores_external_deps(tmp_path):
    """Test that topological sorting only considers deps within the module set."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()
    (module_a / "__manifest__.py").write_text(
        '{"name": "Module A", "version": "1.0.0", "depends": ["sale", "crm"]}'
    )

    module_b = addon_dir / "module_b"
    module_b.mkdir()
    (module_b / "__manifest__.py").write_text(
        '{"name": "Module B", "version": "1.0.0", "depends": ["module_a", "stock"]}'
    )

    manager = ModuleManager(str(addon_dir))
    modules = ["module_b", "module_a"]

    sorted_modules = manager.sort_modules(modules, SortingChoice.TOPOLOGICAL)
    assert sorted_modules.index("module_a") < sorted_modules.index("module_b")


def test_sort_modules_empty_list(tmp_path):
    """Test sorting an empty list."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    manager = ModuleManager(str(addon_dir))

    alphabetical = manager.sort_modules([], SortingChoice.ALPHABETICAL)
    assert alphabetical == []

    topological = manager.sort_modules([], SortingChoice.TOPOLOGICAL)
    assert topological == []


def test_sort_modules_missing_manifest(tmp_path):
    """Test topological sorting when a module has no manifest."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    module_a = addon_dir / "module_a"
    module_a.mkdir()

    manager = ModuleManager(str(addon_dir))
    modules = ["module_a"]

    sorted_modules = manager.sort_modules(modules, SortingChoice.TOPOLOGICAL)
    assert sorted_modules == ["module_a"]


def test_sort_modules_default_alphabetical(tmp_path):
    """Test that default sorting is alphabetical."""
    addon_dir = tmp_path / "addons"
    addon_dir.mkdir()

    for name in ["z", "a", "m"]:
        module = addon_dir / name
        module.mkdir()
        (module / "__manifest__.py").write_text(
            f'{{"name": "{name}", "version": "1.0.0"}}'
        )

    manager = ModuleManager(str(addon_dir))
    modules = ["z", "a", "m"]

    sorted_modules = manager.sort_modules(modules)
    assert sorted_modules == ["a", "m", "z"]
