# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
import tempfile

import pytest

from oduit.manifest import (
    InvalidManifestError,
    Manifest,
    ManifestNotFoundError,
)


class TestManifest:
    """Tests for the Manifest class"""

    def test_from_dict_creation(self):
        """Test creating a Manifest from a dictionary"""
        data = {
            "name": "Test Module",
            "version": "1.0.0",
            "depends": ["base"],
            "installable": True,
            "auto_install": False,
        }

        manifest = Manifest.from_dict(data, "test_module")

        assert manifest.name == "Test Module"
        assert manifest.version == "1.0.0"
        assert manifest.codependencies == ["base"]
        assert manifest.installable is True
        assert manifest.auto_install is False

    def test_manifest_properties_with_defaults(self):
        """Test manifest properties with default values"""
        data = {}  # Empty manifest

        manifest = Manifest.from_dict(data, "test_module")

        assert manifest.name == "test_module"  # Falls back to module_name
        assert manifest.version == "1.0.0"
        assert manifest.codependencies == []
        assert manifest.installable is True  # Default value
        assert manifest.auto_install is False  # Default value
        assert manifest.summary == ""
        assert manifest.description == ""
        assert manifest.author == ""
        assert manifest.website == ""
        assert manifest.license == ""

    def test_dependencies_validation(self):
        """Test that dependencies are properly validated"""
        # Test with non-list depends
        data = {"depends": "not_a_list"}
        manifest = Manifest.from_dict(data)
        assert manifest.codependencies == []

        # Test with mixed types in list
        data = {"depends": ["base", 123, "web", None, "sale"]}
        manifest = Manifest.from_dict(data)
        assert manifest.codependencies == ["base", "web", "sale"]

    def test_external_dependencies(self):
        """Test external dependencies parsing"""
        data = {
            "external_dependencies": {
                "python": ["requests", "lxml"],
                "bin": ["wkhtmltopdf", "curl"],
            }
        }

        manifest = Manifest.from_dict(data)

        assert manifest.python_dependencies == ["requests", "lxml"]
        assert manifest.binary_dependencies == ["wkhtmltopdf", "curl"]
        assert manifest.external_dependencies == data["external_dependencies"]

    def test_has_dependency(self):
        """Test dependency checking"""
        data = {"depends": ["base", "web", "sale"]}
        manifest = Manifest.from_dict(data)

        assert manifest.has_dependency("base") is True
        assert manifest.has_dependency("web") is True
        assert manifest.has_dependency("nonexistent") is False

    def test_validate_structure(self):
        """Test manifest structure validation"""
        # Valid manifest
        data = {
            "name": "Test Module",
            "version": "1.0.0",
            "summary": "A test module",
            "depends": ["base"],
        }
        manifest = Manifest.from_dict(data)
        warnings = manifest.validate_structure()
        assert warnings == []

        # Missing required fields
        data = {"depends": "not_a_list"}  # Also has invalid depends
        manifest = Manifest.from_dict(data)
        warnings = manifest.validate_structure()
        assert "Missing 'name' field" in warnings
        assert "Missing 'version' field" in warnings
        assert "Missing 'summary' or 'description' field" in warnings
        assert "'depends' field should be a list" in warnings

    def test_string_representations(self):
        """Test string and repr methods"""
        data = {"name": "Test Module", "version": "2.0.0"}
        manifest = Manifest.from_dict(data, "test_module")

        str_repr = str(manifest)
        assert "test_module" in str_repr
        assert "Test Module" in str_repr
        assert "2.0.0" in str_repr

        repr_str = repr(manifest)
        assert "Manifest" in repr_str
        assert "/mock/path/test_module" in repr_str

    def test_get_raw_data(self):
        """Test getting raw manifest data"""
        data = {"name": "Test Module", "version": "1.0.0", "depends": ["base"]}
        manifest = Manifest.from_dict(data)
        raw_data = manifest.get_raw_data()

        assert raw_data == data
        assert raw_data is not data  # Should be a copy

    def test_load_manifest_file_not_found(self):
        """Test loading manifest when file doesn't exist"""
        with pytest.raises(ManifestNotFoundError):
            Manifest("/nonexistent/path")

    def test_load_manifest_with_real_file(self):
        """Test loading manifest from actual file"""
        manifest_content = """
{
    'name': 'Test Module',
    'version': '1.0.0',
    'depends': ['base', 'web'],
    'installable': True,
    'summary': 'Test module summary'
}
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = os.path.join(temp_dir, "__manifest__.py")
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(manifest_content)

            manifest = Manifest(temp_dir)

            assert manifest.name == "Test Module"
            assert manifest.version == "1.0.0"
            assert manifest.codependencies == ["base", "web"]
            assert manifest.installable is True
            assert manifest.summary == "Test module summary"

    def test_load_manifest_invalid_syntax(self):
        """Test loading manifest with invalid Python syntax"""
        manifest_content = "{'name': 'Test', invalid_syntax"

        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = os.path.join(temp_dir, "__manifest__.py")
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(manifest_content)

            with pytest.raises(InvalidManifestError):
                Manifest(temp_dir)

    def test_load_manifest_not_dict(self):
        """Test loading manifest that doesn't evaluate to a dict"""
        manifest_content = "['not', 'a', 'dict']"

        with tempfile.TemporaryDirectory() as temp_dir:
            manifest_path = os.path.join(temp_dir, "__manifest__.py")
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(manifest_content)

            with pytest.raises(InvalidManifestError):
                Manifest(temp_dir)

    def test_is_installable_alias(self):
        """Test that is_installable() is an alias for installable property"""
        data = {"installable": False}
        manifest = Manifest.from_dict(data)

        assert manifest.is_installable() is False
        assert manifest.installable is False
