# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import ast
import os
from typing import Any


class ManifestError(Exception):
    """Base exception for manifest-related errors."""


class InvalidManifestError(ManifestError):
    """Raised when manifest contains invalid syntax or structure."""


class ManifestNotFoundError(ManifestError):
    """Raised when manifest file is not found."""


class Manifest:
    """Represents an Odoo module manifest (__manifest__.py)."""

    def __init__(self, module_path: str):
        """Initialize Manifest from a module directory path.

        Args:
            module_path: Absolute path to the module directory

        Raises:
            ManifestNotFoundError: If __manifest__.py is not found
            InvalidManifestError: If manifest contains invalid syntax or structure
        """
        self.module_path = module_path
        self.module_name = os.path.basename(module_path)
        self._data = self._load_manifest()

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], module_name: str = "test_module"
    ) -> "Manifest":
        """Create a Manifest instance from a dictionary (primarily for testing).

        Args:
            data: Dictionary containing manifest data
            module_name: Name of the module (for testing purposes)

        Returns:
            Manifest instance
        """
        # Create a mock instance without loading from file
        instance = cls.__new__(cls)
        instance.module_path = f"/mock/path/{module_name}"
        instance.module_name = module_name
        instance._data = data
        return instance

    def _load_manifest(self) -> dict[str, Any]:
        """Load and parse the __manifest__.py file.

        Returns:
            Dictionary containing manifest data

        Raises:
            ManifestNotFoundError: If __manifest__.py is not found
            InvalidManifestError: If manifest contains invalid syntax or structure
        """
        manifest_path = os.path.join(self.module_path, "__manifest__.py")

        if not os.path.exists(manifest_path):
            raise ManifestNotFoundError(f"Manifest file not found: {manifest_path}")

        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest_content = f.read()

            # Use ast.literal_eval for safe evaluation of Python literals
            manifest_dict = ast.literal_eval(manifest_content)

            # Validate that we got a dictionary
            if not isinstance(manifest_dict, dict):
                raise InvalidManifestError(
                    f"Manifest for {self.module_name} is not a dictionary"
                )

            return manifest_dict

        except FileNotFoundError as e:
            raise ManifestNotFoundError(
                f"Manifest file not found: {manifest_path}"
            ) from e
        except (SyntaxError, ValueError) as e:
            raise InvalidManifestError(
                f"Invalid manifest syntax in {self.module_name}: {e}"
            ) from e
        except Exception as e:
            raise InvalidManifestError(
                f"Error parsing manifest for {self.module_name}: {e}"
            ) from e

    @property
    def name(self) -> str:
        """Get the module name from manifest or use directory name as fallback."""
        return self._data.get("name", self.module_name)

    @property
    def version(self) -> str:
        """Get the module version."""
        return self._data.get("version", "1.0.0")

    @property
    def dependencies(self) -> list[str]:
        """Get direct dependencies from manifest 'depends' field.

        Returns:
            List of dependency module names, empty list if no dependencies
        """
        depends = self._data.get("depends", [])

        # Ensure depends is a list and contains only strings
        if not isinstance(depends, list):
            return []

        return [dep for dep in depends if isinstance(dep, str)]

    @property
    def installable(self) -> bool:
        """Check if the module is installable."""
        return self._data.get("installable", True)

    @property
    def auto_install(self) -> bool:
        """Check if the module is auto-installable."""
        return self._data.get("auto_install", False)

    @property
    def summary(self) -> str:
        """Get the module summary/description."""
        return self._data.get("summary", "")

    @property
    def description(self) -> str:
        """Get the module description."""
        return self._data.get("description", "")

    @property
    def author(self) -> str:
        """Get the module author."""
        return self._data.get("author", "")

    @property
    def website(self) -> str:
        """Get the module website."""
        return self._data.get("website", "")

    @property
    def license(self) -> str:
        """Get the module license."""
        return self._data.get("license", "")

    @property
    def external_dependencies(self) -> dict[str, list[str]]:
        """Get external dependencies (python packages, system binaries)."""
        return self._data.get("external_dependencies", {})

    @property
    def python_dependencies(self) -> list[str]:
        """Get Python package dependencies."""
        return self.external_dependencies.get("python", [])

    @property
    def binary_dependencies(self) -> list[str]:
        """Get system binary dependencies."""
        return self.external_dependencies.get("bin", [])

    def get_raw_data(self) -> dict[str, Any]:
        """Get the raw manifest data dictionary."""
        return self._data.copy()

    def is_installable(self) -> bool:
        """Check if the module is installable (alias for installable property)."""
        return self.installable

    def has_dependency(self, dependency_name: str) -> bool:
        """Check if the module has a specific dependency.

        Args:
            dependency_name: Name of the dependency to check for

        Returns:
            True if the dependency exists, False otherwise
        """
        return dependency_name in self.dependencies

    def validate_structure(self) -> list[str]:
        """Validate the manifest structure and return any warnings.

        Returns:
            List of validation warnings (empty if no issues)
        """
        warnings = []

        # Check for required fields in raw data
        if "name" not in self._data:
            warnings.append("Missing 'name' field")

        if "version" not in self._data:
            warnings.append("Missing 'version' field")

        # Check for recommended fields
        if not self.summary and not self.description:
            warnings.append("Missing 'summary' or 'description' field")

        # Check dependencies format
        depends = self._data.get("depends")
        if depends is not None and not isinstance(depends, list):
            warnings.append("'depends' field should be a list")

        return warnings

    def __str__(self) -> str:
        """String representation of the manifest."""
        return f"Manifest({self.module_name}: {self.name} v{self.version})"

    def __repr__(self) -> str:
        """Developer representation of the manifest."""
        return f"Manifest(module_path='{self.module_path}')"
