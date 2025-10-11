# Copyright (C) 2025 The ODUIT Authors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at https://mozilla.org/MPL/2.0/.

import os
from pathlib import Path
from typing import Any

from manifestoo_core.exceptions import InvalidManifest as ManifestooInvalidManifest
from manifestoo_core.manifest import Manifest as ManifestooManifest
from manifestoo_core.manifest import get_manifest_path


class ManifestError(Exception):
    """Base exception for manifest-related errors."""


class InvalidManifestError(ManifestError):
    """Raised when manifest contains invalid syntax or structure."""


class ManifestNotFoundError(ManifestError):
    """Raised when manifest file is not found."""


class Manifest:
    """Represents an Odoo module manifest (__manifest__.py).

    This is a wrapper around manifestoo-core's Manifest class that provides
    backward compatibility with the original oduit API.
    """

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
        self._manifestoo = self._load_manifest()

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
        instance = cls.__new__(cls)
        instance.module_path = f"/mock/path/{module_name}"
        instance.module_name = module_name
        try:
            instance._manifestoo = ManifestooManifest.from_dict(data)
        except ManifestooInvalidManifest as e:
            raise InvalidManifestError(str(e)) from e
        return instance

    def _load_manifest(self) -> ManifestooManifest:
        """Load and parse the __manifest__.py file.

        Returns:
            ManifestooManifest instance

        Raises:
            ManifestNotFoundError: If __manifest__.py is not found
            InvalidManifestError: If manifest contains invalid syntax or structure
        """
        module_path_obj = Path(self.module_path)
        manifest_path = get_manifest_path(module_path_obj)

        if manifest_path is None:
            raise ManifestNotFoundError(
                f"Manifest file not found in: {self.module_path}"
            )

        try:
            return ManifestooManifest.from_file(manifest_path)
        except ManifestooInvalidManifest as e:
            raise InvalidManifestError(
                f"Invalid manifest in {self.module_name}: {e}"
            ) from e
        except Exception as e:
            raise InvalidManifestError(
                f"Error parsing manifest for {self.module_name}: {e}"
            ) from e

    @property
    def name(self) -> str:
        """Get the module name from manifest or use directory name as fallback."""
        manifest_name = self._manifestoo.name
        return manifest_name if manifest_name else self.module_name

    @property
    def version(self) -> str:
        """Get the module version."""
        version = self._manifestoo.version
        return version if version else "1.0.0"

    @property
    def codependencies(self) -> list[str]:
        """Get codependencies from manifest 'depends' field.

        Codependencies are modules that this module depends on, meaning changes
        to those modules may impact this module.

        Returns:
            List of codependency module names, empty list if no codependencies
        """
        depends = self._manifestoo.manifest_dict.get("depends", [])

        if not isinstance(depends, list):
            return []

        return [dep for dep in depends if isinstance(dep, str)]

    @property
    def installable(self) -> bool:
        """Check if the module is installable."""
        return self._manifestoo.installable

    @property
    def auto_install(self) -> bool:
        """Check if the module is auto-installable."""
        auto_install = self._manifestoo.manifest_dict.get("auto_install", False)
        if isinstance(auto_install, bool):
            return auto_install
        return False

    @property
    def summary(self) -> str:
        """Get the module summary/description."""
        summary = self._manifestoo.summary
        return summary if summary else ""

    @property
    def description(self) -> str:
        """Get the module description."""
        description = self._manifestoo.description
        return description if description else ""

    @property
    def author(self) -> str:
        """Get the module author."""
        author = self._manifestoo.author
        return author if author else ""

    @property
    def website(self) -> str:
        """Get the module website."""
        website = self._manifestoo.website
        return website if website else ""

    @property
    def license(self) -> str:
        """Get the module license."""
        license_str = self._manifestoo.license
        return license_str if license_str else ""

    @property
    def external_dependencies(self) -> dict[str, list[str]]:
        """Get external dependencies (python packages, system binaries)."""
        ext_deps = self._manifestoo.external_dependencies
        result: dict[str, list[str]] = {}
        for key, value in ext_deps.items():
            if isinstance(value, list):
                result[key] = [str(v) for v in value if isinstance(v, str)]
        return result

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
        return self._manifestoo.manifest_dict.copy()

    def is_installable(self) -> bool:
        """Check if the module is installable (alias for installable property)."""
        return self.installable

    def has_dependency(self, dependency_name: str) -> bool:
        """Check if the module has a specific codependency.

        Args:
            dependency_name: Name of the codependency to check for

        Returns:
            True if the codependency exists, False otherwise
        """
        return dependency_name in self.codependencies

    def validate_structure(self) -> list[str]:
        """Validate the manifest structure and return any warnings.

        Returns:
            List of validation warnings (empty if no issues)
        """
        warnings = []
        raw_data = self._manifestoo.manifest_dict

        if "name" not in raw_data:
            warnings.append("Missing 'name' field")

        if "version" not in raw_data:
            warnings.append("Missing 'version' field")

        if not self.summary and not self.description:
            warnings.append("Missing 'summary' or 'description' field")

        depends = raw_data.get("depends")
        if depends is not None and not isinstance(depends, list):
            warnings.append("'depends' field should be a list")

        return warnings

    def __str__(self) -> str:
        """String representation of the manifest."""
        return f"Manifest({self.module_name}: {self.name} v{self.version})"

    def __repr__(self) -> str:
        """Developer representation of the manifest."""
        return f"Manifest(module_path='{self.module_path}')"
