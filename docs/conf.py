import os
import sys

sys.path.insert(0, os.path.abspath(".."))

project = "oduit"
copyright = "2025, The oduit Authors"
author = "The oduit Authors"

try:
    from oduit._version import __version__

    release = __version__
    version = ".".join(__version__.split(".")[:2])
except ImportError:
    release = "0.1.0"
    version = "0.1"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinx.ext.coverage",
    "myst_parser",
]

source_suffix = {
    ".md": "myst",
}

root_doc = "index"

templates_path = ["_templates"]
exclude_patterns = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "README.md",
    "maintainer/*.md",
]

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
}

napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True

intersphinx_mapping = {
    "python": ("https://docs.python.org/3/", None),
}

todo_include_todos = True

nitpick_ignore_regex = [
    ("py:class", r"manifestoo_core\.odoo_series\.OdooSeries"),
    ("py:class", r"typer\.models\.Context"),
    ("py:class", r"dict\[str.*"),
    ("py:class", r"list\[dict\[str.*"),
    ("py:class", r"'?Mapping\[str.*"),
    ("py:class", r"Dictionary with .*"),
    ("py:class", r"Dict containing .*"),
    ("py:class", r"Formatted version string"),
    (
        "py:class",
        r"oduit\.(config_provider\.ConfigProvider|base_process_manager\.BaseProcessManager|documentation_policy\.DocumentationDirectoryPolicy|manifest\.Manifest(?:Error)?|manifest_collection\.ManifestCollection|source_locator\.SourceScanCache|cli_types\.SortingChoice)",
    ),
    ("py:exc", r"ManifestError"),
    ("py:exc", r"ManifestNotFoundError"),
    ("py:exc", r"InvalidManifestError"),
]
