ModuleManager
=============

``ModuleManager`` is the addon discovery and dependency-analysis API.

.. automodule:: oduit.module_manager
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

.. code-block:: python

   from oduit import ConfigLoader, ModuleManager

   loader = ConfigLoader()
   config = loader.load_config("dev")
   manager = ModuleManager(config["addons_path"])

   addons = manager.find_modules()
   sale_manifest = manager.get_manifest("sale")
   install_order = manager.get_install_order("sale", "purchase")
   reverse_deps = manager.get_reverse_dependencies("sale")

Key Methods
-----------

- ``find_module_dirs()`` and ``find_modules()``: discover addons from ``addons_path``
- ``find_module_path()`` and ``get_manifest()``: inspect one addon
- ``get_module_codependencies()``: direct manifest ``depends`` entries; maintained
  for compatibility with older naming
- ``get_direct_dependencies()``: direct external dependencies for one or more
  target addons
- ``get_dependency_tree()`` and ``get_formatted_dependency_tree()``: dependency trees
- ``get_install_order()``: dependency-resolved installation order
- ``get_reverse_dependencies()``: reverse-dependency and update impact analysis
- ``find_missing_dependencies()``: missing addon detection
- ``detect_odoo_series()``: infer Odoo series from addon versions
