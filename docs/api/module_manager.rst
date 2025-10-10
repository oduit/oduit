ModuleManager
=============

The ModuleManager class handles module-specific operations and management.

.. automodule:: oduit.module_manager
   :members:
   :undoc-members:
   :show-inheritance:

Class Reference
---------------

.. autoclass:: oduit.ModuleManager
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

Basic Module Operations
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import ModuleManager, ConfigLoader

   loader = ConfigLoader()
   config = loader.load_config('dev')
   manager = ModuleManager(config)

   # List available modules
   modules = manager.list_modules()
   print(f"Available modules: {modules}")

   # Check module status
   status = manager.get_module_status('sale')
   print(f"Sale module status: {status}")

Module Discovery
~~~~~~~~~~~~~~~~

.. code-block:: python

   # Find modules in addon paths
   addons = manager.discover_addons()

   # Get module codependencies (what this module depends on)
   codeps = manager.get_module_codependencies('sale')
   print(f"Sale module codependencies: {codeps}")

   # Get direct dependencies (external modules needed)
   deps = manager.get_direct_dependencies('sale')
   print(f"Sale module direct dependencies: {deps}")

   # Validate module
   is_valid = manager.validate_module('my_custom_module')
   if is_valid:
       print("Module is valid")
