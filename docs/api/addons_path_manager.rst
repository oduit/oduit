AddonsPathManager
==================

The AddonsPathManager class manages discovery and loading of Odoo modules from addons paths.

.. automodule:: oduit.addons_path_manager
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:

Class Reference
---------------

.. autoclass:: oduit.addons_path_manager.AddonsPathManager
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:

Usage Examples
--------------

Basic Path Management
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.addons_path_manager import AddonsPathManager

   # Initialize with comma-separated paths
   manager = AddonsPathManager('/path/to/addons1,/path/to/addons2')

   # Get all paths (configured + base Odoo paths)
   all_paths = manager.get_all_paths()
   print(f"All addon paths: {all_paths}")

   # Get only configured paths
   configured = manager.get_configured_paths()
   print(f"Configured paths: {configured}")

Finding Modules
~~~~~~~~~~~~~~~

.. code-block:: python

   # Find a specific module
   module_path = manager.find_module_path('sale')
   if module_path:
       print(f"Found sale module at: {module_path}")

   # Get manifest for a module
   manifest = manager.get_manifest('sale')
   if manifest:
       print(f"Sale module version: {manifest.version}")

Working with Collections
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Get collection from specific path
   collection = manager.get_collection_from_path('/path/to/addons')
   print(f"Found {len(collection)} modules")

   # Get all collections from all paths
   all_collections = manager.get_all_collections()

   # Filter by directory
   filtered = manager.get_collection_by_filter('myaddons')
   for module_name in filtered:
       print(f"Module: {module_name}")

   # Get module names
   module_names = manager.get_module_names()
   print(f"All modules: {module_names}")

   # Get module names from specific directory
   custom_modules = manager.get_module_names(filter_dir='myaddons')
   print(f"Custom modules: {custom_modules}")
