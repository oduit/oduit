ManifestCollection
==================

The ManifestCollection class represents a collection of Odoo module manifests.

.. automodule:: oduit.manifest_collection
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:

Class Reference
---------------

.. autoclass:: oduit.manifest_collection.ManifestCollection
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:

Usage Examples
--------------

Basic Collection Operations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.manifest_collection import ManifestCollection
   from oduit.manifest import Manifest

   # Create a collection
   collection = ManifestCollection()

   # Add manifests
   manifest1 = Manifest('/path/to/module1')
   manifest2 = Manifest('/path/to/module2')
   collection.add('module1', manifest1)
   collection.add('module2', manifest2)

   # Check collection size
   print(f"Collection has {len(collection)} modules")

   # Check if module exists
   if 'module1' in collection:
       print("module1 is in collection")

Accessing Manifests
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Get a manifest
   manifest = collection.get('module1')
   if manifest:
       print(f"Version: {manifest.version}")

   # Using dict-like access
   manifest = collection['module1']

   # Iterate over module names
   for module_name in collection:
       print(f"Module: {module_name}")

   # Iterate over items
   for name, manifest in collection.items():
       print(f"{name}: {manifest.version}")

Filtering and Analysis
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Get all dependencies
   all_deps = collection.get_all_dependencies()
   print(f"All dependencies: {all_deps}")

   # Get installable addons
   installable = collection.get_installable_addons()
   print(f"Installable: {installable}")

   # Get auto-install addons
   auto_install = collection.get_auto_install_addons()
   print(f"Auto-install: {auto_install}")

   # Filter by dependency
   sale_dependent = collection.filter_by_dependency('sale')
   print(f"Modules depending on sale: {list(sale_dependent)}")

Validation
~~~~~~~~~~

.. code-block:: python

   # Validate all manifests
   issues = collection.validate_all()
   if issues:
       print("Validation issues found:")
       for addon_name, warnings in issues.items():
           print(f"  {addon_name}:")
           for warning in warnings:
               print(f"    - {warning}")
   else:
       print("All manifests are valid")

Collection Management
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Remove a manifest
   collection.remove('module1')

   # Clear all manifests
   collection.clear()

   # String representation
   print(collection)  # ManifestCollection(2 manifests)
   print(repr(collection))  # ManifestCollection([module1, module2])
