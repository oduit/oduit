OdooOperations
==============

The OdooOperations class provides high-level operations for managing Odoo instances.

.. automodule:: oduit.odoo_operations
   :members:
   :undoc-members:
   :show-inheritance:

Class Reference
---------------

.. autoclass:: oduit.OdooOperations
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

Module Management
~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import OdooOperations, ConfigLoader

   loader = ConfigLoader()
   config = loader.load_config('dev')
   ops = OdooOperations(config)

   # Install modules
   result = ops.install_modules(['sale', 'purchase'])
   if result['success']:
       print(f"Modules installed in {result['duration']} seconds")

   # Update modules
   result = ops.update_modules(['sale'])

   # Uninstall modules
   result = ops.uninstall_modules(['purchase'])

Database Operations
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Create database
   result = ops.create_database('new_db')

   # Drop database
   result = ops.drop_database('old_db')

   # Backup database
   result = ops.backup_database('backup_file.sql')

Testing Operations
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Run tests for modules
   result = ops.run_tests(['my_module'])

   # Run all tests
   result = ops.run_all_tests()
