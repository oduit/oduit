OdooOperations
==============

``OdooOperations`` provides the high-level command-oriented API for running
Odoo, installing or updating addons, running tests, and handling database
operations.

.. automodule:: oduit.odoo_operations
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

.. code-block:: python

   from oduit import ConfigLoader, OdooOperations

   loader = ConfigLoader()
   config = loader.load_config("dev")
   ops = OdooOperations(config, verbose=True)

   install_result = ops.install_module("sale")
   update_result = ops.update_module("sale")
   test_result = ops.run_tests(module="sale")
   version_result = ops.get_odoo_version(suppress_output=True)
   db_result = ops.db_exists(suppress_output=True)

Key Methods
-----------

- ``run_odoo()``: start the Odoo server
- ``run_shell()``: start an Odoo shell or handle piped shell input
- ``install_module()`` and ``update_module()``: addon lifecycle operations
- ``run_tests()``: run test selections with parsed failure output
- ``create_db()``, ``drop_db()``, ``list_db()``, ``db_exists()``: database helpers
- ``create_addon()`` and ``export_module_language()``: addon development helpers
- ``get_odoo_version()``: detect the Odoo version from ``odoo-bin``
- ``execute_python_code()``: execute Python through the Odoo shell interface
