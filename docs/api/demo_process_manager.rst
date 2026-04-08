DemoProcessManager
==================

``DemoProcessManager`` simulates Odoo command execution for tests and demos.

.. automodule:: oduit.demo_process_manager
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

.. code-block:: python

   from oduit import DemoProcessManager
   from oduit.builders import InstallCommandBuilder

   config = {
       "python_bin": "python3",
       "odoo_bin": "odoo-bin",
       "db_name": "demo_db",
       "addons_path": "./addons",
       "demo_mode": True,
   }

   manager = DemoProcessManager(available_modules=["base", "sale", "purchase"])
   operation = InstallCommandBuilder(config, "sale").build_operation()
   result = manager.run_operation(operation)

   assert result["success"]

Notes
-----

- This is intended for simulated execution and test scenarios
- It is public, but separate from the supported runtime manager types exposed to
  users through normal process-manager selection
