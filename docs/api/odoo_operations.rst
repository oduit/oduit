OdooOperations
==============

``OdooOperations`` provides the preferred high-level Python API for running
Odoo, installing or updating addons, running tests, planning addon changes,
and performing safe read-only inspection.

For read-only data access inside Odoo models, prefer ``OdooQuery``. Use
``execute_python_code()`` only for trusted shell-driven execution flows, with
either an explicit ``shell_interface=...`` argument or ``shell_interface`` set
in the environment configuration.

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

   context = ops.get_environment_context(env_name="dev", config_source="env")
   addon = ops.inspect_addon("sale")
   plan = ops.plan_update("sale")
   state = ops.get_addon_install_state("sale")
   installed_addons = ops.list_installed_addons(modules=["sale"])
   partners = ops.query_model("res.partner", fields=["name", "email"], limit=5)

Key Methods
-----------

- ``run_odoo()``: start the Odoo server
- ``run_shell()``: start an Odoo shell or handle piped shell input
- ``install_module()`` and ``update_module()``: addon lifecycle operations
- ``run_tests()``: run test selections with parsed failure output
- ``create_db()``, ``drop_db()``, ``list_db()``, ``db_exists()``: database helpers
- ``create_addon()`` and ``export_module_language()``: addon development helpers
- ``get_odoo_version()``: detect the Odoo version from ``odoo-bin``
- ``get_environment_context()``: return typed environment facts for planning
- ``inspect_addon()`` and ``plan_update()``: return typed addon inspection and
  update-planning models
- ``get_addon_install_state()`` and ``list_installed_addons()``: typed runtime
  addon install-state inspection helpers
- ``query_model()``, ``read_record()``, ``search_count()``, ``get_model_fields()``:
  typed convenience wrappers around ``OdooQuery``
- ``execute_python_code()``: execute arbitrary trusted Python through the Odoo
  shell interface, with an explicit or configured ``shell_interface``

Preferred Public Python Surface
-------------------------------

- ``ConfigLoader`` for loading environment or local configuration
- ``OdooOperations`` for the main command-oriented and typed inspection API
- ``OdooQuery`` when you want direct safe read-only query helpers
- ``ModuleManager`` and ``AddonsPathManager`` for lower-level addon analysis

Safe vs Unsafe Paths
--------------------

- Prefer ``OdooOperations.get_environment_context()``, ``inspect_addon()``,
  ``plan_update()``, ``get_addon_install_state()``, ``list_installed_addons()``,
  and the query delegation helpers for inspection and planning
- Prefer ``OdooQuery`` for direct structured read-only model access
- Use ``execute_python_code()`` only for trusted shell-driven snippets and set
  ``shell_interface`` explicitly or in configuration
- Use ``OdooCodeExecutor`` only when you explicitly need arbitrary execution and
  understand the ``allow_unsafe=True`` contract
