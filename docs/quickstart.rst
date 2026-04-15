Quick Start Guide
=================

This guide shows the current recommended setup and the main user-facing
workflows.

Preferred Configuration
-----------------------

Use sectioned TOML for both local and named environments.

Local ``.oduit.toml``
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [binaries]
   python_bin = "./venv/bin/python"
   odoo_bin = "./odoo/odoo-bin"

   [odoo_params]
   addons_path = "./addons"
   db_name = "project_dev"

Then you can run commands without ``--env``:

.. code-block:: bash

   oduit doctor
   oduit version
   oduit list-addons

Named Environment Config
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: toml

   [binaries]
   python_bin = "/usr/bin/python3"
   odoo_bin = "/opt/odoo/odoo-bin"

   [odoo_params]
   addons_path = "/opt/odoo/addons,/opt/custom/addons"
   db_name = "odoo_dev"
   db_user = "odoo"

Save that as ``~/.config/oduit/dev.toml`` and use it with:

.. code-block:: bash

   oduit --env dev doctor
   oduit --env dev run

CLI Workflows
-------------

Diagnostics and Version Detection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   oduit --env dev doctor
   oduit --env dev version

Addon Intelligence
~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   oduit --env dev list-addons
   oduit --env dev print-manifest sale
   oduit --env dev list-manifest-values category
   oduit --env dev list-depends sale
   oduit --env dev install-order sale,purchase
   oduit --env dev impact-of-update sale
   oduit --env dev docs addon sale --source-only
   oduit --env dev docs addons --select-dir myaddons --output-dir ./docs-out
   oduit --env dev docs dependency-graph --modules sale,purchase

Operations
~~~~~~~~~~

.. code-block:: bash

   oduit --env dev install sale
   oduit --env dev update sale
   oduit --env dev test --test-tags /sale
   oduit --env dev shell

Runtime Inspection and Trusted Execution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   oduit --env dev exec "env['res.partner']._table"
   oduit --env dev inspect ref base.action_partner_form
   oduit --env dev inspect model res.partner
   oduit --env dev inspect field res.partner email --with-db
   oduit --env dev db table res_partner
   oduit --env dev performance table-scans
   oduit --env dev manifest check sale

Prefer the first-class ``inspect`` / ``db`` / ``performance`` commands before
falling back to ``exec``. ``exec`` and ``inspect recordset`` are trusted
arbitrary execution surfaces and keep rollback-by-default semantics unless
``--commit`` is passed explicitly.

Agent Workflow
~~~~~~~~~~~~~~

``oduit agent ...`` is the primary automation surface for external coding
agents. For the full workflow and JSON contract, see
:doc:`agent_contract`.

.. code-block:: bash

   oduit --env dev agent context
   oduit --env dev agent inspect-addon my_partner
   oduit --env dev agent addon-doc my_partner
   oduit --env dev agent inspect-ref base.action_partner_form
   oduit --env dev agent inspect-model res.partner
   oduit --env dev agent inspect-field res.partner email --with-db
   oduit --env dev agent db-table res_partner
   oduit --env dev agent manifest-check sale
   oduit --env dev agent get-model-fields res.partner --attributes string,type,required
   oduit --env dev agent locate-model res.partner --module my_partner
   oduit --env dev agent locate-field res.partner email3 --module my_partner
   oduit --env dev agent list-addon-tests my_partner --model res.partner --field email3
   oduit --env dev agent validate-addon-change my_partner --allow-mutation --install-if-needed --update --discover-tests
   oduit --env dev agent test-summary --module my_partner --test-tags /my_partner

Use the explicit runtime DB flags in your config when you want stronger guards:
``write_protect_db`` and ``agent_write_protect_db`` block runtime DB mutation,
while ``needs_mutation_flag`` and ``agent_needs_mutation_flag`` require
``--allow-mutation`` for the matching caller.

Python API
----------

High-level Operations
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import ConfigLoader, OdooOperations

   loader = ConfigLoader()
   config = loader.load_config("dev")
   ops = OdooOperations(config, verbose=True)

   result = ops.install_module("sale")
   version = ops.get_odoo_version(suppress_output=True)
   model = ops.inspect_model("res.partner")
   field = ops.inspect_field("res.partner", "email", with_db=True)
   addon_docs = ops.build_addon_documentation("sale", source_only=True)

Addon Analysis
~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import ConfigLoader, ModuleManager

   loader = ConfigLoader()
   config = loader.load_config("dev")
   manager = ModuleManager(config["addons_path"])

   addons = manager.find_modules()
   install_order = manager.get_install_order("sale", "purchase")

Safe Read-Only Queries
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import OdooQuery

   query = OdooQuery(config)
   partners = query.query_model(
       "res.partner",
       domain=[("customer_rank", ">", 0)],
       fields=["name", "email"],
       limit=5,
   )

First-Class Runtime Inspection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import OdooInspector

   inspector = OdooInspector(config)
   xmlid = inspector.inspect_ref("base.action_partner_form")
   model = inspector.inspect_model("res.partner")
   table = inspector.describe_table("res_partner")

Raw Trusted Code Execution
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import OdooCodeExecutor
   from oduit.config_provider import ConfigProvider

   executor = OdooCodeExecutor(ConfigProvider(config))
   result = executor.execute_code(
       "env['res.partner'].search_count([])",
       allow_unsafe=True,
   )

Next Steps
----------

* Read :doc:`configuration` for config details
* Read :doc:`cli` for command reference
* Read :doc:`api` for Python API reference
