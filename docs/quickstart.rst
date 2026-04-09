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

Operations
~~~~~~~~~~

.. code-block:: bash

   oduit --env dev install sale
   oduit --env dev update sale
   oduit --env dev test --test-tags /sale
   oduit --env dev shell

Agent Inspection
~~~~~~~~~~~~~~~~

.. code-block:: bash

   oduit --env dev agent inspect-addon sale
   oduit --env dev agent list-addon-models my_partner
   oduit --env dev agent find-model-extensions res.partner --summary
   oduit --env dev agent get-model-views res.partner --types form,tree --summary

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
