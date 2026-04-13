Examples
========

This section points to working examples in the repository and groups them by
current product areas.

Core Workflows
--------------

.. literalinclude:: ../examples/enhanced_demo_example.py
   :language: python
   :caption: Structured operations and parsed results

.. literalinclude:: ../examples/run_command_yielding_example.py
   :language: python
   :caption: Streaming structured process output

Addon and Manifest Workflows
----------------------------

.. literalinclude:: ../examples/module_manifest_example.py
   :language: python
   :caption: Manifest inspection

Trusted Code Execution
----------------------

.. literalinclude:: ../examples/execute_python_example.py
   :language: python
   :caption: Executing trusted Python through the Odoo shell interface

Inspection and Database Workflows
---------------------------------

.. code-block:: bash

   oduit --env dev inspect ref base.action_partner_form
   oduit --env dev inspect model res.partner
   oduit --env dev inspect field res.partner email --with-db
   oduit --env dev db table res_partner
   oduit --env dev performance slow-queries --limit 10
   oduit --env dev manifest check sale

Demo Mode
---------

.. literalinclude:: ../examples/demo_mode_example.py
   :language: python
   :caption: Demo-mode operations

Configuration Examples
----------------------

Preferred local config:

.. code-block:: toml

   [binaries]
   python_bin = "./venv/bin/python"
   odoo_bin = "./odoo/odoo-bin"

   [odoo_params]
   addons_path = "./addons"
   db_name = "project_dev"

Compatibility support still exists for YAML and flat config files, but new
examples should prefer sectioned TOML.
