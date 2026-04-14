Configuration
=============

oduit supports several config shapes for compatibility, but the preferred user
facing format is sectioned TOML.

Recommended Format
------------------

Local or environment configs should look like this:

.. code-block:: toml

   [binaries]
   python_bin = "./venv/bin/python"
   odoo_bin = "./odoo/odoo-bin"
   coverage_bin = "./venv/bin/coverage"

    [odoo_params]
    addons_path = "./addons,./enterprise"
    db_name = "project_dev"
    db_user = "odoo"
    db_host = "localhost"
    http_port = 8069
    write_protect_db = false
    agent_write_protect_db = false
    needs_mutation_flag = false
    agent_needs_mutation_flag = false

Runtime DB mutation policy is controlled by explicit flags:

* ``write_protect_db`` blocks runtime DB mutation for every caller
* ``needs_mutation_flag`` requires ``--allow-mutation`` for human runtime DB mutation
* ``agent_write_protect_db`` blocks runtime DB mutation for agent commands
* ``agent_needs_mutation_flag`` requires ``--allow-mutation`` for agent runtime DB mutation

Plain test runs stay read-only. Only runtime flows that install, update,
uninstall, create a database, or explicitly trigger runtime actions consult these
flags.

The legacy risk-level key is no longer supported and now raises a config error.

Supported Locations
-------------------

* local project config: ``.oduit.toml``
* named environment config: ``~/.config/oduit/<env>.toml``
* compatibility support: ``~/.config/oduit/<env>.yaml``

Compatibility Notes
-------------------

oduit still accepts:

* flat config files with keys at the root level
* YAML environment files

Those shapes are compatibility support, not the preferred format for new docs
or new projects.

Canonical Normalized Shape
--------------------------

Internally, oduit now treats the sectioned shape as the canonical normalized
configuration:

.. code-block:: toml

   [binaries]
   python_bin = "./venv/bin/python"
   odoo_bin = "./odoo/odoo-bin"
   coverage_bin = "./venv/bin/coverage"

   [odoo_params]
   addons_path = "./addons,./enterprise"
   db_name = "project_dev"

``oduit agent resolve-config`` exposes both the compatibility
``effective_config`` view and the canonical ``normalized_config`` view, plus
``config_shape`` metadata with a ``shape_version``.

Legacy flat config files remain supported, but ``resolve-config`` now reports a
deprecation warning when they are detected so agents can migrate toward the
sectioned TOML shape.

Canonical Normalized Shape
--------------------------

Internally, oduit now treats the sectioned shape as the canonical normalized
configuration:

.. code-block:: toml

   [binaries]
   python_bin = "./venv/bin/python"
   odoo_bin = "./odoo/odoo-bin"
   coverage_bin = "./venv/bin/coverage"

   [odoo_params]
   addons_path = "./addons,./enterprise"
   db_name = "project_dev"

``oduit agent resolve-config`` exposes both the compatibility
``effective_config`` view and the canonical ``normalized_config`` view, plus
``config_shape`` metadata with a ``shape_version``.

Legacy flat config files remain supported, but ``resolve-config`` now reports a
deprecation warning when they are detected so agents can migrate toward the
sectioned TOML shape.

Important Keys
--------------

Binary keys:

* ``python_bin``
* ``odoo_bin``
* ``coverage_bin``

Common Odoo keys:

* ``addons_path``
* ``db_name``
* ``db_host``
* ``db_port``
* ``db_user``
* ``db_password``
* ``write_protect_db``
* ``agent_write_protect_db``
* ``needs_mutation_flag``
* ``agent_needs_mutation_flag``
* ``config_file``
* ``without_demo``
* ``log_level``
* ``http_port``
* ``workers``

Python Usage
------------

.. code-block:: python

   from oduit import ConfigLoader

   loader = ConfigLoader()
   dev_config = loader.load_config("dev")

   if loader.has_local_config():
       local_config = loader.load_local_config()

   envs = loader.get_available_environments()

Import Existing Odoo Configuration
----------------------------------

If you already have an ``odoo.conf`` file, import or convert it with the CLI:

.. code-block:: bash

   oduit init dev --from-conf /path/to/odoo.conf

Diagnostics
-----------

Use ``doctor`` to validate that your config, binaries, addons paths, version,
and database settings all line up:

.. code-block:: bash

   oduit doctor
   oduit --env dev doctor
