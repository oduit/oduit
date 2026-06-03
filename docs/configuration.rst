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

Recommended setup for existing Odoo projects
--------------------------------------------

If you already have an ``odoo.conf`` file, prefer importing it instead of
rewriting the config by hand:

.. code-block:: bash

   oduit init dev --from-conf ./odoo.conf
   oduit --env dev print-config
   oduit --env dev doctor

For a project-local config, write ``.oduit.toml`` directly:

.. code-block:: bash

   oduit init dev --from-conf ./odoo.conf --local
   oduit print-config

Use ``--dry-run`` to preview the generated TOML without writing a file. The
generated config may include secrets imported from ``odoo.conf``.

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

Operation sets are not environment configuration
------------------------------------------------

Environment configuration stays in ``.oduit.toml`` or
``~/.config/oduit/<env>.toml``. Operation sets live beside the active config and
store reusable execution plans for install, update, or test operations.

For local project config:

.. code-block:: text

   .oduit.toml
   .oduit/
     sets/
       base.toml

For named environments:

.. code-block:: text

   ~/.config/oduit/dev.toml
   ~/.config/oduit/sets/base.toml

Use ``oduit set inspect``, ``oduit set apply``, and ``oduit set list`` to work
with sets. Save addon lists into sets with ``--save-set`` and ``--set-kind``.
Reorder install/update sets with ``install-order --from-set``.

Short names resolve from the active config set store, then ``.oduit/sets/``,
then ``~/.config/oduit/sets/``.

Paths in ``[test].test_files`` resolve relative to the set file, not necessarily cwd.

Execution controls
~~~~~~~~~~~~~~~~~~

Operation sets may define execution controls inside their matching section.
``verify_state`` enables database state verification after install/update steps.
``retry_missing`` retries addons that are still not installed after verification.
``one_by_one`` executes addon operations individually.
``retry_failed_tests`` applies to test tags and files in test sets.
``stop_on_error`` controls whether execution stops on the first failure.
``skip_installed`` (install only) skips already-installed addons.
``require_installed`` (update only) fails precheck for uninstalled addons.

Equivalent CLI options: ``--verify-state``, ``--retry-missing``, ``--one-by-one``.
CLI options override set-file keys for each invocation.
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

Documentation workflow settings
-------------------------------

Use this section to constrain addon technical documentation writes and scans:

.. code-block:: toml

   [documentation]
   allowed_addon_dirs = ["./addons"]

``allowed_addon_dirs`` values are resolved relative to the project base:
``.oduit.toml`` directory when present, then git root, then current working
directory.

This keeps ``technical-next`` and ``technical-status`` focused on your project
addons and avoids selecting native/third-party addon roots by default.

Legacy flat-key compatibility remains supported through
``documentation_allowed_addon_dirs``.

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

For the full migration workflow, including validation steps and no-pytest smoke
checks, see :doc:`migrate-odoo-conf`.

Diagnostics
-----------

Use ``doctor`` to validate that your config, binaries, addons paths, version,
and database settings all line up:

.. code-block:: bash

   oduit doctor
   oduit --env dev doctor
