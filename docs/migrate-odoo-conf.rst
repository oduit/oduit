Migrating from odoo.conf
========================

Use this guide when you already run Odoo with a normal ``odoo.conf`` file and
want to switch to oduit's sectioned TOML config without rewriting everything by
hand.

One-command import
------------------

.. code-block:: bash

   cd /path/to/odoo-project

   uvx oduit init dev \
     --from-conf ./odoo.conf \
     --python-bin ./.venv/bin/python \
     --odoo-bin ./odoo-bin

This writes ``~/.config/oduit/dev.toml`` by default. If you want a project-local
config instead, use:

.. code-block:: bash

   oduit init dev --from-conf ./odoo.conf --local

Preview without writing a file:

.. code-block:: bash

   oduit init dev --from-conf ./odoo.conf --dry-run

The generated file uses the sectioned TOML format:

.. code-block:: toml

   [binaries]
   python_bin = "./.venv/bin/python"
   odoo_bin = "./odoo-bin"

   [odoo_params]
   db_name = "mydb"
   addons_path = ["./odoo/addons", "./custom/addons"]
   config_file = "./odoo.conf"

Inspect the generated config
----------------------------

.. code-block:: bash

   oduit --env dev print-config

Check at least:

* ``python_bin``
* ``odoo_bin``
* ``db_name``
* ``addons_path``
* ``config_file``

Validate the environment
------------------------

.. code-block:: bash

   oduit --env dev doctor
   oduit --env dev list-addons
   oduit --env dev list-duplicates
   oduit --env dev version

Use the migrated config
-----------------------

.. code-block:: bash

   oduit --env dev run
   oduit --env dev shell
   oduit --env dev update my_module
   oduit --env dev test --test-tags /my_module

Do not commit secrets
---------------------

The generated TOML may contain secrets imported from ``odoo.conf``, including
database, admin, and SMTP passwords. Do not commit it unless that is intended
for your project. Keep ``.oduit.toml`` or environment-specific TOML files out of
version control when needed.

Suggested no-pytest validation commands
---------------------------------------

Run these from the repository root when you want a quick smoke path without
running pytest.

Static syntax check
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   python -m py_compile \
     oduit/config_loader.py \
     oduit/config_provider.py \
     oduit/builders.py \
     oduit/cli/init_env.py \
     oduit/cli/register_app_commands.py \
     tests/test_cli_app.py \
     tests/test_config_provider.py \
     tests/test_builders.py \
     tests/test_docs_surface.py

Manual conversion smoke test
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   tmpdir="$(mktemp -d)"
   home="$tmpdir/home"
   mkdir -p "$home"

   cat > "$tmpdir/odoo.conf" <<'EOF'
   [options]
   db_name = migrated_db
   db_user = odoo
   db_password = secret
   db_host = localhost
   db_port = 5432
   addons_path = /opt/odoo/addons,/opt/custom/addons
   http_port = 8069
   workers = 2
   proxy_mode = True
   log_level = info
   EOF

   HOME="$home" python -m oduit.cli.app init dev \
     --from-conf "$tmpdir/odoo.conf" \
     --python-bin /usr/bin/python3 \
     --odoo-bin /opt/odoo/odoo-bin \
     --coverage-bin /usr/bin/coverage

   cat "$home/.config/oduit/dev.toml"
   grep -q '^\[binaries\]' "$home/.config/oduit/dev.toml"
   grep -q '^\[odoo_params\]' "$home/.config/oduit/dev.toml"
   grep -q 'db_name = "migrated_db"' "$home/.config/oduit/dev.toml"
   grep -q 'config_file = ' "$home/.config/oduit/dev.toml"
   grep -q 'addons_path = \[' "$home/.config/oduit/dev.toml"

Builder smoke check after config_file fix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   python - <<'PY'
   from oduit.config_provider import ConfigProvider
   from oduit.builders import RunCommandBuilder

   config = ConfigProvider(
       {
           "python_bin": "python3",
           "odoo_bin": "odoo-bin",
           "config_file": "/etc/odoo/odoo.conf",
           "db_name": "migrated_db",
       }
   )

   cmd = RunCommandBuilder(config).build_operation().command
   print(cmd)

   assert "--config=/etc/odoo/odoo.conf" in cmd
   assert "--database=migrated_db" in cmd
   PY
