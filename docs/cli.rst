Command Line Interface
======================

oduit provides a command-line interface (CLI) for managing Odoo instances, testing modules,
and performing common operations without writing Python code.

.. contents:: Table of Contents
   :local:
   :depth: 2

Installation
------------

The CLI is automatically installed when you install oduit:

.. code-block:: bash

   pip install oduit

After installation, the ``oduit`` command will be available in your terminal.

Configuration
-------------

The CLI can use either:

1. **Environment configuration** from ``~/.config/oduit/<env>.yaml`` or ``~/.config/oduit/<env>.toml``
2. **Local project configuration** from ``.oduit.toml`` in the current directory

Environment Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^

Create a configuration file for your environment:

**YAML format** (``~/.config/oduit/dev.yaml``):

.. code-block:: yaml

   binaries:
     python_bin: "/usr/bin/python3"
     odoo_bin: "/opt/odoo/odoo-bin"
     coverage_bin: "/usr/bin/coverage"

   odoo_params:
     db_name: "mydb"
     addons_path: "/opt/odoo/addons"
     config_file: "/etc/odoo/odoo.conf"
     http_port: 8069
     workers: 4
     dev: true

**TOML format** (``~/.config/oduit/dev.toml``):

.. code-block:: toml

   [binaries]
   python_bin = "/usr/bin/python3"
   odoo_bin = "/opt/odoo/odoo-bin"
   coverage_bin = "/usr/bin/coverage"

   [odoo_params]
   db_name = "mydb"
   addons_path = "/opt/odoo/addons"
   config_file = "/etc/odoo/odoo.conf"
   http_port = 8069
   workers = 4
   dev = true

Local Project Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Create a ``.oduit.toml`` file in your project root:

.. code-block:: toml

   [binaries]
   python_bin = "./venv/bin/python"
   odoo_bin = "./odoo/odoo-bin"

   [odoo_params]
   addons_path = "./addons"
   db_name = "project_dev"
   dev = true

If present, this configuration will be used when ``--env`` is not specified.

Basic Usage
-----------

Global Options
^^^^^^^^^^^^^^

These options are available for all commands:

.. code-block:: bash

   oduit [OPTIONS] COMMAND [ARGS]

Options:

- ``--env, -e TEXT``: Environment to use (e.g., prod, test, dev)
- ``--json``: Output in JSON format (default: text)
- ``--verbose, -v``: Show verbose output including configuration and command details
- ``--no-http``: Add --no-http flag to all odoo-bin commands

Commands
--------

run
^^^

Run the Odoo server with the configured settings.

.. code-block:: bash

   oduit --env dev run
   oduit run  # Uses local .oduit.toml

**Examples:**

.. code-block:: bash

   # Run with specific environment
   oduit --env production run

   # Run with verbose output
   oduit --env dev --verbose run

   # Run without HTTP (for running alongside another Odoo instance)
   oduit --env dev --no-http run

shell
^^^^^

Start an Odoo shell for interactive Python execution within the Odoo environment.

.. code-block:: bash

   oduit --env dev shell [OPTIONS]

**Options:**

- ``--shell-interface [ipython|ptpython|bpython|python]``: Shell interface to use (default: python)
- ``--compact``: Suppress INFO logs at startup for cleaner output

**Examples:**

.. code-block:: bash

   # Start default Python shell
   oduit --env dev shell

   # Use IPython shell
   oduit --env dev shell --shell-interface ipython

   # Compact output (no startup logs)
   oduit --env dev shell --compact

install
^^^^^^^

Install an Odoo module.

.. code-block:: bash

   oduit --env dev install MODULE [OPTIONS]

**Options:**

- ``--without-demo TEXT``: Install without demo data
- ``--with-demo``: Install with demo data (overrides config)
- ``--language TEXT``: Load specific language translations
- ``--i18n-overwrite``: Overwrite existing translations during installation
- ``--max-cron-threads INTEGER``: Set maximum cron threads for Odoo server

**Examples:**

.. code-block:: bash

   # Install a module
   oduit --env dev install sale

   # Install without demo data
   oduit --env dev install sale --without-demo all

   # Install with specific language
   oduit --env dev install sale --language de_DE

   # Install and overwrite translations
   oduit --env dev install sale --language de_DE --i18n-overwrite

update
^^^^^^

Update an Odoo module.

.. code-block:: bash

   oduit --env dev update MODULE [OPTIONS]

**Options:**

- ``--without-demo TEXT``: Update without demo data
- ``--language TEXT``: Load specific language translations
- ``--i18n-overwrite``: Overwrite existing translations during update
- ``--max-cron-threads INTEGER``: Set maximum cron threads for Odoo server
- ``--compact``: Suppress INFO logs at startup for cleaner output

**Examples:**

.. code-block:: bash

   # Update a module
   oduit --env dev update sale

   # Update with language overwrite
   oduit --env dev update sale --i18n-overwrite --language de_DE

   # Update with compact output
   oduit --env dev update sale --compact

test
^^^^

Run module tests with various options.

.. code-block:: bash

   oduit --env dev test [OPTIONS]

**Options:**

- ``--test-tags TEXT``: Comma-separated list of specs to filter tests
- ``--install TEXT``: Install specified addon before testing
- ``--update TEXT``: Update specified addon before testing
- ``--coverage TEXT``: Run coverage report for specified module after tests
- ``--test-file TEXT``: Run a specific Python test file
- ``--stop-on-error``: Abort test run on first detected failure in output
- ``--compact``: Show only test progress dots, statistics, and result summaries

**Examples:**

.. code-block:: bash

   # Test a specific module
   oduit --env dev test --test-tags /sale

   # Install module and run tests
   oduit --env dev test --install sale --test-tags /sale

   # Test with coverage report
   oduit --env dev test --test-tags /sale --coverage sale

   # Run specific test file
   oduit --env dev test --test-file tests/test_sale.py

   # Stop on first error with compact output
   oduit --env dev test --test-tags /sale --stop-on-error --compact

create-db
^^^^^^^^^

Create a new database for Odoo.

.. code-block:: bash

   oduit --env dev create-db [OPTIONS]

**Options:**

- ``--create-role``: Create database role
- ``--alter-role``: Alter database role
- ``--with-sudo``: Use sudo for database creation (if required by PostgreSQL setup)
- ``--drop``: Drop database if it exists before creating
- ``--non-interactive``: Run without confirmation prompt (use with caution)
- ``--db-user TEXT``: Specify the database user (overrides config setting)

**Examples:**

.. code-block:: bash

   # Create database (prompts for confirmation)
   oduit --env dev create-db

   # Create database with role creation
   oduit --env dev create-db --create-role

   # Drop existing database and create new one
   oduit --env dev create-db --drop

   # Non-interactive mode (auto-confirm)
   oduit --env dev create-db --non-interactive

   # Use sudo for PostgreSQL operations
   oduit --env dev create-db --with-sudo

   # Combine options: drop, create role, non-interactive
   oduit --env dev create-db --drop --create-role --non-interactive

.. note::
   The command checks if the database exists before attempting to create it.
   Use ``--drop`` to automatically drop an existing database before creating.

.. warning::
   This command will prompt for confirmation before creating the database
   unless ``--non-interactive`` is specified.

list-db
^^^^^^^

List all databases in PostgreSQL.

.. code-block:: bash

   oduit --env dev list-db [OPTIONS]

**Options:**

- ``--with-sudo/--no-sudo``: Use sudo for database listing (default: False)
- ``--db-user TEXT``: Specify the database user (overrides config setting)

**Examples:**

.. code-block:: bash

   # List databases
   oduit --env dev list-db

   # List databases with sudo
   oduit --env dev list-db --with-sudo

   # List databases as specific user
   oduit --env dev list-db --db-user postgres

create-addon
^^^^^^^^^^^^

Create a new Odoo addon with a template structure.

.. code-block:: bash

   oduit --env dev create-addon ADDON_NAME [OPTIONS]

**Options:**

- ``--path TEXT``: Path where to create the addon
- ``--template [basic|website]``: Addon template to use (default: basic)

**Examples:**

.. code-block:: bash

   # Create basic addon
   oduit --env dev create-addon my_custom_module

   # Create addon with website template
   oduit --env dev create-addon my_website_module --template website

   # Create addon in specific path
   oduit --env dev create-addon my_module --path /opt/custom/addons

list-addons
^^^^^^^^^^^

List available addons in the configured addons path.

.. code-block:: bash

   oduit --env dev list-addons [OPTIONS]

**Options:**

- ``--type [all|installed|available]``: Type of addons to list (default: all)

**Examples:**

.. code-block:: bash

   # List all addons
   oduit --env dev list-addons

   # List only installed addons (if supported)
   oduit --env dev list-addons --type installed

export-lang
^^^^^^^^^^^

Export language translations for a module.

.. code-block:: bash

   oduit --env dev export-lang MODULE [OPTIONS]

**Options:**

- ``--language, -l TEXT``: Language to export (default: from config or de_DE)

**Examples:**

.. code-block:: bash

   # Export default language
   oduit --env dev export-lang sale

   # Export specific language
   oduit --env dev export-lang sale --language fr_FR

The exported file will be saved to ``<module_path>/i18n/<language>.po``.

print-config
^^^^^^^^^^^^

Print the current environment configuration.

.. code-block:: bash

   oduit --env dev print-config

**Examples:**

.. code-block:: bash

   # Print production config
   oduit --env production print-config

   # Print local config
   oduit print-config

Output Formats
--------------

Text Output (Default)
^^^^^^^^^^^^^^^^^^^^^

Human-readable output with colors and formatting:

.. code-block:: bash

   oduit --env dev install sale

JSON Output
^^^^^^^^^^^

Machine-readable JSON output for scripting:

.. code-block:: bash

   oduit --env dev --json install sale

Example output:

.. code-block:: json

   {
     "success": true,
     "operation_type": "install",
     "modules_installed": ["sale"],
     "modules_loaded": 42,
     "without_demo": false,
     "verbose": false
   }

Common Workflows
----------------

Development Workflow
^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Start development server
   oduit --env dev run

   # In another terminal: Install module
   oduit --env dev install my_module

   # Run tests
   oduit --env dev test --test-tags /my_module --compact

   # Update after changes
   oduit --env dev update my_module --compact

Testing Workflow
^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Install module and run tests with coverage
   oduit --env test install sale --without-demo all
   oduit --env test test --test-tags /sale --coverage sale

   # Run specific test file
   oduit --env test test --test-file tests/test_sale_flow.py

Translation Workflow
^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Export translations
   oduit --env dev export-lang my_module --language de_DE

   # Update module with translation overwrite
   oduit --env dev update my_module --i18n-overwrite --language de_DE

Production Deployment
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Install modules without demo data
   oduit --env production install sale,purchase,stock --without-demo all

   # Update modules
   oduit --env production update sale,purchase,stock

   # Run server
   oduit --env production run

Error Handling
--------------

Exit Codes
^^^^^^^^^^

The CLI uses standard exit codes:

- ``0``: Success
- ``1``: Error (configuration error, operation failed, etc.)

When an error occurs, the CLI will:

1. Print an error message describing the issue
2. Exit with code 1
3. Optionally output JSON error details (when ``--json`` is used)

Troubleshooting
^^^^^^^^^^^^^^^

**Configuration not found:**

.. code-block:: bash

   # Check available environments
   ls ~/.config/oduit/

   # Print current config
   oduit --env dev print-config

**Module not found:**

.. code-block:: bash

   # List available modules
   oduit --env dev list-addons

**Test failures:**

.. code-block:: bash

   # Run with verbose output
   oduit --env dev --verbose test --test-tags /my_module

   # Run with compact output to focus on failures
   oduit --env dev test --test-tags /my_module --compact

API Reference
-------------

CLI Types
^^^^^^^^^

.. automodule:: oduit.cli_types
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:

CLI Implementation
^^^^^^^^^^^^^^^^^^

.. automodule:: oduit.cli_typer
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:

See Also
--------

- :doc:`quickstart` - Getting started with oduit
- :doc:`configuration` - Configuration file reference
- :doc:`api/odoo_operations` - OdooOperations API (used internally by CLI)
- :doc:`examples` - Python API usage examples
