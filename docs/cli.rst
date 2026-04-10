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
- ``--non-interactive``: Fail instead of prompting for confirmation
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
   unless you pass ``--non-interactive``. In non-interactive mode, the command
   fails fast instead of auto-confirming.

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
- ``--select-dir TEXT``: Filter addons by exact directory name match

**Examples:**

.. code-block:: bash

   # List all addons
   oduit --env dev list-addons

   # List only installed addons (if supported)
   oduit --env dev list-addons --type installed

   # List addons in a specific directory (exact name match)
   oduit --env dev list-addons --select-dir custom_addons

.. note::
   The ``--select-dir`` option requires an exact match with the directory
   basename. For example, if your addons path is ``/path/to/custom_addons``,
   you must use ``--select-dir custom_addons`` (not ``custom`` or ``addons``).

**Filtering Options:**

- ``--include FIELD:VALUE``: Include only addons where FIELD contains VALUE
- ``--exclude FIELD:VALUE``: Exclude addons where FIELD contains VALUE
- ``--exclude-core-addons``: Exclude Odoo core addons
- ``--exclude-enterprise-addons``: Exclude Odoo enterprise addons

Valid filter fields: ``name``, ``version``, ``summary``, ``author``, ``website``,
``license``, ``category``, ``module_path``, ``depends``, ``addon_type``

**Filtering Examples:**

.. code-block:: bash

   # Exclude all Theme addons
   oduit --env dev list-addons --exclude category:Theme

   # Include only Odoo-authored addons (excluding core addons)
   oduit --env dev list-addons --include author:Odoo --exclude-core-addons

   # List only LGPL licensed addons
   oduit --env dev list-addons --include license:LGPL

   # Exclude addons depending on sale
   oduit --env dev list-addons --exclude depends:sale

list-duplicates
^^^^^^^^^^^^^^^

List duplicate addon names discovered in more than one addons path.

.. code-block:: bash

   oduit --env dev list-duplicates

This is useful before automated updates, because duplicate module names make
resolution order ambiguous.

   # Combine multiple filters
   oduit --env dev list-addons --exclude category:Theme --exclude category:Hidden

print-manifest
^^^^^^^^^^^^^^

Display detailed manifest information for a specific addon.

.. code-block:: bash

   oduit --env dev print-manifest ADDON_NAME [OPTIONS]

**Options:**

- ``--select-dir TEXT``: Filter addons by exact directory name match

**Examples:**

.. code-block:: bash

   # Print manifest for sale module
   oduit --env dev print-manifest sale

   # Print manifest for module in specific directory
   oduit --env dev print-manifest my_module --select-dir custom_addons

   # Output as JSON
   oduit --env dev --json print-manifest sale

**Output:**

The command displays a Rich table with the following information:

- **Name**: Technical module name
- **Display Name**: Human-readable name
- **Version**: Module version
- **Addon Type**: Odoo CE, Odoo EE, or Custom
- **Summary**: Brief description
- **Author**: Module author(s)
- **Website**: Project website
- **License**: License type (e.g., LGPL-3, OPL-1)
- **Category**: Module category
- **Installable**: Whether the module can be installed
- **Auto Install**: Whether the module auto-installs
- **Depends**: Module dependencies
- **External Dependencies (Python)**: Required Python packages
- **External Dependencies (Bin)**: Required binary dependencies
- **Module Path**: Full filesystem path to the module

list-manifest-values
^^^^^^^^^^^^^^^^^^^^

List unique values for a specific manifest field across all addons.

.. code-block:: bash

   oduit --env dev list-manifest-values FIELD [OPTIONS]

This command scans all available addons and collects unique values for the
specified manifest field. Useful for discovering what values exist in your
addons (e.g., all categories, licenses, authors in use).

**Arguments:**

- ``FIELD``: The manifest field to list values for (e.g., ``category``, ``license``, ``author``)

**Options:**

- ``--separator TEXT``: Separator for output (default: newline)
- ``--select-dir TEXT``: Filter addons by exact directory name match
- ``--exclude-core-addons``: Exclude Odoo core addons
- ``--exclude-enterprise-addons``: Exclude Odoo enterprise addons

**Examples:**

.. code-block:: bash

   # List all unique categories
   oduit --env dev list-manifest-values category

   # List all licenses used in custom addons only
   oduit --env dev list-manifest-values license --exclude-core-addons

   # List authors with comma separator
   oduit --env dev list-manifest-values author --separator ", "

   # List categories in a specific directory
   oduit --env dev list-manifest-values category --select-dir myaddons

   # Output as JSON
   oduit --env dev --json list-manifest-values category

**Output:**

- Text mode: One value per line (or separated by custom separator)
- JSON mode: Versioned payload containing ``field`` and ``values``

list-depends
^^^^^^^^^^^^

List external dependencies for a specified module or directory of modules.

.. code-block:: bash

   oduit --env dev list-depends [MODULE] [OPTIONS]

This command analyzes the module's dependency tree and identifies external
dependencies that are not available in the configured addons paths. It
recursively checks all transitive dependencies.

You can either provide module names directly or use ``--select-dir`` to
automatically get dependencies for all modules in a specific directory.

**Options:**

- ``--tree``: Display dependencies as a hierarchical tree structure
- ``--depth INTEGER``: Maximum depth of dependencies to show (0=direct only, 1=direct+their deps, etc.)
- ``--separator TEXT``: Separator for list output (e.g., ",")
- ``--select-dir TEXT``: Get dependencies for all modules in a specific directory

**Examples:**

.. code-block:: bash

   # Check external dependencies for sale module
   oduit --env dev list-depends sale

   # Display dependency tree for a module
   oduit --env dev list-depends sale --tree

   # Check multiple modules external dependencies
   oduit --env dev list-depends sale,purchase

   # Output as comma-separated list
   oduit --env dev list-depends sale --separator ","

   # Show only direct dependencies
   oduit --env dev list-depends sale --depth 0

   # Show direct dependencies and their dependencies
   oduit --env dev list-depends sale --depth 1

   # Show tree with limited depth
   oduit --env dev list-depends sale --tree --depth 1

   # Multiple modules with depth limit
   oduit --env dev list-depends sale,purchase --depth 0

   # Tree view for multiple modules
   oduit --env dev list-depends sale,purchase --tree

   # Get dependencies for all modules in a directory
   oduit --env dev list-depends --select-dir myaddons

   # Get dependencies for a directory with comma-separated output
   oduit --env dev list-depends --select-dir myaddons --separator ","

   # Get dependencies for a directory with depth limit
   oduit --env dev list-depends --select-dir myaddons --depth 0

   # Tree view for all modules in a directory
   oduit --env dev list-depends --select-dir myaddons --tree

**Tree View:**

The ``--tree`` option displays a hierarchical view of all codependencies:

.. code-block:: text

   └── sale (17.0.1.0.0)
       ├── base (1.3)
       ├── web (1.0)
       │   └── base (1.3)
       └── portal (1.0.0)
           └── web (1.0)

Features:

- Shows module versions in parentheses
- Uses box-drawing characters (└──, ├──, │) for tree structure
- Detects and marks circular dependencies with ⬆ symbol
- Supports multiple modules (displays trees separately with blank line separator)

**Output:**

The command will:

- List all external dependencies if any are found
- Return "No external dependencies" if all dependencies are available
- Return an error if the module itself is not found
- In tree mode, display the full dependency hierarchy for a single module

list-codepends
^^^^^^^^^^^^^^

List reverse dependencies for a specified module.

.. code-block:: bash

   oduit --env dev list-codepends MODULE

This command lists the addons that depend on the specified module. The current
implementation also includes the selected module itself in the output, which is
useful when feeding the result into follow-up install or impact-analysis flows.

**Examples:**

.. code-block:: bash

   # Find which addons depend on base
   oduit --env dev list-codepends base

   # Find which addons depend on sale
   oduit --env dev list-codepends sale

   # Find reverse dependencies for a custom module
   oduit --env dev list-codepends my_custom_module

**Output:**

The command will:

- List the selected module together with all modules that depend on it
- Return only the selected module if no reverse dependencies are found
- Preserve the command name ``list-codepends`` for compatibility, even though
  the behavior is reverse-dependency analysis

install-order
^^^^^^^^^^^^^

Return the dependency-resolved install or update order for one or more addons.

.. code-block:: bash

   oduit --env dev install-order [MODULES] [OPTIONS]

You can either provide comma-separated module names directly or use
``--select-dir`` to compute the order for all addons in one directory.

**Options:**

- ``--separator TEXT``: Separator for output (e.g., ",")
- ``--select-dir TEXT``: Get install order for all modules in a specific directory

**Examples:**

.. code-block:: bash

   # Compute install order for two addons
   oduit --env dev install-order sale,purchase

   # Output as a comma-separated list
   oduit --env dev install-order sale,purchase --separator ","

   # Compute install order for all addons in one directory
   oduit --env dev install-order --select-dir myaddons

    # Output as JSON
    oduit --env dev --json install-order sale,purchase

If dependency resolution fails because of a cycle, JSON output includes a
structured ``cycle_path`` and remediation guidance.

impact-of-update
^^^^^^^^^^^^^^^^

Show which addons depend on a module and would likely be affected by updating it.

.. code-block:: bash

   oduit --env dev impact-of-update MODULE [OPTIONS]

This command uses reverse dependency analysis to show the likely blast radius
of a module update.

**Options:**

- ``--separator TEXT``: Separator for output (e.g., ",")

**Examples:**

.. code-block:: bash

   # Show addons impacted by updating sale
   oduit --env dev impact-of-update sale

   # Output as a comma-separated list
   oduit --env dev impact-of-update sale --separator ","

   # Output as JSON
   oduit --env dev --json impact-of-update sale

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
      "schema_version": "1.0",
      "type": "result",
      "success": true,
      "operation": "install",
      "read_only": false,
      "safety_level": "controlled_mutation",
      "warnings": [],
      "errors": [],
      "remediation": [],
      "data": {
         "return_code": 0,
         "modules_installed": ["sale"],
         "modules_loaded": 42,
         "without_demo": false,
         "verbose": false
      },
      "meta": {
         "timestamp": "2026-04-09T12:00:00"
      },
      "return_code": 0,
      "modules_installed": ["sale"],
      "modules_loaded": 42,
      "without_demo": false,
      "verbose": false
   }

JSON Contract
^^^^^^^^^^^^^

JSON output is versioned for automation use.

Guaranteed keys for result payloads:

* ``schema_version``: current schema version string
* ``type``: payload family such as ``result`` or ``doctor_report``
* ``success``: overall success flag
* ``read_only``: whether the command is inspection-only
* ``safety_level``: ``safe_read_only``, ``controlled_mutation``, or
  ``unsafe_arbitrary_execution``
* ``warnings`` / ``errors`` / ``remediation``: normalized machine-readable
  guidance lists
* ``data``: command-specific payload content
* ``meta``: shared metadata such as ``timestamp`` and optional ``duration``

Common keys when they apply:

* ``operation``
* ``command``
* ``return_code``
* ``stdout`` / ``stderr``
* ``error`` / ``error_type``

Operation-specific fields are preserved alongside those keys.

Agent Commands
--------------

The ``oduit agent`` command group is the preferred automation surface for
inspection and planning. These commands always emit structured JSON and do not
require the global ``--json`` flag.

Use :doc:`agent_contract` for the canonical command sequence, mutation policy,
payload expectations, and failure handling. This section is the command
reference.

context
^^^^^^^

Return a one-shot environment snapshot for agent workflows.

.. code-block:: bash

   oduit --env dev agent context

inspect-addon
^^^^^^^^^^^^^

Inspect one addon with manifest, dependency, and impact data.

.. code-block:: bash

   oduit --env dev agent inspect-addon sale

inspect-addons
^^^^^^^^^^^^^^

Inspect multiple addons in one call.

.. code-block:: bash

   oduit --env dev agent inspect-addons --modules sale,stock

plan-update
^^^^^^^^^^^

Build a read-only update plan with impact and risk metadata.

.. code-block:: bash

   oduit --env dev agent plan-update sale

list-addon-models
^^^^^^^^^^^^^^^^^

Return the models declared or extended by one addon.

.. code-block:: bash

   oduit --env dev agent list-addon-models my_partner

find-model-extensions
^^^^^^^^^^^^^^^^^^^^^

Return where a model is declared and extended across addons, plus installed
field and view extension metadata from the database.

.. code-block:: bash

   oduit --env dev agent find-model-extensions crm.stage --summary

get-model-views
^^^^^^^^^^^^^^^

Fetch primary and extension ``ir.ui.view`` records for a model directly from
the database.

.. code-block:: bash

   oduit --env dev agent get-model-views crm.stage --types form,tree
   oduit --env dev agent get-model-views crm.stage --types form,tree --summary

locate-model
^^^^^^^^^^^^

Locate likely Python source files for a model extension inside one addon.

.. code-block:: bash

   oduit --env dev agent locate-model res.partner --module my_partner

locate-field
^^^^^^^^^^^^

Locate an existing field definition or suggest the best insertion point.

.. code-block:: bash

   oduit --env dev agent locate-field res.partner email3 --module my_partner

list-addon-tests
^^^^^^^^^^^^^^^^

Return likely test files for an addon, optionally ranked by model or field
references.

.. code-block:: bash

   oduit --env dev agent list-addon-tests my_partner --model res.partner --field email3

doctor
^^^^^^

Return doctor diagnostics through the standard agent envelope.

.. code-block:: bash

   oduit --env dev agent doctor

list-addons
^^^^^^^^^^^

Return structured addon inventory with filters and duplicate indicators.

.. code-block:: bash

   oduit --env dev agent list-addons --exclude category:Theme

dependency-graph
^^^^^^^^^^^^^^^^

Return dependency graph nodes, edges, cycles, and install order data.

.. code-block:: bash

   oduit --env dev agent dependency-graph --modules sale,stock

resolve-config
^^^^^^^^^^^^^^

Return the resolved configuration with sensitive values redacted.

.. code-block:: bash

   oduit --env dev agent resolve-config

list-duplicates
^^^^^^^^^^^^^^^

Return duplicate addon-name analysis through the standard envelope.

.. code-block:: bash

   oduit --env dev agent list-duplicates

test-summary
^^^^^^^^^^^^

Run tests and emit a normalized summary payload. This is a controlled mutation
command and requires ``--allow-mutation``.

.. code-block:: bash

   oduit --env dev agent test-summary --allow-mutation --module sale --test-tags /sale

Controlled mutation commands require ``--allow-mutation``. See
:doc:`agent_contract` for the mutation rules and ``--dry-run`` expectations.

.. code-block:: bash

   oduit --env dev agent install-module sale --dry-run
   oduit --env dev agent update-module sale --allow-mutation
   oduit --env dev agent create-addon my_module --allow-mutation
   oduit --env dev agent export-lang sale --allow-mutation --language de_DE

query-model
^^^^^^^^^^^

Run a structured read-only model query through ``OdooQuery``.

.. code-block:: bash

   oduit --env dev agent query-model res.partner --fields name,email --limit 5

Other read helpers follow the same pattern:

.. code-block:: bash

   oduit --env dev agent read-record res.partner 7 --fields name,email
   oduit --env dev agent search-count res.partner --domain-json '[["is_company", "=", true]]'
   oduit --env dev agent get-model-fields res.partner --attributes string,type
   oduit --env dev agent get-model-views res.partner --types form,tree --summary

For the recommended end-to-end coding-agent loop, use :doc:`agent_contract`.

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
