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

The CLI prefers sectioned TOML configuration:

1. **Environment configuration** from ``~/.config/oduit/<env>.toml``
2. **Local project configuration** from ``.oduit.toml`` in the current directory

Compatibility support for ``~/.config/oduit/<env>.yaml`` still exists, but new
configs and new docs examples should use TOML.

Environment Configuration
^^^^^^^^^^^^^^^^^^^^^^^^^

Create a configuration file for your environment.

**Preferred TOML format** (``~/.config/oduit/dev.toml``):

.. code-block:: toml

   [binaries]
   python_bin = "/usr/bin/python3"
   odoo_bin = "/opt/odoo/odoo-bin"
   coverage_bin = "/usr/bin/coverage"

   [odoo_params]
    db_name = "mydb"
    addons_path = "/opt/odoo/addons"
    config_file = "/etc/odoo/odoo.conf"
    db_risk_level = "dev"
    http_port = 8069
    workers = 4
    dev = true
    allow_uninstall = false

**Compatibility YAML format** (``~/.config/oduit/dev.yaml``):

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
    db_risk_level = "dev"
    dev = true
    allow_uninstall = false

If present, this configuration will be used when ``--env`` is not specified.

Runtime DB mutation policy is controlled by ``db_risk_level``:

* ``test`` auto-allows runtime DB mutation
* ``dev`` requires ``--allow-mutation``
* ``prod`` blocks runtime DB mutation entirely

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

Install an Odoo module. This is a runtime DB mutation command.

.. code-block:: bash

   oduit --env dev install MODULE [OPTIONS]

**Options:**

- ``--without-demo TEXT``: Install without demo data
- ``--with-demo``: Install with demo data (overrides config)
- ``--language TEXT``: Load specific language translations
- ``--i18n-overwrite``: Overwrite existing translations during installation
- ``--max-cron-threads INTEGER``: Set maximum cron threads for Odoo server
- ``--allow-mutation``: Required on ``db_risk_level = "dev"``

**Examples:**

.. code-block:: bash

   # Install a module
   oduit --env dev install sale --allow-mutation

   # Install without demo data
   oduit --env dev install sale --allow-mutation --without-demo all

   # Install with specific language
   oduit --env dev install sale --allow-mutation --language de_DE

   # Install and overwrite translations
   oduit --env dev install sale --allow-mutation --language de_DE --i18n-overwrite

update
^^^^^^

Update an Odoo module. This is a runtime DB mutation command.

.. code-block:: bash

   oduit --env dev update MODULE [OPTIONS]

**Options:**

- ``--without-demo TEXT``: Update without demo data
- ``--language TEXT``: Load specific language translations
- ``--i18n-overwrite``: Overwrite existing translations during update
- ``--max-cron-threads INTEGER``: Set maximum cron threads for Odoo server
- ``--compact``: Suppress INFO logs at startup for cleaner output
- ``--allow-mutation``: Required on ``db_risk_level = "dev"``

**Examples:**

.. code-block:: bash

   # Update a module
   oduit --env dev update sale --allow-mutation

   # Update with language overwrite
   oduit --env dev update sale --allow-mutation --i18n-overwrite --language de_DE

   # Update with compact output
   oduit --env dev update sale --allow-mutation --compact

uninstall
^^^^^^^^^

Uninstall an Odoo module through the trusted runtime mutation path.

.. code-block:: bash

   oduit --env dev uninstall MODULE --allow-mutation --allow-uninstall

**Notes:**

- Uninstall is disabled by default and requires ``allow_uninstall = true`` in
  the active config.
- Runtime DB mutation still follows ``db_risk_level`` policy.
- The CLI requires ``--allow-uninstall`` for each destructive uninstall.
- Uninstall may fail early if installed dependents still rely on the target
  module.

**Examples:**

.. code-block:: bash

   # Uninstall a module after opting in at config level
   oduit --env dev uninstall crm --allow-mutation --allow-uninstall

   # Machine-readable uninstall result
   oduit --env dev --json uninstall crm --allow-mutation --allow-uninstall

test
^^^^

Run module tests with various options. This is a runtime DB mutation command.

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
- ``--allow-mutation``: Required on ``db_risk_level = "dev"``

**Examples:**

.. code-block:: bash

   # Test a specific module
   oduit --env dev test --allow-mutation --test-tags /sale

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

Create a new database for Odoo. This follows ``db_risk_level`` policy and is
blocked when ``db_risk_level = "prod"``.

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

Create a new Odoo addon with a template structure. This is a controlled source
mutation command and requires ``--allow-mutation``.

.. code-block:: bash

   oduit --env dev create-addon ADDON_NAME [OPTIONS]

**Options:**

- ``--path TEXT``: Path where to create the addon
- ``--template [basic|website]``: Addon template to use (default: basic)

**Examples:**

.. code-block:: bash

   # Create basic addon
   oduit --env dev create-addon my_custom_module --allow-mutation

   # Create addon with website template
   oduit --env dev create-addon my_website_module --allow-mutation --template website

   # Create addon in specific path
   oduit --env dev create-addon my_module --allow-mutation --path /opt/custom/addons

list-addons
^^^^^^^^^^^

List available addons in the configured addons path.

.. code-block:: bash

   oduit --env dev list-addons [OPTIONS]

**Options:**

- ``--select-dir TEXT``: Filter addons by exact directory name match

**Examples:**

.. code-block:: bash

   # List all addons
   oduit --env dev list-addons

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

.. note::
   ``list-addons`` is source inventory only. It scans the configured
   ``addons_path`` and does not query database runtime module state.

list-installed-addons
^^^^^^^^^^^^^^^^^^^^^

List installed addons from the active database runtime.

.. code-block:: bash

   oduit --env dev list-installed-addons [OPTIONS]

**Options:**

- ``--module TEXT`` / ``--modules TEXT``: Comma-separated addon names filter
- ``--state TEXT``: Repeatable runtime state filter (defaults to ``installed``)
- ``--separator TEXT``: Separator for text output
- ``--include-state``: Print ``module:state`` in text mode

**Examples:**

.. code-block:: bash

   # List installed addons from the active database
   oduit --env dev list-installed-addons

   # Filter to selected addons
   oduit --env dev list-installed-addons --modules sale,stock

   # Include the runtime state in text output
   oduit --env dev list-installed-addons --state installed --state to_upgrade --include-state

.. note::
   ``list-installed-addons`` is runtime inventory. It requires working database
   access and is separate from the source-only ``list-addons`` command.

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

Export language translations for a module. This is a controlled source mutation
command and requires ``--allow-mutation``.

.. code-block:: bash

   oduit --env dev export-lang MODULE [OPTIONS]

**Options:**

- ``--language, -l TEXT``: Language to export (default: from config or de_DE)

**Examples:**

.. code-block:: bash

   # Export default language
   oduit --env dev export-lang sale --allow-mutation

   # Export specific language
   oduit --env dev export-lang sale --allow-mutation --language fr_FR

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

Trusted Execution and Inspection
--------------------------------

exec
^^^^

Execute trusted Python directly inside the Odoo runtime and return a structured
result.

.. code-block:: bash

   oduit --env dev exec "env['project.task']._table"
   oduit --env dev exec "env['res.partner'].search_count([])" --output full

**Options:**

- ``--database TEXT``: Override the configured database
- ``--commit``: Commit database changes made by the code
- ``--timeout FLOAT``: Execution timeout in seconds
- ``--output [value|full]``: Print only the resulting value or the full result

.. warning::
   ``exec`` is a trusted arbitrary execution surface. It rolls back by default;
   pass ``--commit`` only when mutation is explicitly intended.

exec-file
^^^^^^^^^

Execute trusted Python loaded from a file.

.. code-block:: bash

   oduit --env dev exec-file scripts/check_runtime.py
   oduit --env dev exec-file scripts/repair_demo_data.py --commit --output full

inspect
^^^^^^^

Inspect runtime metadata without dropping into ``odoo-bin shell``.

.. code-block:: bash

   oduit --env dev inspect ref base.action_partner_form
   oduit --env dev inspect cron base.ir_cron_autovacuum
   oduit --env dev inspect cron base.ir_cron_autovacuum --trigger
   oduit --env dev inspect modules --state installed --names-only
   oduit --env dev inspect model res.partner
   oduit --env dev inspect field res.partner email --with-db
   oduit --env dev inspect subtypes crm.lead
   oduit --env dev inspect recordset "env['sale.order'].search([], limit=3).mapped('name')"

Use:

- ``inspect ref`` for XMLID resolution
- ``inspect cron`` for cron metadata and explicit triggering
- ``inspect modules`` for runtime module state from ``ir.module.module``
- ``inspect model`` / ``inspect field`` for ORM metadata
- ``inspect recordset`` only as the trusted arbitrary-expression escape hatch

db
^^

Inspect PostgreSQL metadata through the active Odoo connection.

.. code-block:: bash

   oduit --env dev db table res_partner
   oduit --env dev db column res_partner email
   oduit --env dev db constraints sale_order
   oduit --env dev db tables --like sale
   oduit --env dev db m2m res.partner category_id

performance
^^^^^^^^^^^

Read PostgreSQL performance metadata through the active Odoo connection.

.. code-block:: bash

   oduit --env dev performance table-scans
   oduit --env dev performance slow-queries --limit 10
   oduit --env dev performance indexes

``performance slow-queries`` reads ``pg_stat_statements`` only when the
extension is installed and reports clearly when it is unavailable.

manifest
^^^^^^^^

Use the ``manifest`` command group for path-or-addon-name manifest workflows.

.. code-block:: bash

   oduit --env dev manifest check sale
   oduit --env dev manifest check ./addons/my_module
   oduit --env dev manifest show sale

Showcase Replacements
^^^^^^^^^^^^^^^^^^^^^

Use the first-class commands instead of shell-only examples:

.. code-block:: bash

   # Resolve an XMLID
   oduit --env dev inspect ref base.action_partner_form

   # Inspect one model or field
   oduit --env dev inspect model project.task
   oduit --env dev inspect field res.partner email --with-db

   # Inspect PostgreSQL metadata
   oduit --env dev db table res_partner

   # Trusted one-off fallback
   oduit --env dev exec "env['project.task']._table"

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
      "schema_version": "2.0",
      "type": "result",
      "success": true,
      "operation": "install",
      "read_only": false,
      "safety_level": "controlled_runtime_mutation",
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
* ``safety_level``: ``safe_read_only``, ``controlled_runtime_mutation``,
  ``controlled_source_mutation``, or ``unsafe_arbitrary_execution``
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
Use :doc:`agent_command_inventory` for the generated agent command matrix and
``docs/maintainer/agent_contract_changes.md`` for machine-facing change notes.

When an agent needs exact parity with the human inspection / DB / performance /
manifest surface, use the direct structured wrappers instead of shell snippets:

.. code-block:: bash

   oduit --env dev agent inspect-ref base.action_partner_form
   oduit --env dev agent inspect-cron base.ir_cron_autovacuum
   oduit --env dev agent inspect-model res.partner
   oduit --env dev agent inspect-field res.partner email --with-db
   oduit --env dev agent db-table res_partner
   oduit --env dev agent manifest-check sale

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

inspect-ref
^^^^^^^^^^^

Resolve one XMLID through the structured agent envelope.

.. code-block:: bash

   oduit --env dev agent inspect-ref base.action_partner_form

inspect-cron
^^^^^^^^^^^^

Inspect one cron record, or trigger it explicitly with mutation approval.

.. code-block:: bash

   oduit --env dev agent inspect-cron base.ir_cron_autovacuum
   oduit --env dev agent inspect-cron base.ir_cron_autovacuum --trigger --allow-mutation

inspect-model
^^^^^^^^^^^^^

Inspect runtime model registration metadata with the agent envelope.

.. code-block:: bash

   oduit --env dev agent inspect-model res.partner

inspect-field
^^^^^^^^^^^^^

Inspect runtime field metadata, optionally including DB-level details.

.. code-block:: bash

   oduit --env dev agent inspect-field res.partner email --with-db

db-table / db-column / db-constraints / db-tables / db-m2m
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use the structured DB wrappers when an agent needs direct schema parity.

.. code-block:: bash

   oduit --env dev agent db-table res_partner
   oduit --env dev agent db-column res_partner email
   oduit --env dev agent db-constraints res_partner
   oduit --env dev agent db-tables --like res_%
   oduit --env dev agent db-m2m res.partner category_id

manifest-check / manifest-show
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Use the structured manifest wrappers instead of ad hoc file parsing.

.. code-block:: bash

   oduit --env dev agent manifest-check sale
   oduit --env dev agent manifest-show sale

plan-update
^^^^^^^^^^^

Build a read-only update plan with impact, risk metadata, and runtime mutation
policy details.

.. code-block:: bash

   oduit --env dev agent plan-update sale

prepare-addon-change
^^^^^^^^^^^^^^^^^^^^

Bundle the common read-only planning steps for one addon change into a single
structured payload.

.. code-block:: bash

   oduit --env dev agent prepare-addon-change my_partner --model res.partner --field email3
   oduit --env dev agent prepare-addon-change my_partner --model res.partner --field email3 --types form,tree

This command aggregates environment context, addon inspection, update planning,
source-location hints, addon model inventory, addon test inventory, and
best-effort runtime metadata queries for the requested model.

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

Locate likely Python source files for a model extension inside one addon. The
payload now includes ``resolution``, ``ambiguous``, and candidate ``evidence``
so agents can distinguish confirmed matches from ambiguous source hints.

.. code-block:: bash

   oduit --env dev agent locate-model res.partner --module my_partner

locate-field
^^^^^^^^^^^^

Locate an existing field definition or suggest the best insertion point. The
payload includes explicit ``resolution`` and ambiguity metadata, plus per-
candidate evidence for exact field matches.

.. code-block:: bash

   oduit --env dev agent locate-field res.partner email3 --module my_partner

list-addon-tests
^^^^^^^^^^^^^^^^

Return likely test files for an addon, optionally ranked by model or field
references.

.. code-block:: bash

   oduit --env dev agent list-addon-tests my_partner --model res.partner --field email3

recommend-tests
^^^^^^^^^^^^^^^

Map changed addon files to recommended tests and suggested ``--test-tags``.

.. code-block:: bash

   oduit --env dev agent recommend-tests --module my_partner --paths models/res_partner.py,views/res_partner_views.xml

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

Return the resolved configuration with sensitive values redacted. The payload
includes both the compatibility ``effective_config`` view and the canonical
sectioned ``normalized_config`` view, plus ``config_shape`` metadata and any
legacy-flat deprecation warnings.

.. code-block:: bash

   oduit --env dev agent resolve-config

resolve-addon-root
^^^^^^^^^^^^^^^^^^

Resolve a module name to one or more addon root candidates before editing.

.. code-block:: bash

   oduit --env dev agent resolve-addon-root sale

get-addon-files
^^^^^^^^^^^^^^^

Return a deterministic addon file inventory, optionally filtered by glob
patterns.

.. code-block:: bash

   oduit --env dev agent get-addon-files sale
   oduit --env dev agent get-addon-files sale --globs models/*.py,views/*.xml

check-addons-installed
^^^^^^^^^^^^^^^^^^^^^^

Return runtime installed-state checks for one or more addons.

.. code-block:: bash

   oduit --env dev agent check-addons-installed --modules sale,stock

check-model-exists
^^^^^^^^^^^^^^^^^^

Check whether a model exists in source discovery and, when available, runtime
metadata.

.. code-block:: bash

   oduit --env dev agent check-model-exists res.partner --module my_partner

check-field-exists
^^^^^^^^^^^^^^^^^^

Check whether a field exists in runtime metadata and source, or return the best
source insertion hint when it does not.

.. code-block:: bash

   oduit --env dev agent check-field-exists res.partner email3 --module my_partner

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

preflight-addon-change
^^^^^^^^^^^^^^^^^^^^^^

Run a cheap read-only addon-change preflight that bundles inspection, doctor,
duplicate checks, install-state lookup, source discovery, and likely test
inventory before editing.

.. code-block:: bash

   oduit --env dev agent preflight-addon-change sale --model res.partner --field email3

validate-addon-change
^^^^^^^^^^^^^^^^^^^^^

Run one end-to-end addon verification pass and return aggregate sub-results for
inspection, config health, duplicate checks, optional install or update, the
full module test suite, and optional discovered test inventory.

.. code-block:: bash

   oduit --env dev agent validate-addon-change sale --allow-mutation --update
   oduit --env dev agent validate-addon-change sale --allow-mutation --install-if-needed --discover-tests

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
Keep arbitrary code execution as a trusted fallback only; ``OdooCodeExecutor``
and ``execute_python_code()`` still require explicit ``allow_unsafe=True``.

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
   oduit --env dev export-lang my_module --allow-mutation --language de_DE

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

CLI Composition
^^^^^^^^^^^^^^^

.. automodule:: oduit.cli.app
   :members:
   :undoc-members:
   :show-inheritance:
   :no-index:

``oduit.cli_typer`` remains available as a compatibility import facade.

See Also
--------

- :doc:`quickstart` - Getting started with oduit
- :doc:`configuration` - Configuration file reference
- :doc:`api/odoo_operations` - OdooOperations API (used internally by CLI)
- :doc:`examples` - Python API usage examples
