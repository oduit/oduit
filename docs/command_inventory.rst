CLI command inventory
=====================

This page is generated from the canonical Typer registration surface in
``oduit.cli.app``.

.. list-table:: Canonical top-level CLI commands
   :header-rows: 1

   * - Command
     - Stability tier
     - Summary
   * - ``doctor``
     - ``human_oriented``
     - Diagnose environment and configuration issues.
   * - ``run``
     - ``human_oriented``
     - Run Odoo server.
   * - ``shell``
     - ``human_oriented``
     - Start Odoo shell.
   * - ``install``
     - ``human_oriented``
     - Install module.
   * - ``update``
     - ``human_oriented``
     - Update module.
   * - ``uninstall``
     - ``human_oriented``
     - Uninstall module.
   * - ``test``
     - ``human_oriented``
     - Run module tests with various options.
   * - ``create-db``
     - ``human_oriented``
     - Create database.
   * - ``list-db``
     - ``human_oriented``
     - List all databases.
   * - ``list-env``
     - ``human_oriented``
     - List available environments.
   * - ``print-config``
     - ``human_oriented``
     - Print environment config.
   * - ``edit-config``
     - ``human_oriented``
     - Open the active config file in the default editor.
   * - ``create-addon``
     - ``human_oriented``
     - Create new addon.
   * - ``print-manifest``
     - ``human_oriented``
     - Print addon manifest information in a table.
   * - ``addon-info``
     - ``human_oriented``
     - Print a combined manifest, source, and runtime addon summary.
   * - ``list-addons``
     - ``human_oriented``
     - List available addons.
   * - ``list-installed-addons``
     - ``human_oriented``
     - List installed addons from the active database.
   * - ``list-manifest-values``
     - ``human_oriented``
     - List unique values for a manifest field across all addons.
   * - ``list-duplicates``
     - ``human_oriented``
     - List duplicate addon names across configured addon paths.
   * - ``list-depends``
     - ``human_oriented``
     - List direct dependencies needed to install a set of modules.
   * - ``list-codepends``
     - ``human_oriented``
     - List reverse dependencies for a module.
   * - ``install-order``
     - ``human_oriented``
     - Return the dependency-resolved install order for one or more addons.
   * - ``impact-of-update``
     - ``human_oriented``
     - Show addons affected by updating a specific module.
   * - ``list-missing``
     - ``human_oriented``
     - Find missing dependencies for modules.
   * - ``init``
     - ``human_oriented``
     - Initialize a new oduit environment configuration.
   * - ``export-lang``
     - ``human_oriented``
     - Export language module.
   * - ``version``
     - ``human_oriented``
     - Get Odoo version from odoo-bin.
   * - ``exec``
     - ``human_oriented``
     - Execute trusted Python within Odoo and return a structured result.
   * - ``exec-file``
     - ``human_oriented``
     - Execute trusted Python from a file within Odoo.
   * - ``docs``
     - ``human_oriented``
     - Generate addon and model documentation
   * - ``inspect``
     - ``human_oriented``
     - Runtime model, field, XMLID, and module inspection
   * - ``db``
     - ``human_oriented``
     - Database inspection through the live Odoo connection
   * - ``performance``
     - ``human_oriented``
     - Read-only PostgreSQL performance inspection
   * - ``manifest``
     - ``human_oriented``
     - Manifest inspection and validation
