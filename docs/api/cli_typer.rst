CLI Typer Compatibility
=======================

``oduit.cli_typer`` remains as a compatibility facade for older imports.
The canonical Typer composition root now lives in :mod:`oduit.cli.app`.

Compatibility Exports
---------------------

.. automodule:: oduit.cli_typer
   :members:
   :undoc-members:
   :show-inheritance:

Canonical Module
----------------

For new code, import the root app object and entrypoint from
``oduit.cli.app`` instead:

.. autofunction:: oduit.cli.app.create_global_config
.. autofunction:: oduit.cli.app.cli_main
