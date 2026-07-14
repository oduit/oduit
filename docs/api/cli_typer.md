# CLI Typer Compatibility

`oduit.cli_typer` remains as a compatibility facade for older imports.
The canonical Typer composition root now lives in `oduit.cli.app`.

## Compatibility Exports

```{eval-rst}
.. automodule:: oduit.cli_typer
   :members:
   :undoc-members:
   :show-inheritance:
```

## Canonical Module

For new code, import the root app object and entrypoint from
`oduit.cli.app` instead:

- {doc}`cli_app` documents the canonical `create_global_config()` export.
- {doc}`cli_app` documents the canonical `cli_main()` entrypoint.
