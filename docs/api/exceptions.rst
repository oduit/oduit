Exceptions
==========

The exceptions module defines custom exceptions used throughout oduit.

.. automodule:: oduit.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

Exception Hierarchy
-------------------

.. code-block:: text

   Exception
   └── ConfigError
   └── OdooOperationError
       ├── ModuleOperationError
       │   ├── ModuleInstallError
       │   ├── ModuleUpdateError
       │   └── ModuleNotFoundError
       └── DatabaseOperationError

Usage Examples
--------------

.. code-block:: python

   from oduit import ConfigLoader, ConfigError, ModuleInstallError, OdooOperations

   loader = ConfigLoader()

   try:
       config = loader.load_config("dev")
   except ConfigError as exc:
       print(f"Configuration error: {exc}")
   else:
       ops = OdooOperations(config)
       try:
           ops.install_module("nonexistent_module", raise_on_error=True)
       except ModuleInstallError as exc:
           print(f"Module installation failed: {exc}")
