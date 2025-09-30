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

Exception Classes
-----------------

.. autoexception:: oduit.ConfigError
   :members:
   :undoc-members:

.. autoexception:: oduit.OdooOperationError
   :members:
   :undoc-members:

.. autoexception:: oduit.ModuleOperationError
   :members:
   :undoc-members:

.. autoexception:: oduit.ModuleInstallError
   :members:
   :undoc-members:

.. autoexception:: oduit.ModuleUpdateError
   :members:
   :undoc-members:

.. autoexception:: oduit.ModuleNotFoundError
   :members:
   :undoc-members:

.. autoexception:: oduit.DatabaseOperationError
   :members:
   :undoc-members:

Usage Examples
--------------

Exception Handling
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import (
       load_config,
       ConfigError,
       OdooOperations,
       ModuleInstallError
   )

   try:
       config = load_config('dev')
   except ConfigError as e:
       print(f"Configuration error: {e}")
       exit(1)

   try:
       ops = OdooOperations(config)
       result = ops.install_modules(['nonexistent_module'])
   except ModuleInstallError as e:
       print(f"Module installation failed: {e}")
   except Exception as e:
       print(f"Unexpected error: {e}")

Custom Exception Handling
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.exceptions import ModuleOperationError

   def safe_module_operation(operation_func, *args, **kwargs):
       try:
           return operation_func(*args, **kwargs)
       except ModuleOperationError as e:
           print(f"Module operation failed: {e}")
           return None
       except Exception as e:
           print(f"Unexpected error: {e}")
           raise
