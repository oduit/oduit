Output
======

The output module provides utilities for formatting and displaying output.

.. automodule:: oduit.output
   :members:
   :undoc-members:
   :show-inheritance:

Functions
---------

.. autofunction:: oduit.configure_output
.. autofunction:: oduit.print_info
.. autofunction:: oduit.print_success
.. autofunction:: oduit.print_warning
.. autofunction:: oduit.print_error
.. autofunction:: oduit.print_result
.. autofunction:: oduit.print_error_result

Class Reference
---------------

.. autoclass:: oduit.OutputFormatter
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

Basic Output Functions
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import print_info, print_success, print_warning, print_error

   # Print different message types
   print_info("Starting operation...")
   print_success("Operation completed successfully!")
   print_warning("This is a warning message")
   print_error("An error occurred")

Output Configuration
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import configure_output, OutputFormatter

   # Configure output format
   configure_output(verbose=True, color=True)

   # Create custom formatter
   formatter = OutputFormatter(
       use_colors=True,
       timestamp=True,
       prefix="[ODUIT]"
   )

Result Output
~~~~~~~~~~~~~

.. code-block:: python

   from oduit import print_result, print_error_result, OperationResult

   # Print operation results
   result = OperationResult(success=True, message="Success!")
   print_result(result)

   # Print error results
   error_result = OperationResult(success=False, message="Failed", error="Details")
   print_error_result(error_result)
