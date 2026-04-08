Output
======

The output module provides text and JSON formatting helpers.

.. automodule:: oduit.output
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

.. code-block:: python

   from oduit import configure_output, print_error, print_info, print_result

   configure_output(format_type="json", non_interactive=True)
   print_info("Starting operation")
   print_result({"operation": "demo", "success": True}, "Operation completed")
   print_error("Something went wrong")

Key APIs
--------

- ``configure_output(format_type="text", non_interactive=False)``
- ``print_info()``, ``print_success()``, ``print_warning()``, ``print_error()``
- ``print_result(data, message=...)``
- ``print_error_result(error_msg, error_code=1)``
- ``OutputFormatter(format_type="text", non_interactive=False)``
