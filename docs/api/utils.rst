Utils
=====

The utils module contains general utility functions used throughout oduit.

.. automodule:: oduit.utils
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

File and Path Utilities
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import utils

   # Check if path exists and is accessible
   if utils.path_exists('/path/to/odoo'):
       print("Odoo path is valid")

   # Ensure directory exists
   utils.ensure_directory('/path/to/logs')

   # Get absolute path
   abs_path = utils.get_absolute_path('relative/path')

Process Utilities
~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Check if process is running
   if utils.is_process_running(1234):
       print("Process is running")

   # Kill process safely
   utils.kill_process(1234)

   # Execute command and get output
   output = utils.execute_command(['ls', '-la'])

Configuration Utilities
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Merge configuration dictionaries
   base_config = {'database': {'host': 'localhost'}}
   override_config = {'database': {'port': 5432}}
   merged = utils.merge_configs(base_config, override_config)

   # Validate configuration structure
   is_valid = utils.validate_config_structure(config_dict)

   # Get environment variable with default
   db_host = utils.get_env_var('DB_HOST', 'localhost')
