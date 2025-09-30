ConfigLoader
============

The config_loader module handles loading and parsing YAML and TOML configuration files.

.. automodule:: oduit.config_loader
   :members:
   :undoc-members:
   :show-inheritance:

Class Reference
---------------

.. autoclass:: oduit.config_loader.ConfigLoader
   :members:
   :undoc-members:
   :show-inheritance:

Functions
---------

.. autofunction:: oduit.config_loader.load_config
.. autofunction:: oduit.config_loader.get_config_path
.. autofunction:: oduit.config_loader.has_local_config
.. autofunction:: oduit.config_loader.load_local_config
.. autofunction:: oduit.config_loader.get_available_environments
.. autofunction:: oduit.config_loader.load_demo_config

Usage Examples
--------------

Loading Configurations
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import load_config

   # Load configuration by environment name
   config = load_config('dev')      # Loads ~/.config/oduit/dev.yaml or dev.toml
   config = load_config('prod')     # Loads ~/.config/oduit/prod.yaml or prod.toml

   # Load local configuration from current directory
   from oduit import load_local_config, has_local_config

   if has_local_config():
       config = load_local_config()  # Loads .oduit.toml

Environment Management
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit import get_available_environments, load_demo_config

   # Get available environments
   environments = get_available_environments()
   print(f"Available environments: {environments}")

   # Load demo configuration for testing
   demo_config = load_demo_config()
   print(f"Demo mode: {demo_config.get('demo_mode', False)}")
