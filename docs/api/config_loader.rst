ConfigLoader
============

The config_loader module handles loading and parsing YAML and TOML configuration files.

.. automodule:: oduit.config_loader
   :members:
   :undoc-members:
   :show-inheritance:

Usage Examples
--------------

Loading Configurations
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.config_loader import ConfigLoader

   loader = ConfigLoader()

   # Load configuration by environment name
   config = loader.load_config('dev')      # Loads ~/.config/oduit/dev.yaml or dev.toml
   config = loader.load_config('prod')     # Loads ~/.config/oduit/prod.yaml or prod.toml

   # Load local configuration from current directory
   if loader.has_local_config():
       config = loader.load_local_config()  # Loads .oduit.toml

Environment Management
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from oduit.config_loader import ConfigLoader

   loader = ConfigLoader()

   # Get available environments
   environments = loader.get_available_environments()
   print(f"Available environments: {environments}")

   # Load demo configuration for testing
   demo_config = loader.load_demo_config()
   print(f"Demo mode: {demo_config.get('demo_mode', False)}")
