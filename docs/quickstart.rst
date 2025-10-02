Quick Start Guide
=================

This guide will help you get started with oduit's OdooOperations class quickly.

Basic Setup
-----------

**Using ConfigLoader with YAML Files**

First, create a YAML configuration file in ``~/.config/oduit/`` (e.g., ``development.yaml``):

.. code-block:: yaml

   python_bin: "/usr/bin/python3"
   odoo_bin: "/path/to/odoo-bin"
   db_name: "test_db"
   addons_path: "/path/to/custom/addons"
   coverage_bin: "/usr/bin/coverage"

Then load it using ConfigLoader:

.. code-block:: python

   from oduit.config_loader import ConfigLoader
   from oduit.odoo_operations import OdooOperations

   # Load configuration from YAML file
   config_loader = ConfigLoader()
   env_config = config_loader.load_config('development')

   # Create operations manager
   ops = OdooOperations(env_config, verbose=True)

**Using ConfigLoader with Local Config**

Create a ``.oduit.toml`` file in your project directory:

.. code-block:: toml

   python_bin = "/usr/bin/python3"
   odoo_bin = "/path/to/odoo-bin"
   db_name = "test_db"
   addons_path = ["/path/to/custom/addons", "/path/to/other/addons"]

Load the local configuration:

.. code-block:: python

   from oduit.config_loader import ConfigLoader
   from oduit.odoo_operations import OdooOperations

   # Load local .oduit.toml configuration
   config_loader = ConfigLoader()
   env_config = config_loader.load_local_config()

   # Create operations manager
   ops = OdooOperations(env_config, verbose=True)

**Import from Existing Odoo Configuration**

.. code-block:: python

   from oduit.config_loader import ConfigLoader
   from oduit.odoo_operations import OdooOperations

   # Import from existing Odoo .conf file
   config_loader = ConfigLoader()
   env_config = config_loader.import_odoo_conf('/path/to/odoo.conf')

   # Create operations manager
   ops = OdooOperations(env_config, verbose=True)

**Using Demo Configuration**

For testing and development, you can use the demo configuration:

.. code-block:: python

   from oduit.config_loader import ConfigLoader
   from oduit.odoo_operations import OdooOperations

   # Load demo configuration (no Odoo installation required)
   config_loader = ConfigLoader()
   env_config = config_loader.load_demo_config()
   ops = OdooOperations(env_config, verbose=True)

Core Operations
---------------

**Starting Odoo Server**

.. code-block:: python

   # Start Odoo server (runs until manually stopped)
   ops.run_odoo(no_http=False, verbose=True)

   # Start server without HTTP (for shell operations)
   ops.run_odoo(no_http=True)

**Module Operations**

.. code-block:: python

   # Install a module
   result = ops.install_module(module='sale')
   if result['success']:
       print("Module installed successfully!")
       print(f"Duration: {result['duration']:.2f} seconds")

   # Update a module
   result = ops.update_module(module='sale')

   # Install module without demo data
   result = ops.install_module(module='purchase', without_demo=True)

**Running Tests**

.. code-block:: python

   # Run tests for a specific module
   result = ops.run_tests(module='sale')

   # Run tests with coverage
   result = ops.run_tests(module='sale', coverage='sale')

   # Run tests and stop on first error
   result = ops.run_tests(module='sale', stop_on_error=True)

**Interactive Shell**

.. code-block:: python

   # Start Python shell
   result = ops.run_shell(shell_interface='python')

   # Start IPython shell
   result = ops.run_shell(shell_interface='ipython')

**Execute Python Code**

.. code-block:: python

   # Execute Python code in Odoo environment
   python_code = "print(env['res.users'].search_count([]))"
   result = ops.execute_python_code(python_code)
   if result['success']:
       print(result['stdout'])

Database Operations
-------------------

**Create Database**

.. code-block:: python

   # Drop and recreate database
   result = ops.create_db()
   if result['success']:
       print("Database created successfully!")

Addon Development
-----------------

**Create New Addon**

.. code-block:: python

   # Create new addon with default template
   result = ops.create_addon(addon_name='my_custom_module')

   # Create addon with specific template
   result = ops.create_addon(addon_name='my_module', template='theme')

   # Create addon in specific directory
   result = ops.create_addon(addon_name='my_module', destination='/path/to/addons')

Language Operations
-------------------

**Export Module Translations**

.. code-block:: python

   # Export French translations for sale module
   result = ops.export_module_language(
       module='sale',
       filename='sale_fr.po',
       language='fr_FR'
   )

Error Handling
--------------

**Using raise_on_error**

.. code-block:: python

   from oduit.exceptions import ModuleInstallError

   try:
       result = ops.install_module(
           module='nonexistent_module',
           raise_on_error=True
       )
   except ModuleInstallError as e:
       print(f"Installation failed: {e}")
       if e.operation_result:
           print(f"Operation result: {e.operation_result}")

**Checking Results**

.. code-block:: python

   result = ops.install_module(module='sale')

   if result['success']:
       print("Installation successful")
       print(f"Duration: {result['duration']:.2f} seconds")
   else:
       print(f"Installation failed: {result.get('error', 'Unknown error')}")
       print(f"Return code: {result.get('return_code')}")

Silent Operations
-----------------

For programmatic use without output:

.. code-block:: python

   # Silent operations (no output)
   result = ops.install_module(module='sale', suppress_output=True)
   result = ops.run_tests(module='sale', suppress_output=True)

Demo Mode
---------

For testing without requiring a real Odoo installation:

.. code-block:: python

   from oduit.config_loader import ConfigLoader
   from oduit.odoo_operations import OdooOperations

   # Load demo configuration
   config_loader = ConfigLoader()
   env_config = config_loader.load_demo_config()
   ops = OdooOperations(env_config, verbose=True)

   # All operations work in demo mode with simulated output
   result = ops.install_module(module='sale')
   result = ops.run_tests(module='sale')

Next Steps
----------

* Read the :doc:`configuration` guide for detailed configuration options
* Check out the :doc:`examples` for more usage scenarios
* Browse the :doc:`api` documentation for complete API reference
