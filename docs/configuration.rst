Configuration
=============

oduit uses YAML or TOML configuration files to manage Odoo instances and operations.

Configuration Structure
-----------------------

oduit supports two configuration formats:

1. **Flat Format** (Legacy) - All keys at the root level
2. **Sectioned Format** (New) - Keys grouped into ``binaries`` and ``odoo_params`` sections

**Flat Format Example:**

.. code-block:: yaml

   python_bin: "/usr/bin/python3"
   odoo_bin: "/path/to/odoo-bin"
   coverage_bin: "/usr/bin/coverage"
   config_file: "/path/to/odoo.conf"
   addons_path: "/path/to/addons,/path/to/enterprise"
   db_name: "my_database"
   db_host: "localhost"
   db_port: 5432
   db_user: "odoo"
   db_password: "password"
   without_demo: false
   log_level: "info"

**Sectioned Format Example:**

.. code-block:: yaml

   binaries:
     python_bin: "/usr/bin/python3"
     odoo_bin: "/path/to/odoo-bin"
     coverage_bin: "/usr/bin/coverage"

   odoo_params:
     config_file: "/path/to/odoo.conf"
     addons_path: "/path/to/addons,/path/to/enterprise"
     db_name: "my_database"
     db_host: "localhost"
     db_port: 5432
     db_user: "odoo"
     db_password: "password"
     without_demo: false
     log_level: "info"

Configuration Options
---------------------

**Binaries Section:**

* ``python_bin`` - Path to Python executable (default: "python3")
* ``odoo_bin`` - Path to Odoo executable (required)
* ``coverage_bin`` - Path to coverage executable for test coverage

**Odoo Parameters Section:**

**Required Options:**

* ``db_name`` - Database name to use

**Optional Options:**

* ``config_file`` - Path to Odoo configuration file
* ``addons_path`` - Comma-separated list of addon directories
* ``db_host`` - Database host (default: "localhost")
* ``db_port`` - Database port (default: 5432)
* ``db_user`` - Database username (default: "odoo")
* ``db_password`` - Database password
* ``without_demo`` - Skip demo data installation (default: false)
* ``log_level`` - Log level ("debug", "info", "warn", "error")
* ``xmlrpc_port`` - XML-RPC port (default: 8069)
* ``http_port`` - HTTP port
* ``workers`` - Number of worker processes
* ``limit_time_cpu`` - CPU time limit per request
* ``limit_time_real`` - Real time limit per request

Environment-Specific Configurations
------------------------------------

You can create different configurations for different environments using YAML or TOML format:

**Development (dev.yaml):**

.. code-block:: yaml

   python_bin: "/usr/bin/python3"
   odoo_bin: "/opt/odoo-dev/odoo-bin"
   db_name: "odoo_dev"
   db_user: "dev_user"
   addons_path: "/opt/odoo-dev/addons,/opt/custom-addons"
   log_level: "debug"
   xmlrpc_port: 8069

**Production (prod.yaml):**

.. code-block:: yaml

   binaries:
     python_bin: "/usr/bin/python3"
     odoo_bin: "/opt/odoo/odoo-bin"

   odoo_params:
     db_name: "odoo_prod"
     db_user: "odoo_prod"
     db_password: "secure_password"
     db_host: "prod-db.example.com"
     addons_path: "/opt/odoo/addons,/opt/enterprise"
     xmlrpc_port: 8069
     workers: 8
     log_level: "warn"

Loading Configurations
----------------------

Load configuration in your Python code using environment names:

.. code-block:: python

   from oduit.config_loader import ConfigLoader

   loader = ConfigLoader()

   # Load environment-specific config from ~/.config/oduit/
   dev_config = loader.load_config('dev')       # Loads dev.yaml or dev.toml
   prod_config = loader.load_config('prod')     # Loads prod.yaml or prod.toml

   # Load local config from current directory
   if loader.has_local_config():
       local_config = loader.load_local_config()  # Loads .oduit.toml

Configuration files are loaded from:

1. ``.oduit.toml`` in current directory (if exists)
2. ``~/.config/oduit/<env_name>.(yaml|toml)``

**Available Environments:**

.. code-block:: python

   from oduit.config_loader import ConfigLoader

   loader = ConfigLoader()
   envs = loader.get_available_environments()
   print(f"Available environments: {envs}")

Configuration Validation
-------------------------

The configuration loader validates the configuration structure and required fields.
If validation fails, a ``ConfigError`` will be raised with details about missing or invalid options.

.. code-block:: python

   from oduit.exceptions import ConfigError
   from oduit.config_loader import ConfigLoader

   loader = ConfigLoader()
   try:
       config = loader.load_config('my_env')
   except ConfigError as e:
       print(f"Configuration error: {e}")

Advanced Configuration
----------------------

**Custom Module Paths:**

.. code-block:: yaml

   addons_path: "/opt/odoo/addons,/opt/enterprise/addons,/opt/custom/addons"

**Database Configuration:**

.. code-block:: yaml

   db_name: "my_odoo_db"
   db_user: "odoo_user"
   db_password: "secure_password"
   db_host: "database.example.com"
   db_port: 5432

**Server Configuration:**

.. code-block:: yaml

   xmlrpc_port: 8069
   http_port: 8080
   workers: 4
   limit_time_cpu: 60
   limit_time_real: 120

**Demo Mode Configuration:**

For testing without a real Odoo installation:

.. code-block:: python

   from oduit.config_loader import ConfigLoader

   loader = ConfigLoader()
   demo_config = loader.load_demo_config()
   # Returns configuration with demo_mode=True flag
