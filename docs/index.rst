Welcome to oduit's documentation!
=========================================

**oduit** is a Python package for managing Odoo instances through a YAML configuration system.
It helps start odoo-bin, run tests, and install/update addons with support for multiple environments.

Features
--------

* Start Odoo instances with custom configurations
* Run tests and manage test databases
* Install and update Odoo addons
* Support for multiple environments
* YAML-based configuration management
* Demo mode support for testing scenarios

Quick Start
-----------

.. code-block:: python

   from oduit import ConfigLoader, OdooOperations

   # Load configuration from environment file
   loader = ConfigLoader()
   env_config = loader.load_config('development')

   # Create operations manager
   ops = OdooOperations(env_config, verbose=True)

   # Start Odoo instance (runs until manually stopped)
   ops.run_odoo()

   # Install a module
   result = ops.install_module(module='sale')
   if result['success']:
       print("Module installed successfully!")

Installation
------------

.. code-block:: bash

   pip install oduit

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   installation
   quickstart
   cli
   configuration
   api
   examples
   changelog

API Reference
=============

.. toctree::
   :maxdepth: 2
   :caption: API Documentation:

   api/modules
   api/process_manager
   api/config_loader
   api/odoo_operations
   api/builders
   api/utils

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
