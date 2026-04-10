Installation
============

Requirements
------------

* Python 3.10 or higher
* An Odoo instance for runtime commands such as ``run``, ``install``,
  ``update``, ``test``, and database-backed ``oduit agent`` queries

Install from PyPI
-----------------

.. code-block:: bash

   pip install oduit

Install from Source
-------------------

.. code-block:: bash

   git clone https://github.com/oduit/oduit.git
   cd oduit
   pip install -e .

Development Installation
------------------------

For local development, install the package in editable mode:

.. code-block:: bash

   git clone https://github.com/oduit/oduit.git
   cd oduit
   pip install -e .

Dependencies
------------

Core dependencies:

* ``PyYAML`` - For YAML configuration parsing
* ``tomli`` on Python versions earlier than 3.11
* ``tomli-w`` for writing TOML configuration
* ``typer`` for the CLI
* ``manifestoo-core`` for Odoo addon metadata and series support

Contributor workflows in this repository use tools such as ``pytest``, ``ruff``,
``mypy``, ``pre-commit``, and ``sphinx``.
