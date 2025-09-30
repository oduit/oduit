Installation
============

Requirements
------------

* Python 3.9 or higher
* PyYAML
* Odoo instance (for operation)

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

For development, install with additional dependencies:

.. code-block:: bash

   git clone https://github.com/oduit/oduit.git
   cd oduit
   pip install -e ".[dev]"

   # Install pre-commit hooks
   pre-commit install

Dependencies
------------

Core dependencies:

* ``PyYAML`` - For YAML configuration parsing
* ``typing-extensions`` - For enhanced type hints

Development dependencies:

* ``pytest`` - Testing framework
* ``ruff`` - Linting and formatting
* ``pre-commit`` - Git hooks for code quality
* ``sphinx`` - Documentation generation
