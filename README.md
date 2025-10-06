[![PyPI - Version](https://img.shields.io/pypi/v/oduit)](https://pypi.org/project/oduit/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/oduit)
![PyPI - Downloads](https://img.shields.io/pypi/dm/oduit)
[![codecov](https://codecov.io/github/oduit/oduit/graph/badge.svg?token=6K8YL60OXJ)](https://codecov.io/github/oduit/oduit)

# oduit

A Python library for managing Odoo instances through a YAML configuration system. oduit helps start odoo-bin, run tests, and install/update addons with support for multiple environments.

## Features

- **Command Line Interface**: Simple CLI for common Odoo operations (run, install, test, shell)
- **Configuration Management**: YAML/TOML-based configuration with support for multiple environments
- **Process Management**: Run Odoo commands, shell commands, and manage processes
- **Module Management**: Install, update, and test Odoo modules
- **Demo Mode**: Specialized process manager for demo scenarios
- **Code Execution**: Execute Python code within Odoo environments and capture results
- **Flexible Output**: Configurable output formatting and logging
- **Operation Results**: Structured results with success/failure tracking

## Installation

```bash
pip install oduit
```

### Requirements

- Python 3.10+
- PyYAML 5.4+
- tomli 1.2.0+ (Python < 3.11)
- tomli-w 1.0.0+

## Invoking oduit without installing it

```
uvx oduit
```

## Quick Start

### Command Line Interface (CLI)

The easiest way to use oduit is through the command line:

```bash
# Create configuration file at ~/.config/oduit/dev.yaml
cat > ~/.config/oduit/dev.yaml << EOF
binaries:
  python_bin: "/usr/bin/python3"
  odoo_bin: "/path/to/odoo-bin"

odoo_params:
  db_name: "mydb"
  addons_path: "/path/to/addons"
  config_file: "/path/to/odoo.conf"
EOF

# Run Odoo server
oduit --env dev run

# Install a module
oduit --env dev install sale

# Run tests
oduit --env dev test --test-tags /sale

# Start Odoo shell
oduit --env dev shell

# Update a module
oduit --env dev update sale

# Create a new addon
oduit --env dev create-addon my_custom_module

# Export translations
oduit --env dev export-lang sale --language de_DE

# List available addons
oduit --env dev list-addons
```

**Local Project Configuration:**

Create a `.oduit.toml` in your project directory to avoid specifying `--env`:

```toml
[binaries]
python_bin = "./venv/bin/python"
odoo_bin = "./odoo/odoo-bin"

[odoo_params]
addons_path = "./addons"
db_name = "project_dev"
dev = true
```

Then run commands without `--env`:

```bash
oduit run
oduit install sale
oduit test --test-tags /sale
```

### Python API

For programmatic access and advanced usage, use the Python API:

#### Enhanced Operation Execution

```python
from oduit.config_loader import ConfigLoader
from oduit.process_manager import ProcessManager
from oduit.builders import InstallCommandBuilder, OdooTestCommandBuilder

# Load configuration
config_loader = ConfigLoader()
config = config_loader.load_config("myenv")

# Initialize process manager
process_manager = ProcessManager()

# Install a module using structured operations
install_builder = InstallCommandBuilder(config, "sale")
install_operation = install_builder.build_operation()

result = process_manager.run_operation(install_operation, verbose=True)

if result['success']:
    print("Module installed successfully!")
    print(f"Modules installed: {result.get('modules_installed', [])}")
    if result.get('modules_loaded'):
        print(f"Modules loaded: {result['modules_loaded']}")
else:
    print(f"Installation failed: {result.get('error', 'Unknown error')}")
    if result.get('dependency_errors'):
        print("Dependency errors:")
        for error in result['dependency_errors']:
            print(f"  - {error}")

# Run tests with enhanced result parsing
test_builder = OdooTestCommandBuilder(config, "/sale")
test_operation = test_builder.build_operation()

result = process_manager.run_operation(test_operation)

print(f"Test Success: {result['success']}")
print(f"Total Tests: {result.get('total_tests', 0)}")
print(f"Passed: {result.get('passed_tests', 0)}")
print(f"Failed: {result.get('failed_tests', 0)}")

if result.get('failures'):
    print("Test Failures:")
    for failure in result['failures']:
        print(f"  {failure['test_name']}: {failure.get('error_message', 'No details')}")
```

## Core Components

### Command Builders (New Architecture)

Build structured operations with rich metadata for enhanced result processing:

```python
from oduit.builders import (
    InstallCommandBuilder,
    UpdateCommandBuilder,
    OdooTestCommandBuilder,
    ShellCommandBuilder,
    DatabaseCommandBuilder
)

# Install command with metadata
install_builder = InstallCommandBuilder(config, "sale")
operation = install_builder.build_operation()

print(f"Command: {' '.join(operation.command)}")
print(f"Operation Type: {operation.operation_type}")  # 'install'
print(f"Modules: {operation.modules}")                # ['sale']
print(f"Result Parsers: {operation.result_parsers}")  # ['install']

# Test command with coverage
test_builder = OdooTestCommandBuilder(config, "/my_module")
operation = test_builder.build_operation()

print(f"Test Tags: {operation.test_tags}")            # '/my_module'
print(f"Expected Results: {operation.expected_result_fields}")

# Database operations
db_builder = DatabaseCommandBuilder(config)
db_builder.create_database("new_db")
operation = db_builder.build_operation()

print(f"Is Odoo Command: {operation.is_odoo_command}")  # False (postgres command)
```

### ConfigLoader

Loads and manages configuration from YAML/TOML files:

```python
from oduit import ConfigLoader

loader = ConfigLoader()

# Load environment configuration
config = loader.load_config("production")

# Check available environments
environments = loader.get_available_environments()

# Load local project configuration
if loader.has_local_config():
    local_config = loader.load_local_config()
```

### ConfigProvider

Provides a clean interface for accessing configuration values:

```python
from oduit.config_provider import ConfigProvider

provider = ConfigProvider(config)

# Get required values
db_name = provider.get_required("db_name")

# Get optional values with defaults
port = provider.get_optional("http_port", 8069)

# Get Odoo parameters as command line list
params = provider.get_odoo_params_list()
# Returns: ["--db-name=mydb", "--addons-path=/path/to/addons", "--http-port=8069"]
```

### ProcessManager

Execute commands with enhanced structured operations:

```python
from oduit.process_manager import ProcessManager
from oduit.builders import (
    InstallCommandBuilder,
    UpdateCommandBuilder,
    OdooTestCommandBuilder,
    ShellCommandBuilder
)

pm = ProcessManager()

# Enhanced structured operations (recommended)
install_builder = InstallCommandBuilder(config, "purchase")
operation = install_builder.build_operation()
result = pm.run_operation(operation, verbose=True)

# Access structured results
print(f"Success: {result['success']}")
print(f"Operation Type: {result.get('operation_type')}")
print(f"Database: {result.get('database')}")
print(f"Modules Installed: {result.get('modules_installed', [])}")

# Test operations with detailed parsing
test_builder = OdooTestCommandBuilder(config, "/my_module")
test_operation = test_builder.build_operation()
result = pm.run_operation(test_operation)

if result.get('failures'):
    print("Test failures:")
    for failure in result['failures']:
        print(f"  {failure['test_name']}: {failure.get('error_message')}")

# Update operations
update_builder = UpdateCommandBuilder(config, "stock")
update_operation = update_builder.build_operation()
result = pm.run_operation(update_operation)

print(f"Modules Updated: {result.get('modules_updated', [])}")

# Run Odoo commands directly
result = pm.run_command([
    "odoo-bin", "--db-name", "mydb", "--stop-after-init"
], timeout=30000)

# Real-time output streaming
for item in pm.run_command_yielding(["odoo-bin", "--help"]):
    if 'line' in item:
        print(item['line'].strip())
```

#### Process Manager Types

Choose the right process manager for your use case:

```python
from oduit.process_manager import ProcessManager
from oduit.demo_process_manager import DemoProcessManager

# Default: SystemProcessManager (subprocess execution)
pm = ProcessManager()

# Demo: Simulated execution for testing
pm = DemoProcessManager(config, available_modules=["base", "sale"])
```

**When to use each:**

- **SystemProcessManager**: Shell scripting, piped commands, external tools
- **DemoProcessManager**: Testing, demonstrations, offline development

**Shell Command Examples:**

```python
# System manager: Full shell support
result = pm.run_shell_command('echo "data" | psql mydb', capture_output=True)
```

### ModuleManager

Manage Odoo modules:

```python
from oduit import ModuleManager

mm = ModuleManager(config)

# Install modules
result = mm.install_module("sale", "mydb")

# Update modules
result = mm.update_module("stock", "mydb")

# Run module tests
result = mm.test_module("account", "mydb")

# Bulk operations
result = mm.install_modules(["sale", "purchase", "stock"], "mydb")
```

### OdooCodeExecutor

Execute Python code within an Odoo environment and capture results directly as Python objects:

```python
from oduit.config_provider import ConfigProvider
from oduit.odoo_code_executor import OdooCodeExecutor

# Initialize with configuration
basic_config = {
    "db_name": "mydb",
    "db_user": "odoo",
    "db_password": "odoo",
    "addons_path": "/opt/odoo/addons",
    "data_dir": "~/data",
}
config_provider = ConfigProvider(basic_config)
executor = OdooCodeExecutor(config_provider)

# Execute simple expressions - get partner name
result = executor.execute_code("env['res.partner'].search([],limit=1).name")
if result["success"]:
    partner_name = result["value"]  # Returns actual string, not printed output
    print(f"Partner: {partner_name}")

# Execute multi-line code with return values
code = """
partner_count = len(env['res.partner'].search([]))
customer_count = len(env['res.partner'].search([('is_company', '=', False)]))
company_count = len(env['res.partner'].search([('is_company', '=', True)]))

{
    'total_partners': partner_count,
    'customers': customer_count,
    'companies': company_count,
    'ratio': f"{customer_count}/{company_count}" if company_count > 0 else "N/A"
}
"""
result = executor.execute_code(code)
if result["success"]:
    stats = result["value"]  # Returns the dictionary directly
    print(f"Total partners: {stats['total_partners']}")
    print(f"Customer/Company ratio: {stats['ratio']}")

# Create data (with transaction control)
create_code = """
partner = env['res.partner'].create({
    'name': 'Test Partner',
    'email': 'test@example.com',
    'is_company': False
})
{'id': partner.id, 'name': partner.name, 'email': partner.email}
"""
result = executor.execute_code(create_code, commit=True)  # Will commit changes
if result["success"]:
    partner_data = result["value"]
    print(f"Created partner: {partner_data}")

# Execute multiple code blocks in sequence
code_blocks = [
    "partners = env['res.partner'].search([('is_company', '=', True)], limit=3)",
    "partner_names = [p.name for p in partners]",
    "{'count': len(partner_names), 'names': partner_names}"
]
result = executor.execute_multiple(code_blocks)
if result["success"]:
    final_result = result["results"][-1]["value"]
    print(f"Found {final_result['count']} companies: {final_result['names']}")

# Error handling
result = executor.execute_code("nonexistent_variable + 42")
if not result["success"]:
    print(f"Error: {result['error']}")
    print(f"Traceback: {result['traceback']}")
```

**Key Features:**

- **Direct Result Capture**: Returns Python objects, not console output
- **Expression & Statement Support**: Handles both single expressions and multi-line code blocks
- **Transaction Control**: Rollback by default, optional commit
- **Error Handling**: Detailed error messages and tracebacks
- **Multiple Code Blocks**: Execute sequences of related code in same transaction
- **Odoo Environment**: Full access to `env`, `cr`, `uid`, and common Python modules

### Manifest

Parse and validate Odoo module manifests:

```python
from oduit import Manifest

# Load manifest from __manifest__.py
manifest = Manifest.from_path("/path/to/module")

print(f"Module: {manifest.name}")
print(f"Version: {manifest.version}")
print(f"Dependencies: {manifest.depends}")

# Validate manifest
try:
    manifest.validate()
    print("Manifest is valid!")
except ManifestError as e:
    print(f"Invalid manifest: {e}")
```

## Configuration Formats

### Environment Configuration

**YAML Format** (`~/.config/oduit/myenv.yaml`):

```yaml
binaries:
  python_bin: "/usr/bin/python3"
  odoo_bin: "/opt/odoo/odoo-bin"

odoo_params:
  db_name: "mydb"
  addons_path: "/opt/odoo/addons:/custom/addons"
  config_file: "/etc/odoo/odoo.conf"
  workers: 4
  dev: true
```

**TOML Format** (`~/.config/oduit/myenv.toml`):

```toml
[binaries]
python_bin = "/usr/bin/python3"
odoo_bin = "/opt/odoo/odoo-bin"

[odoo_params]
db_name = "mydb"
addons_path = "/opt/odoo/addons:/custom/addons"
config_file = "/etc/odoo/odoo.conf"
workers = 4
dev = true
```

### Local Project Configuration

Create `.oduit.toml` in your project root for project-specific settings:

```toml
[binaries]
python_bin = "./venv/bin/python"
odoo_bin = "./odoo/odoo-bin"

[odoo_params]
addons_path = "./addons"
db_name = "project_dev"
dev = true
```

## Exception Handling

oduit provides specific exceptions for different error scenarios:

```python
from oduit import (
    ConfigError,
    OdooOperationError,
    ModuleOperationError,
    ModuleNotFoundError,
    DatabaseOperationError
)

try:
    result = module_manager.install_module("nonexistent", "mydb")
except ModuleNotFoundError as e:
    print(f"Module not found: {e}")
except DatabaseOperationError as e:
    print(f"Database error: {e}")
except OdooOperationError as e:
    print(f"Odoo operation failed: {e}")
```

## Output and Logging

Configure output formatting:

```python
from oduit import configure_output, print_info, print_success, print_error

# Configure output (colors, verbose mode, etc.)
configure_output(verbose=True, no_color=False)

# Use formatted output
print_info("Starting Odoo installation...")
print_success("Module installed successfully!")
print_error("Failed to connect to database")
```

## Examples

The `examples/` directory contains comprehensive examples showing both legacy and enhanced usage patterns:

### Enhanced Architecture Examples

- `enhanced_demo_example.py` - Complete workflow using command builders and structured operations
- `demo_comparison.py` - Side-by-side comparison of legacy vs enhanced approaches
- `code_executor_example.py` - Execute Python code within Odoo environments and capture results

### Legacy Examples (Still Supported)

- `simple_shell_example.py` - Basic shell command usage
- `install_module_example.py` - Module installation
- `test_module_example.py` - Module testing
- `demo_mode_example.py` - Demo process management
- `module_manifest_example.py` - Manifest parsing

### Key Enhanced Features Demonstrated

**Structured Results with Automatic Parsing:**

```python
# From enhanced_demo_example.py
result = process_manager.run_operation(install_operation)

# Rich structured results automatically parsed
print(f"Modules Loaded: {result.get('modules_loaded', 0)}")
print(f"Dependency Errors: {result.get('dependency_errors', [])}")
print(f"Installation Duration: {result.get('duration', 0):.2f}s")
```

**Test Results with Failure Details:**

```python
# Detailed test failure information
if result.get('failures'):
    for failure in result['failures']:
        print(f"Failed Test: {failure['test_name']}")
        print(f"File: {failure.get('file', 'Unknown')}:{failure.get('line', '?')}")
        print(f"Error: {failure.get('error_message', 'No details')}")
```

**Semantic Success Detection:**

```python
# Operations can be marked as failed even if process exits with code 0
# when semantic analysis detects issues (e.g., unmet dependencies)
if not result['success'] and result.get('dependency_errors'):
    print("Installation failed due to dependency issues:")
    for error in result['dependency_errors']:
        print(f"  - {error}")
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_config_provider.py

# Run with coverage
pytest --cov=oduit --cov-report=term
```

### Linting and Formatting

```bash
# Check and fix code style
ruff check --fix --exit-non-zero-on-fix --config=.ruff.toml

# Format code
ruff format

# Run pre-commit hooks
pre-commit run --all-files
```

### Project Structure

```
oduit/
├── oduit/           # Main library code
│   ├── __init__.py       # Public API exports
│   ├── config_loader.py  # Configuration loading
│   ├── config_provider.py # Configuration access
│   ├── process_manager.py # Process execution
│   ├── module_manager.py # Module operations
│   ├── manifest.py       # Manifest parsing
│   └── ...
├── tests/                # Unit tests
├── examples/             # Usage examples
└── docs/                 # Documentation
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite and linting
6. Submit a pull request

## License

This project is licensed under the Mozilla Public License 2.0. See the [LICENSE](LICENSE) file for details.

## Authors

The oduit Authors

---

For more detailed documentation, see the [docs](docs/) directory or visit the [project documentation](https://oduit.readthedocs.io/).
