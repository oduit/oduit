# oduit Examples

This directory contains example scripts demonstrating various features of oduit.

## Prerequisites

Before running these example scripts, you need to create a `.oduit.toml` configuration file in the directory where you'll run the scripts. This file contains the necessary configuration for connecting to your Odoo instance.

### Creating a .oduit.toml file

You can create a configuration file in one of two ways:

1. **Using the `oduit init` command** (recommended):
   ```bash
   oduit init myenv --from-conf /path/to/odoo.conf
   ```
   This creates a configuration in `~/.config/oduit/myenv.toml` that you can use with `--env myenv`.

2. **Creating a local `.oduit.toml` file manually**:
   Create a `.oduit.toml` file in the current directory with content like:
   ```toml
   python_bin = "/path/to/python"
   odoo_bin = "/path/to/odoo-bin"
   coverage_bin = "/path/to/coverage"
   db_name = "your_database_name"
   db_user = "odoo_user"
   db_password = "odoo_password"
   data_dir = "~/odoo_data"
   http_port = 8069
   addons_path = [
     "/path/to/odoo/addons",
     "/path/to/custom/addons",
   ]
   ```

## Example Scripts

### Module Management
- **`install_module_example.py`** - Install Odoo modules programmatically
- **`update_module_example.py`** - Update existing modules
- **`test_module_example.py`** - Run tests for specific modules

### Database Operations
- **`database_operations_example.py`** - Database creation and management

### Code Execution
- **`code_executor_example.py`** - Execute Python code in Odoo context
- **`execute_python_example.py`** - Another code execution example
- **`shell_command_example.py`** - Execute shell commands
- **`simple_shell_example.py`** - Simple shell interaction

### Manifest Management
- **`manifest_collection_example.py`** - Work with module manifest collections
- **`module_manifest_example.py`** - Parse and work with module manifests
- **`series_detection_example.py`** - Detect Odoo series from modules

### Demo Mode
- **`demo_mode_example.py`** - Using demo mode features
- **`demo_comparison.py`** - Compare demo mode implementations
- **`demo_test_scenarios.py`** - Test scenarios for demo mode
- **`enhanced_demo_example.py`** - Enhanced demo mode features

### Output Handling
- **`run_command_yielding_example.py`** - Handle command output with yielding
- **`yield_line_example.py`** - Process output line by line
- **`simple_yield_test.py`** - Simple yield testing

## Running the Examples

Once you have created a `.oduit.toml` file, you can run any example script:

```bash
python install_module_example.py
```

Or if you're using an environment configuration:

```bash
# First ensure your script loads the right config
python install_module_example.py
```

For more information, see the main [README.md](../README.md) in the project root.
