# Integration Tests

This directory contains integration tests that run against a real Odoo instance.

## Setup

1. **Configure Odoo Environment**: Edit `.oduit.toml` with your Odoo installation paths:
   ```toml
   python_bin = "/path/to/odoo/venv/bin/python3"
   odoo_bin = "/path/to/odoo-bin"
   db_name = "test_db"
   db_user = "odoo_user"
   db_password = "odoo_password"
   addons_path = [
     "/path/to/odoo/addons",
     "/path/to/integration_tests/myaddons/",
   ]
   ```

2. **Ensure Odoo is Accessible**: The Odoo binary and Python environment must be accessible.

3. **Database**: The test database should exist or Odoo should have permissions to create it.

## Test Modules

The `myaddons/` directory contains test modules:

- **Module a**: Has dependencies on modules b and c
- **Module b**: Has a dependency on `crm` and contains a failing test
- **Module c**: Has a dependency on `mail`, simple module
- **Module d**: Has a missing dependency (`nonexistent_module_will_fail`) to test installation failure

## Running Tests

### Run all integration tests:
```bash
pytest integration_tests/ -m integration -v
```

### Run specific test:
```bash
pytest integration_tests/test_basic_operations.py::test_install_module_success -v
```

### Skip integration tests in regular test runs:
```bash
pytest -m "not integration"
```

## Test Scenarios

1. **test_install_module_success**: Verifies successful module installation
2. **test_install_module_with_dependencies**: Tests dependency resolution (a → b,c)
3. **test_install_nonexistent_module**: Verifies error detection for missing modules
4. **test_module_with_missing_dependency**: Tests handling of modules with unmet dependencies (module d)
5. **test_module_test_failure**: Verifies oduit detects failing unit tests in module b
6. **test_run_module_tests_success**: Tests successful test execution

## CI/CD

These tests require a real Odoo instance and are typically:
- Run in a Docker container with Odoo pre-installed
- Skipped in lightweight CI environments
- Run nightly or before releases

## Troubleshooting

**Tests are skipped**: Check that:
- `.oduit.toml` paths point to valid Odoo installation
- Database credentials are correct
- Odoo has required dependencies installed

**Database errors**: Ensure the test database:
- Exists or can be created
- Is accessible with provided credentials
- Is not being used by another process
