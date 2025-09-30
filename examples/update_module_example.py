#!/usr/bin/env python3
"""
Example script showing how to update an Odoo module using oduit.

This example demonstrates:
1. Loading configuration from a YAML/TOML file
2. Using OdooOperations to update a module with the new unified return structure
3. Error handling with return values and exceptions
4. Using the suppress_output mode for programmatic usage
"""

from oduit.config_loader import ConfigLoader
from oduit.odoo_operations import ModuleUpdateError, OdooOperations


def main():
    # Initialize the configuration loader and operations
    config_loader = ConfigLoader()
    # Option 1: Load configuration from ~/.config/oduit/development.yaml
    # Replace "development" with your environment name
    env_config = config_loader.load_config("common-test")

    # Option 2: Load from local .oduit.toml file in current directory
    # Uncomment the following line if you have a local config file:
    # env_config = config_loader.load_local_config()

    odoo_ops = OdooOperations(env_config, verbose=True)

    try:
        # Update a specific module
        module_name = "sale"  # Replace with your module name

        print(f"Updating module: {module_name}")

        # Example 1: Update with return value checking (suppress_output mode)
        result = odoo_ops.update_module(
            module=module_name,
            no_http=True,
            suppress_output=True,  # Suppress output for programmatic use
        )

        # Check the result
        if result["success"]:
            print(f"✓ Module {module_name} updated successfully!")
            print(f"  Duration: {result['duration']:.2f} seconds")
            print(f"  Command: {' '.join(result['command'])}")
        else:
            print(f"✗ Module {module_name} update failed!")
            print(f"  Error: {result.get('error', 'Unknown error')}")
            print(f"  Return code: {result.get('return_code', 'Unknown')}")
            return 1

        # Example 2: Update with exception handling
        # This will now properly detect when a module doesn't exist
        try:
            odoo_ops.update_module(
                module="nonexistent_module_test",
                suppress_output=True,
                raise_on_error=True,  # This will raise an exception on failure
            )
            print("This shouldn't print if module doesn't exist")
        except ModuleUpdateError as e:
            print(f"✓ Expected error caught: {e}")
            if e.operation_result:
                print(
                    f"  Operation result available: "
                    f"success={e.operation_result['success']}"
                )
                print(
                    f"  Error type: {e.operation_result.get('error_type', 'Unknown')}"
                )

        return 0

    except FileNotFoundError as e:
        print(f"Configuration file not found: {e}")
        print("Available environments:", config_loader.get_available_environments())
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
