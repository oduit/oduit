#!/usr/bin/env python3
"""
Example script showing how to execute Python code in the Odoo shell using oduit.

This example demonstrates:
1. Using OdooOperations.run_shell() to execute Python code in Odoo environment
2. Using piped input to send Python commands to the Odoo shell
3. Capturing output from Odoo shell commands
4. Error handling with Odoo shell operations
5. Multiple ways to interact with the Odoo shell programmatically
"""

from oduit.config_loader import ConfigLoader
from oduit.odoo_operations import (
    ConfigProvider,
    ShellCommandBuilder,
)


def main():
    # Initialize configuration and operations
    config_loader = ConfigLoader()

    print("=== Odoo Shell Command Examples ===\n")

    try:
        # Load configuration - adjust environment name as needed
        env_config = config_loader.load_config("common-test")

        print("1. Starting Odoo shell with embedded manager:")
        print("   Note: Embedded shell is interactive, can't be fully automated")

        config = ConfigProvider(env_config)
        cmd_builder = ShellCommandBuilder(config)
        cmd_builder.shell_interface("ipython")
        shell_cmd = cmd_builder.no_http().build()

        # Execute using ProcessManager's run_shell_command with string
        from oduit.base_process_manager import ProcessManagerFactory

        # Use system manager for piped commands which work better
        pm_system = ProcessManagerFactory.create_manager(manager_type="system")

        python_code = "print('Partners found:', len(env['res.partner'].search([])))"
        full_command = f'echo "{python_code}" | {" ".join(shell_cmd)}'
        print(f"   Full command: {full_command}")

        result = pm_system.run_shell_command(
            full_command, verbose=True, capture_output=True
        )

        if result["success"]:
            print("   ✓ Output:")
            for line in result["stdout"].strip().split("\n"):
                if line.strip() and ("Partners found:" in line or "test_db" in line):
                    print(f"     {line}")
        else:
            print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
            if result.get("stderr"):
                print(f"   Stderr: {result['stderr']}")
        print()

        print("3. Multiple Python commands with system manager:")
        python_commands = [
            "print('=== Odoo Environment Info ===')",
            "print('Database:', env.cr.dbname)",
            "print('User:', env.user.name)",
            "print('Company:', env.company.name)",
            "partner_count = len(env['res.partner'].search([]))",
            "print('Total partners:', partner_count)",
            "print('=== Done ===')",
        ]

        # Join commands with semicolons and newlines
        multi_command = "; ".join(python_commands)
        full_command = f'echo "{multi_command}" | {" ".join(shell_cmd)}'

        print(f"   Commands: {len(python_commands)} Python statements")
        result = pm_system.run_shell_command(
            full_command,
            verbose=False,  # Reduce verbosity for cleaner output
            capture_output=True,
        )

        if result["success"]:
            print("   ✓ Output:")
            for line in result["stdout"].strip().split("\n"):
                if line.strip() and any(
                    keyword in line
                    for keyword in [
                        "Database:",
                        "User:",
                        "Company:",
                        "Total partners:",
                        "===",
                    ]
                ):
                    print(f"     {line}")
        else:
            print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
        print()

        print("4. Error handling example with system manager:")
        error_code = "print(nonexistent_variable)"
        full_command = f'echo "{error_code}" | {" ".join(shell_cmd)}'

        print("   Code: print(nonexistent_variable)")
        result = pm_system.run_shell_command(
            full_command, verbose=False, capture_output=True
        )

        if result["success"]:
            print("   ✓ Unexpected success")
        else:
            print("   ✓ Expected error caught")
            # Look for Python error in output
            output_text = result.get("stdout", "") + result.get("stderr", "")
            if "NameError" in output_text:
                print("     Error type: NameError (variable not defined)")
        print()

    except FileNotFoundError as e:
        print(f"Configuration file not found: {e}")
        print("Available environments:", config_loader.get_available_environments())
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

    print("=== Summary ===")
    print("✓ Embedded manager starts interactive Odoo shell")
    print("✓ System manager supports piped input (echo | shell) for automation")
    print("✓ Multiple commands can be chained with semicolons")
    print("✓ Output can be captured and processed programmatically")
    print("✓ Error handling works for both shell and Python errors")
    print("✓ Choose the right manager type based on your use case:")
    print("  - Embedded: Better performance, interactive shell")
    print("  - System: Piped input support, subprocess execution")

    return 0


if __name__ == "__main__":
    exit(main())
