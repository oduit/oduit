#!/usr/bin/env python3
"""
Example script showing the new execute_python_code function in OdooOperations.

This example demonstrates:
1. Using the simplified execute_python_code method
2. Executing single Python commands in Odoo environment
3. Executing multiple Python commands
4. Error handling with the new function
5. Comparison with the manual approach
"""

from oduit.config_loader import ConfigLoader
from oduit.odoo_operations import OdooOperations


def main():
    # Initialize configuration and operations
    config_loader = ConfigLoader()
    env_config = config_loader.load_config("common-test")
    odoo_ops = OdooOperations(env_config, verbose=True)
    odoo_ops_quiet = OdooOperations(env_config, verbose=False)

    print("=== New execute_python_code Examples ===\n")

    try:
        # Run examples
        run_simple_example(odoo_ops)
        run_environment_info_example(odoo_ops_quiet)
        run_query_data_example(odoo_ops_quiet)
        run_error_handling_example(odoo_ops_quiet)
        run_statistics_example(odoo_ops_quiet)

    except FileNotFoundError as e:
        print(f"Configuration file not found: {e}")
        print("Available environments:", config_loader.get_available_environments())
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

    print_summary()
    return 0


def run_simple_example(odoo_ops):
    """Run simple Python code execution example"""
    print("1. Simple Python code execution:")
    python_code = "print('Partners found:', len(env['res.partner'].search([])))"
    print(f"   Code: {python_code}")

    result = odoo_ops.execute_python_code(
        python_code=python_code,
        capture_output=True,
    )

    if result["success"]:
        print("   ✓ Output:")
        for line in result["stdout"].strip().split("\n"):
            if line.strip() and "Partners found:" in line:
                print(f"     {line}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()


def run_environment_info_example(odoo_ops):
    """Run environment information query example"""
    print("2. Environment information query:")
    env_info_code = """
print('=== Odoo Environment Info ===')
print('Database:', env.cr.dbname)
print('User:', env.user.name)
print('Company:', env.company.name)
partner_count = len(env['res.partner'].search([]))
print('Total partners:', partner_count)
print('=== Done ===')
"""
    result = odoo_ops.execute_python_code(
        python_code=env_info_code,
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


def run_query_data_example(odoo_ops):
    """Run query specific data example"""
    print("3. Query specific data:")
    query_code = """
partners = env['res.partner'].search([('is_company', '=', True)], limit=3)
print('=== Company Partners ===')
for partner in partners:
    print('-', partner.name, '(ID:', str(partner.id) + ')')
companies_total = len(env['res.partner'].search([('is_company', '=', True)]))
print('Total companies:', companies_total)
"""

    result = odoo_ops.execute_python_code(
        python_code=query_code,
        capture_output=True,
    )

    if result["success"]:
        print("   ✓ Output:")
        for line in result["stdout"].strip().split("\n"):
            if line.strip() and (
                "Company Partners" in line
                or line.strip().startswith("-")
                or "Total companies:" in line
            ):
                print(f"     {line}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()


def run_error_handling_example(odoo_ops):
    """Run error handling example"""
    print("4. Error handling example:")
    error_code = "print(nonexistent_variable)"

    result = odoo_ops.execute_python_code(
        python_code=error_code,
        capture_output=True,
    )

    if result["success"]:
        print("   ✓ Unexpected success")
    else:
        print("   ✓ Expected error caught")
        if "NameError" in result.get("stdout", "") or "NameError" in result.get(
            "stderr", ""
        ):
            print("     Error type: NameError (variable not defined)")
    print()


def run_statistics_example(odoo_ops):
    """Run complex calculation example"""
    print("5. Complex calculation example:")
    calc_code = """
# Calculate some statistics
user_count = len(env['res.users'].search([]))
partner_count = len(env['res.partner'].search([]))
company_count = len(env['res.partner'].search([('is_company', '=', True)]))

print('=== Odoo Statistics ===')
print(f'Users: {user_count}')
print(f'Partners: {partner_count}')
print(f'Companies: {company_count}')
print(f'Individual contacts: {partner_count - company_count}')
print('=== End Statistics ===')
"""

    result = odoo_ops.execute_python_code(python_code=calc_code, capture_output=True)

    if result["success"]:
        print("   ✓ Statistics:")
        for line in result["stdout"].strip().split("\n"):
            if line.strip() and any(
                keyword in line
                for keyword in [
                    "Users:",
                    "Partners:",
                    "Companies:",
                    "Individual contacts:",
                    "===",
                ]
            ):
                print(f"     {line}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()


def print_summary():
    """Print summary of the examples"""
    print("=== Summary ===")
    print("✓ execute_python_code() simplifies Odoo shell interaction")
    print("✓ No need to manually build commands or handle pipes")
    print("✓ Built-in error handling and result parsing")
    print("✓ Supports both simple and complex Python code execution")
    print("✓ Consistent return format with other oduit operations")


if __name__ == "__main__":
    exit(main())
