#!/usr/bin/env python3
"""
Demo script showing different test scenarios using the demo process manager.

This example demonstrates:
1. Module with all passing tests
2. Module with one failing test
3. Module with multiple failing tests
"""

from oduit.config_loader import ConfigLoader
from oduit.odoo_operations import OdooOperations


def test_module_scenario(module_name: str, description: str):
    """Test a specific module scenario and display results"""
    print(f"\n{'=' * 60}")
    print(f"Testing: {module_name}")
    print(f"Scenario: {description}")
    print("=" * 60)

    config_loader = ConfigLoader()
    env_config = config_loader.load_demo_config()
    odoo_ops = OdooOperations(env_config, verbose=True)

    try:
        # Run tests for the module
        result = odoo_ops.run_tests(
            module=module_name,
            suppress_output=False,
        )

        # Display results
        if result["success"]:
            print(f"✓ Module {module_name} tests completed successfully!")
        else:
            print(f"✗ Module {module_name} tests failed!")

        print(f"  Duration: {result['duration']:.2f} seconds")
        print(f"  Return code: {result.get('return_code', 'Unknown')}")

        # Display test statistics if available
        if "total_tests" in result:
            print(
                f"  Tests: {result.get('passed_tests', 0)} passed, "
                f"{result.get('failed_tests', 0)} failed, "
                f"{result.get('error_tests', 0)} errors, "
                f"{result.get('total_tests', 0)} total"
            )

        # Display failure details
        failures = result.get("failures", [])
        if failures:
            print(f"  Failures ({len(failures)}):")
            for i, failure in enumerate(failures, 1):
                test_name = failure.get("test_name", "Unknown test")
                file_path = failure.get("file", "Unknown file")
                line_num = failure.get("line", "Unknown line")
                error_msg = failure.get("error_message", "Unknown error")
                print(f"    {i}. {test_name}")
                print(f"       File: {file_path}:{line_num}")
                print(f"       Error: {error_msg}")

        return result["success"]

    except Exception as e:
        print(f"Error testing module {module_name}: {e}")
        return False


def main():
    """Run demo test scenarios"""
    print("ODUIT Demo - Test Scenarios")
    print("This demo shows how different test outcomes are handled and displayed.")

    scenarios = [
        ("test_module_pass", "All tests pass"),
        ("test_module_one_fail", "One test fails"),
        ("test_module_multi_fail", "Multiple tests fail"),
    ]

    results = []
    for module_name, description in scenarios:
        success = test_module_scenario(module_name, description)
        results.append((module_name, success))

    # Summary
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    for module_name, success in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status} {module_name}")

    print(f"\nDemo completed. Tested {len(scenarios)} scenarios.")
    return 0


if __name__ == "__main__":
    exit(main())
