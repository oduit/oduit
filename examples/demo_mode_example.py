#!/usr/bin/env python3
"""
Example script demonstrating the demo mode functionality in oduit.

This example shows:
1. Loading demo configuration without requiring a real Odoo installation
2. Testing different module behaviors (success, error, warning)
3. Using all operations in demo mode for development and testing
"""

from oduit.config_loader import ConfigLoader
from oduit.odoo_operations import ModuleInstallError, OdooOperations


def test_module_operations():
    """Test module install/update operations in demo mode"""
    print("=== Testing Module Operations in Demo Mode ===")

    config_loader = ConfigLoader()
    env_config = config_loader.load_demo_config()
    ops = OdooOperations(env_config, verbose=True)

    # Test successful module update
    print("\n1. Testing successful module update:")
    result = ops.update_module("module_ok", suppress_output=True)
    print(f"   Success: {result['success']}")
    print(f"   Duration: {result['duration']:.2f}s")
    print(f"   Output: {result['stdout'][:100]}...")

    # Test module with warnings
    print("\n2. Testing module with warnings:")
    result = ops.update_module("module_warning", suppress_output=True)
    print(f"   Success: {result['success']}")
    print(f"   Output: {result['stdout'][:100]}...")

    # Test failing module
    print("\n3. Testing failing module:")
    result = ops.update_module("module_error", suppress_output=True)
    print(f"   Success: {result['success']}")
    print(f"   Error: {result.get('error', 'No error message')}")

    # Test unknown module
    print("\n4. Testing unknown module:")
    result = ops.update_module("unknown_module", suppress_output=True)
    print(f"   Success: {result['success']}")
    print(f"   Output: {result['stdout']}")

    # Test with exception handling
    print("\n5. Testing with exception handling:")
    try:
        ops.install_module("module_error", suppress_output=True, raise_on_error=True)
        print("   This shouldn't print")
    except ModuleInstallError as e:
        print(f"   ✓ Caught expected error: {e}")


def test_other_operations():
    """Test other operations in demo mode"""
    print("\n=== Testing Other Operations in Demo Mode ===")

    config_loader = ConfigLoader()
    env_config = config_loader.load_demo_config()
    ops = OdooOperations(env_config, verbose=True)

    # Test database creation
    print("\n1. Testing database creation:")
    result = ops.create_db(suppress_output=True)
    print(f"   Success: {result['success']}")
    print(f"   Database: {result['database']}")

    # Test addon creation
    print("\n2. Testing addon creation:")
    ops.create_addon("test_addon", template="default")

    # Test language export
    print("\n3. Testing language export:")
    ops.export_module_language(module="sale", filename="test.po", language="en_US")

    # Test module tests
    print("\n4. Testing module tests:")
    result = ops.run_tests(module="sale", compact=True)
    print(f"   Test success: {result['success']}")


def test_demo_vs_real_mode():
    """Demonstrate difference between demo and real mode"""
    print("\n=== Demo Mode vs Real Mode Comparison ===")

    config_loader = ConfigLoader()
    demo_config = config_loader.load_demo_config()
    print(f"Demo mode enabled: {demo_config.get('demo_mode', False)}")
    print(f"Available demo modules: {demo_config['available_modules']}")

    # Regular config would look like this (commented out since we don't have
    # real config)
    # try:
    #     real_config = load_config("development")  # Would load real config
    #     print(f"Real mode: {real_config.get('demo_mode', False)}")
    # except:
    #     print("No real config available - that's fine for this demo")

    ops = OdooOperations(demo_config, verbose=True)

    # Show that the same operation behaves differently
    print("\n1. Same operation, different behaviors:")

    # In demo mode - will succeed
    result1 = ops.update_module("sale", suppress_output=True)
    print(f"   Demo mode result: {result1['success']} (simulated)")

    # In real mode - would try to execute actual odoo-bin command
    # result2 = ops.update_module(
    #     real_config, "sale", verbose=True, suppress_output=True
    # )
    # print(f"   Real mode result: {result2['success']} (would run real command)")


def main():
    """Main demo function"""
    print("🚀 ODUIT Demo Mode Example")
    print("=" * 50)

    try:
        test_module_operations()
        test_other_operations()
        test_demo_vs_real_mode()

        print("\n✅ All demo tests completed successfully!")
        print("\nDemo mode allows you to:")
        print("• Test oduit functionality without Odoo installation")
        print("• Simulate different module behaviors (success/error/warning)")
        print("• Develop and test scripts safely")
        print("• Run CI/CD tests without database dependencies")

        return 0

    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
