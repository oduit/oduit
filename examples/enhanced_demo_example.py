#!/usr/bin/env python3
"""
Enhanced demo mode example showing realistic log streaming.

This example demonstrates:
1. Progressive log streaming like real Odoo
2. Error scenarios with detailed logging
3. Different module behaviors with realistic timing
4. Comparison between demo and real execution patterns
"""

from oduit.config_loader import ConfigLoader
from oduit.odoo_operations import ModuleUpdateError, OdooOperations


def test_streaming_logs():
    """Test the new streaming log functionality"""
    print("=== Testing Enhanced Demo Mode with Log Streaming ===")

    config_loader = ConfigLoader()
    env_config = config_loader.load_demo_config()
    ops = OdooOperations(env_config, verbose=True)

    # Test successful module with log streaming
    print("\n1. Testing successful module with streaming logs:")
    print("   (Watch the progressive log output)")
    result = ops.update_module("sale", suppress_output=True)
    print(f"   ✓ Success: {result['success']}")
    print(f"   Duration: {result['duration']:.2f}s")

    # Test error module with detailed error logs
    print("\n2. Testing error module with detailed error streaming:")
    result = ops.update_module("module_error", suppress_output=True)
    print(f"   ✗ Success: {result['success']}")
    print(f"   Return code: {result['return_code']}")

    # Test warning module
    print("\n3. Testing warning module with streaming:")
    result = ops.update_module("module_warning", suppress_output=True)
    print(f"   ⚠ Success: {result['success']} (with warnings)")

    # Test unknown module
    print("\n4. Testing unknown module (should show warning stream):")
    result = ops.update_module("unknown_module", suppress_output=True)
    print(f"   ✗ Success: {result['success']} (module not found)")

    # Test slow module to see extended processing
    print("\n5. Testing slow module (extended processing time):")
    result = ops.update_module("module_slow", suppress_output=True)
    print(f"   ✓ Success: {result['success']} (took longer)")


def compare_demo_vs_real():
    """Compare demo output patterns with real Odoo patterns"""
    print("\n=== Demo vs Real Execution Comparison ===")

    print("\n📊 Demo mode characteristics:")
    print("   • Progressive log streaming with realistic timestamps")
    print("   • Simulated processing delays")
    print("   • Realistic error patterns and messages")
    print("   • No actual odoo-bin process required")
    print("   • Predictable outcomes for testing")

    print("\n📊 Real mode characteristics:")
    print("   • Actual Odoo process execution")
    print("   • Real database operations")
    print("   • Unpredictable timing based on system load")
    print("   • Genuine error conditions")
    print("   • Requires working Odoo installation")


def test_error_scenarios():
    """Test various error scenarios with detailed logging"""
    print("\n=== Testing Error Scenarios ===")

    config_loader = ConfigLoader()
    env_config = config_loader.load_demo_config()
    ops = OdooOperations(env_config, verbose=True)

    # Test with exception handling
    print("\n1. Testing exception handling with streaming:")
    try:
        ops.update_module("module_error", suppress_output=True, raise_on_error=True)
        print("   This shouldn't print")
    except ModuleUpdateError as e:
        print(f"   ✓ Caught expected error: {e}")
        if e.operation_result:
            print(f"   Error details: {e.operation_result.get('error', 'No details')}")

    # Test module installation error
    print("\n2. Testing installation error:")
    result = ops.install_module("module_error", suppress_output=True)
    print(f"   Install result: {result['success']}")


def main():
    """Main demo function"""
    print("🚀 Enhanced ODUIT Demo Mode with Log Streaming")
    print("=" * 60)

    try:
        test_streaming_logs()
        compare_demo_vs_real()
        test_error_scenarios()

        print("\n✅ Enhanced demo completed successfully!")
        print("\nNew features demonstrated:")
        print("• 📡 Progressive log streaming with timestamps")
        print("• ⏱️  Realistic processing delays")
        print("• 🔍 Detailed error scenario simulation")
        print("• 🎭 Multiple module behavior patterns")
        print("• 🔄 Stream-based output like real Odoo")

        return 0

    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
