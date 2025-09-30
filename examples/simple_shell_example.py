#!/usr/bin/env python3
"""
Simple example showing how to use ProcessManager's run_shell_command
with string commands.

This example demonstrates the new string command functionality that enables
shell features like pipes, redirects, and variable expansion.
"""

from oduit.process_manager import ProcessManager


def main():
    # Initialize the process manager
    pm = ProcessManager()

    print("=== ProcessManager String Command Examples ===\n")

    # Example 1: Basic pipe command
    print("1. Basic pipe command:")
    print("   Command: 'echo \"Hello World\" | wc -w'")
    result = pm.run_shell_command(
        'echo "Hello World" | wc -w', verbose=True, capture_output=True
    )
    if result["success"]:
        print(f"   ✓ Word count: {result['stdout'].strip()}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()

    # Example 2: Multiple pipes
    print("2. Multiple pipes with grep:")
    print("   Command: 'ps aux | grep python | grep -v grep | wc -l'")
    result = pm.run_shell_command(
        "ps aux | grep python | grep -v grep | wc -l", verbose=True, capture_output=True
    )
    if result["success"]:
        print(f"   ✓ Python processes running: {result['stdout'].strip()}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()

    # Example 3: Environment variables
    print("3. Environment variable expansion:")
    print("   Command: 'echo \"User: $USER, Home: $HOME\"'")
    result = pm.run_shell_command(
        'echo "User: $USER, Home: $HOME"', verbose=True, capture_output=True
    )
    if result["success"]:
        print(f"   ✓ {result['stdout'].strip()}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()

    # Example 4: File operations
    print("4. File operations with find and head:")
    print("   Command: 'find . -name \"*.py\" -type f | head -5'")
    result = pm.run_shell_command(
        'find . -name "*.py" -type f | head -5', verbose=True, capture_output=True
    )
    if result["success"]:
        print("   ✓ First 5 Python files:")
        for line in result["stdout"].strip().split("\n")[:5]:
            if line.strip():
                print(f"     - {line}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()

    # Example 5: Mathematical operations
    print("5. Mathematical operations using bc:")
    print("   Command: 'echo \"scale=2; 22/7\" | bc'")
    result = pm.run_shell_command(
        'echo "scale=2; 22/7" | bc', verbose=True, capture_output=True
    )
    if result["success"]:
        print(f"   ✓ 22/7 = {result['stdout'].strip()}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
        print("   (bc calculator might not be installed)")
    print()

    # Example 6: Backward compatibility with list commands
    print("6. Backward compatibility - list command:")
    print("   Command: ['echo', 'Hello', 'from', 'list']")
    result = pm.run_shell_command(
        ["echo", "Hello", "from", "list"], verbose=True, capture_output=True
    )
    if result["success"]:
        print(f"   ✓ Output: {result['stdout'].strip()}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()

    # Example 7: Demonstration of Odoo shell concept (without actual Odoo)
    print("7. Simulated shell interaction (Python REPL):")
    python_code = (
        "print('Hello from Python'); import sys; "
        "print(f'Python version: {sys.version_info.major}.{sys.version_info.minor}')"
    )
    command = f'echo "{python_code}" | python3'
    print('   Command: echo "<python_code>" | python3')
    result = pm.run_shell_command(command, verbose=True, capture_output=True)
    if result["success"]:
        print("   ✓ Python output:")
        for line in result["stdout"].strip().split("\n"):
            if line.strip():
                print(f"     {line}")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()

    # Example 8: Direct terminal output (no capture)
    print("8. Direct terminal output:")
    print("   Command: 'echo \"This output goes directly to terminal\"'")
    print("   (Output appears below)")
    result = pm.run_shell_command(
        'echo "This output goes directly to terminal"',
        verbose=False,
        capture_output=False,  # Direct to terminal
    )
    if result["success"]:
        print("   ✓ Command completed successfully")
    else:
        print(f"   ✗ Error: {result.get('error', 'Unknown error')}")
    print()

    print("=== Summary ===")
    print("✓ String commands enable full shell functionality")
    print("✓ Pipes, redirects, and variables work as expected")
    print("✓ List commands maintain backward compatibility")
    print("✓ Both capture_output modes work correctly")
    print("✓ This enables piping data to interactive programs like Odoo shell")

    return 0


if __name__ == "__main__":
    exit(main())
