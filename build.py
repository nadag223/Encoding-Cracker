#!/usr/bin/env python3
"""
Build script for CTF Encoding Cracker

Sets up the development environment and verifies the build.
"""

import os
import sys
import subprocess
import platform

def run_command(cmd, description):
    """Run a shell command with description"""
    print(f"\n{description}...")
    print(f"$ {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stdout:
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return False

def install_dependencies():
    """Install required dependencies"""
    print("\nInstalling dependencies...")

    # Check if pip is available
    if not run_command("pip --version", "Checking pip version"):
        print("Error: pip not found. Please install Python and pip first.")
        return False

    # Install requirements
    if not run_command("pip install -r requirements.txt", "Installing requirements"):
        print("Error: Failed to install dependencies.")
        return False

    return True

def verify_installation():
    """Verify that all dependencies are installed correctly"""
    print("\nVerifying installation...")

    # Test numpy
    try:
        import numpy
        print(f"✓ numpy version: {numpy.__version__}")
    except ImportError:
        print("✗ numpy not installed")
        return False

    # Test colorama
    try:
        import colorama
        print(f"✓ colorama version: {colorama.__version__}")
    except ImportError:
        print("✗ colorama not installed")
        return False

    # Test py-enigma (optional)
    try:
        import py_enigma
        print(f"✓ py-enigma version: {py_enigma.__version__}")
    except ImportError:
        print("⚠ py-enigma not installed (optional)")

    return True

def run_tests():
    """Run basic functionality tests"""
    print("\nRunning basic tests...")

    # Test method listing
    if not run_command("python cracker.py --list-methods | head -5", "Testing method listing"):
        print("Error: Method listing failed")
        return False

    # Test basic functionality
    test_cases = [
        ("SGVsbG8gV29ybGQ=", "Testing base64 decoding"),
        ("flag{test}", "Testing flag format detection"),
    ]

    for test_input, description in test_cases:
        cmd = f"python cracker.py \"{test_input}\" --no-parallel --max-depth 1 | head -10"
        if not run_command(cmd, description):
            print(f"Error: Test failed for input '{test_input}'")
            return False

    return True

def show_usage():
    """Show usage information"""
    print("\nCTF Encoding Cracker - Build Script")
    print("=" * 40)
    print("Usage: python build.py [command]")
    print("\nCommands:")
    print("  setup     - Install dependencies and verify installation")
    print("  test      - Run basic functionality tests")
    print("  clean     - Clean build artifacts (runs clean.py)")
    print("  all       - Run setup, test, and verify (default)")
    print("  --help    - Show this help message")

def main():
    print("CTF Encoding Cracker - Build Script")
    print("=" * 40)

    # Parse arguments
    command = "all"
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

    if command == "--help" or command == "-h":
        show_usage()
        return 0

    success = True

    if command == "setup" or command == "all":
        success &= install_dependencies()
        success &= verify_installation()

    if command == "test" or command == "all":
        success &= run_tests()

    if command == "clean":
        success &= run_command("python clean.py", "Running cleanup")

    if success:
        print("\n✅ Build completed successfully!")
        print("\nTo use the tool:")
        print("  python cracker.py \"<encoded_text>\" [options]")
        print("  python cracker.py --list-methods")
        print("  python cracker.py --help")
        return 0
    else:
        print("\n[ERROR] Build failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())