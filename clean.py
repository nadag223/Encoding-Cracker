#!/usr/bin/env python3
"""
Build cleanup script for CTF Encoding Cracker

Removes temporary files, cache directories, and build artifacts
to ensure a clean build environment.
"""

import os
import shutil
import glob
import sys

def remove_directory(path):
    """Remove a directory if it exists"""
    if os.path.exists(path):
        print(f"Removing directory: {path}")
        shutil.rmtree(path)

def remove_file(path):
    """Remove a file if it exists"""
    if os.path.exists(path):
        print(f"Removing file: {path}")
        os.remove(path)

def remove_files(pattern):
    """Remove all files matching a pattern"""
    for file in glob.glob(pattern):
        remove_file(file)

def clean_pycache():
    """Remove all __pycache__ directories"""
    print("\nCleaning __pycache__ directories...")
    for root, dirs, files in os.walk('.'):
        for dir_name in dirs:
            if dir_name == '__pycache__':
                full_path = os.path.join(root, dir_name)
                remove_directory(full_path)

def clean_results():
    """Remove results directory"""
    print("\nCleaning results directory...")
    remove_directory('results')

def clean_bytecode():
    """Remove Python bytecode files"""
    print("\nCleaning Python bytecode files...")
    remove_files('*.pyc')
    remove_files('*.pyo')
    remove_files('*.pyd')

def clean_logs():
    """Remove log files"""
    print("\nCleaning log files...")
    remove_files('*.log')
    # Remove only specific txt files we want to clean
    remove_files('results/*.txt')
    remove_files('*.test')
    remove_files('*.out')

def clean_build_artifacts():
    """Remove build artifacts"""
    print("\nCleaning build artifacts...")
    remove_directory('build')
    remove_directory('dist')
    remove_files('*.egg-info')
    remove_files('*.spec')

def clean_ide_files():
    """Remove IDE-specific files"""
    print("\nCleaning IDE files...")
    remove_directory('.idea')
    remove_directory('.vscode')
    remove_files('*.swp')
    remove_files('*.swo')

def clean_all():
    """Run all cleanup tasks"""
    print("Starting comprehensive cleanup...")
    clean_pycache()
    clean_results()
    clean_bytecode()
    clean_logs()
    clean_build_artifacts()
    clean_ide_files()
    print("\nCleanup completed successfully!")

def main():
    print("CTF Encoding Cracker - Build Cleanup Script")
    print("=" * 50)

    # Check if specific cleanup requested
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            if arg == 'pycache':
                clean_pycache()
            elif arg == 'results':
                clean_results()
            elif arg == 'bytecode':
                clean_bytecode()
            elif arg == 'logs':
                clean_logs()
            elif arg == 'build':
                clean_build_artifacts()
            elif arg == 'ide':
                clean_ide_files()
            elif arg == '--help' or arg == '-h':
                print("\nUsage: python clean.py [option]")
                print("Options:")
                print("  pycache    - Clean __pycache__ directories")
                print("  results    - Clean results directory")
                print("  bytecode   - Clean Python bytecode files")
                print("  logs       - Clean log files")
                print("  build      - Clean build artifacts")
                print("  ide        - Clean IDE files")
                print("  (no args)  - Clean everything")
                return
    else:
        clean_all()

if __name__ == "__main__":
    main()