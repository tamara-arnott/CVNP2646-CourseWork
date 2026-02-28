"""
backup_planner.py
CVNP2646 - Week 7 Project
Config-Driven Backup Planner

Reads a JSON configuration file, validates its structure,
and generates a dry-run simulation report showing what
would be backed up. No actual files are copied.

Usage:
    python backup_planner.py backup_config.json
    python backup_planner.py invalid_config.json
"""

import json
import random
import sys
from datetime import datetime


# =============================================================================
# FUNCTION 1: LOAD CONFIG
# Reads the JSON config file and converts it to a Python dictionary.
# Handles two error cases: file not found, and broken/invalid JSON.
# =============================================================================

def load_config(filepath):
    """
    Load and parse a JSON backup configuration file.

    Args:
        filepath (str): Path to the JSON config file

    Returns:
        dict: Parsed configuration, or None if loading fails
    """
    try:
        with open(filepath) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Config file '{filepath}' not found")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{filepath}': {e}")
        return None


# =============================================================================
# FUNCTION 2: VALIDATE CONFIG
# Checks the config across 4 levels. Collects ALL errors before returning.
# Never returns after the first error — always reports the complete list.
# =============================================================================

def validate_config(config):
    """
    Validate backup configuration across 4 levels.

    Args:
        config (dict): Parsed JSON dict from load_config()

    Returns:
        tuple: (is_valid: bool, errors: list[str])
        Always collects ALL errors before returning.
    """
    errors = []

    # Level 2: Required fields
    # Check that plan_name, sources, and destination are all present
    required_fields = ['plan_name', 'sources', 'destination']
    for field in required_fields:
        if field not in config:
            errors.append(f"Missing required field: '{field}'")

    # Level 3: Type validation
    # Check that fields are the correct data types
    if 'sources' in config and not isinstance(config['sources'], list):
        errors.append(
            f"'sources' must be a list, got {type(config['sources']).__name__}"
        )

    if 'destination' in config and not isinstance(config['destination'], dict):
        errors.append(
            f"'destination' must be a dict, got {type(config['destination']).__name__}"
        )

    if 'plan_name' in config and not isinstance(config['plan_name'], str):
        errors.append(
            f"'plan_name' must be a string, got {type(config['plan_name']).__name__}"
        )

    # Level 4: Value validation
    # Check that values make logical sense
    if isinstance(config.get('sources'), list):
        if len(config['sources']) == 0:
            errors.append("'sources' list cannot be empty")

        for i, source in enumerate(config['sources']):
            if 'path' not in source:
                errors.append(f"Source {i}: missing 'path' field")
            elif not source['path']:
                errors.append(f"Source {i}: 'path' cannot be empty string")

    if isinstance(config.get('destination'), dict):
        dest = config['destination']
        if 'base_path' not in dest:
            errors.append("destination: missing 'base_path' field")
        elif not dest.get('base_path'):
            errors.append("destination: 'base_path' cannot be empty string")

    return len(errors) == 0, errors


# =============================================================================
# FUNCTION 3: SIMULATE BACKUP
# Generates fake file data to show what WOULD be backed up.
# Does NOT read real directories or copy any files.
# Uses the random module to create realistic fake file data.
# =============================================================================

def simulate_backup(config):
    """
    Generate a dry-run backup simulation using fake file data.

    Does NOT read real directories or copy any files.
    Uses random module to create realistic fake file data.

    Args:
        config (dict): Validated backup configuration

    Returns:
        dict: Simulation report with operations and summary statistics
    """
    operations = []

    for source in config['sources']:
        # Generate 5-15 fake files for each source
        num_files = random.randint(5, 15)
        files = []

        for i in range(num_files):
            size_mb = round(random.uniform(1, 100), 1)
            name = f"{source['name'].lower().replace(' ', '_')}_{i+1:03d}.log"
            files.append({'name': name, 'size_mb': size_mb})

        operations.append({
            'source_name': source['name'],
            'source_path': source['path'],
            'files': files
        })

    total_files = sum(len(op['files']) for op in operations)
    total_size = round(
        sum(f['size_mb'] for op in operations for f in op['files']), 1
    )

    timestamp = datetime.now().strftime('%Y-%m-%d_%H%M%S')

    return {
        'plan_name': config['plan_name'],
        'mode': 'DRY-RUN',
        'timestamp': timestamp,
        'summary': {
            'total_sources': len(operations),
            'total_files': total_files,
            'total_size_mb': total_size
        },
        'operations': operations
    }


# =============================================================================
# FUNCTION 4: GENERATE REPORT
# Prints a formatted, human-readable report to the screen.
# Shows summary statistics and sample files for each source.
# =============================================================================

def generate_report(report_data):
    """
    Print a formatted dry-run simulation report to stdout.

    Args:
        report_data (dict): Output from simulate_backup()
    """
    sep = '=' * 70
    thin = '-' * 70

    print(sep)
    print(f"{'BACKUP PLAN DRY-RUN SIMULATION':^70}")
    print(sep)
    print(f"Plan: {report_data['plan_name']}")
    print(f"Mode: {report_data['mode']} (no files will be copied)")
    print(f"Timestamp: {report_data['timestamp']}")
    print()

    s = report_data['summary']
    print('SUMMARY')
    print(thin[:7])
    print(f"Total Sources:  {s['total_sources']}")
    print(f"Total Files:    {s['total_files']}")
    print(f"Total Size:     {s['total_size_mb']} MB")
    print()

    for i, op in enumerate(report_data['operations'], 1):
        print(f"SOURCE {i}: {op['source_name']}")
        print(f"Path: {op['source_path']}")
        print(f"Files: {len(op['files'])}")
        for f in op['files'][:3]:
            print(f"  -> {f['name']} ({f['size_mb']} MB)")
        remaining = len(op['files']) - 3
        if remaining > 0:
            print(f"  ... and {remaining} more files")
        print()

    print(sep)
    print('DRY-RUN complete. No files were copied.')
    print(sep)


# =============================================================================
# FUNCTION 5: MAIN
# Orchestrates the entire pipeline in order:
# Load -> Validate -> Simulate -> Report
# =============================================================================

def main():
    """
    Orchestrate the backup planning pipeline.
    Reads config file path from command line argument.
    """
    if len(sys.argv) < 2:
        print("Usage: python backup_planner.py <config_file>")
        sys.exit(1)

    filepath = sys.argv[1]

    # Step 1: Load
    config = load_config(filepath)
    if config is None:
        sys.exit(1)

    # Step 2: Validate
    is_valid, errors = validate_config(config)
    if not is_valid:
        print(f"Validation FAILED. {len(errors)} error(s) found:")
        for i, err in enumerate(errors, 1):
            print(f"  [{i}] {err}")
        sys.exit(1)

    print("Validation PASSED.")

    # Step 3: Simulate
    report_data = simulate_backup(config)

    # Step 4: Report
    generate_report(report_data)


if __name__ == "__main__":
    main()
