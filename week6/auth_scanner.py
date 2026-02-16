"""
Authentication Log Scanner
CVNP2646 - Week 6 Project

Parses authentication logs, detects brute force attack patterns,
and generates intelligence reports for SOC analysts.

Author: Tamara Arnott
Date: 2025
"""

import json
import sys
from collections import Counter
from datetime import datetime


def parse_log_line(line):
    """
    Parse a single authentication log line into a dictionary.

    Separates the various elements on each line to allow examination
    for correctness. Returns the parsed data and a list of any
    warnings encountered during parsing.

    Args:
        line: A single log line string

    Returns:
        tuple: (data_dict or None, list of warning strings)
            - data_dict contains 'timestamp' and any key=value fields found
            - warnings list describes any problems found during parsing
    """
    warnings = []

    # Everything is wrapped in try/except so the program does not crash
    # even if something unexpected goes wrong
    try:
        # Check for empty lines and short lines first because
        # they are the most common malformations
        line = line.strip()
        if not line:
            return None, ["Empty line"]

        parts = line.split()
        if len(parts) < 2:
            return None, [f"Line too short: {line}"]

        # Check for a date and time format so we know what to skip
        # and where to start the parsing of the key=value pairs
        if len(parts[0]) != 10 or parts[0][4] != '-':
            return None, [f"Missing or invalid date: {line}"]

        if ':' not in parts[1]:
            return None, [f"Missing or invalid time: {line}"]

        # First two parts are the timestamp (date + time)
        # Everything after that is key=value pairs
        timestamp = parts[0] + " " + parts[1]

        # Loop through the remaining parts and split each on =
        data = {'timestamp': timestamp}
        for pair in parts[2:]:
            # If = is missing, continue allows the program to keep going
            # rather than crashing. We log the warning so an analyst
            # can investigate later.
            if '=' not in pair:
                warnings.append(f"Malformed pair '{pair}' in line: {line}")
                continue
            # split('=', 1) splits on the first = only, in case the
            # value itself contains an = sign
            key, value = pair.split('=', 1)
            data[key] = value

        return data, warnings

    except Exception as e:
        return None, [f"Unexpected error parsing line: {line} ({e})"]


def analyze_logs(filename):
    """
    Read a log file, parse all lines, and count attack patterns.

    This is the main analysis engine. It goes through every line in
    the file, uses the parser to break each one apart, then counts
    up the successes, failures, and errors. It also saves any
    problem lines to a separate error log so an analyst can review
    them later.

    Args:
        filename: Path to the log file to analyze

    Returns:
        dict with all the counts and results needed for reporting
    """
    # Counter is used instead of plain dictionaries because it
    # doesn't crash when it sees a new username for the first time.
    # It also has most_common() which automatically gives us the
    # top 5 sorted by count.
    # How these work: the keys are the usernames (admin, root, test)
    # and the values are how many times each one failed.
    failed_by_user = Counter()
    failed_by_ip = Counter()
    parse_errors = Counter()
    total_lines = 0
    total_success = 0
    total_fail = 0
    successful_parses = 0

    # Open an error log file to save the actual bad lines.
    # This way an analyst can look at the specific lines that
    # failed and decide if it's normal corruption or tampering.
    with open('parse_errors.log', 'w') as error_log:
        error_log.write(f"Parse Error Log - Generated: {datetime.now()}\n")
        error_log.write("=" * 70 + "\n\n")

        # Read the log file one line at a time
        with open(filename, 'r') as f:
            for line in f:
                total_lines += 1

                # Send each line to the parser
                data, warnings = parse_log_line(line)

                # If there were any warnings, save them to the error log
                for warning in warnings:
                    error_log.write(f"Line {total_lines}: {warning}\n")

                # If parsing failed completely (returned None),
                # count it as a malformed line and move on
                if data is None:
                    parse_errors['malformed_line'] += 1
                    continue

                # If the line parsed but had a bad pair, count that too
                if warnings:
                    parse_errors['malformed_pair'] += 1

                # Check that the status field is actually SUCCESS or FAIL.
                # An empty status or garbage value means we can't use
                # this line for our analysis.
                status = data.get('status', '')
                if status not in ['SUCCESS', 'FAIL']:
                    parse_errors['invalid_status'] += 1
                    error_log.write(
                        f"Line {total_lines}: Invalid status '{status}'\n"
                    )
                    continue

                # If we made it here, the line is valid
                successful_parses += 1

                if status == 'SUCCESS':
                    total_success += 1
                elif status == 'FAIL':
                    # Only FAIL events get counted by user and IP
                    # because those are the potential attacks
                    total_fail += 1
                    failed_by_user[data.get('user', 'UNKNOWN')] += 1
                    failed_by_ip[data.get('ip', 'UNKNOWN')] += 1

    # Package everything up and send it back
    results = {
        'total_lines': total_lines,
        'successful_parses': successful_parses,
        'parse_errors': parse_errors,
        'total_success': total_success,
        'total_fail': total_fail,
        'failed_by_user': failed_by_user,
        'failed_by_ip': failed_by_ip,
    }

    return results


def generate_json_report(results, filename='incident_report.json'):
    """
    Generate a JSON intelligence report for SIEM integration.

    The JSON report is meant for other software to read automatically.
    SIEM tools like Splunk can ingest this file and trigger alerts
    based on the numbers. No human is expected to read this directly.

    Args:
        results: Dictionary returned by analyze_logs()
        filename: Output filename for the JSON report
    """
    total_events = results['successful_parses']
    total_errors = sum(results['parse_errors'].values())

    # Avoid dividing by zero if the file was empty or all lines failed
    if total_events > 0:
        failure_rate = round(
            (results['total_fail'] / total_events) * 100, 2
        )
    else:
        failure_rate = 0

    # Build the report as a Python dictionary, then let json.dump()
    # convert it to proper JSON format
    report = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'analyst': 'Tamara Arnott',
            'classification': 'INTERNAL'
        },
        'summary': {
            'total_events': total_events,
            'total_success': results['total_success'],
            'total_fail': results['total_fail'],
            'failure_rate': failure_rate,
            'parse_errors': total_errors
        },
        # most_common(5) returns the top 5 users/IPs sorted by count.
        # The list comprehension wraps each one in a dictionary with
        # clear labels so the JSON is easy to understand.
        'top_targeted_users': [
            {'username': user, 'failed_attempts': count}
            for user, count in results['failed_by_user'].most_common(5)
        ],
        'top_attacking_ips': [
            {'ip_address': ip, 'failed_attempts': count}
            for ip, count in results['failed_by_ip'].most_common(5)
        ]
    }

    # json.dump() writes directly to a file
    # indent=2 makes it readable with nice spacing
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)

    return report


def generate_text_report(results, filename='incident_report.txt'):
    """
    Generate a human-readable text report for SOC analysts.

    This is the report a human reads after the SIEM has already
    triggered an alarm. It puts the most critical information at
    the top so an analyst can understand the situation in about
    5 seconds. It also includes recommended actions.

    Args:
        results: Dictionary returned by analyze_logs()
        filename: Output filename for the text report
    """
    total_events = results['successful_parses']
    total_errors = sum(results['parse_errors'].values())

    if total_events > 0:
        failure_rate = (results['total_fail'] / total_events) * 100
        success_rate = (results['total_success'] / total_events) * 100
    else:
        failure_rate = 0
        success_rate = 0

    # Build the report as a list of strings, one per line.
    # At the end, join() connects them all with newlines.
    report = []

    # Header
    report.append("=" * 70)
    report.append("       AUTHENTICATION FAILURE ANALYSIS REPORT")
    report.append(
        f"       Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    report.append("=" * 70)
    report.append("")

    # Alert goes right at the top so the analyst sees it first.
    # Normal failure rate is 2-5%, anything over 10% is suspicious.
    if failure_rate > 10:
        report.append(
            f"ALERT: High failure rate detected: "
            f"{failure_rate:.1f}% (baseline: 2-5%)"
        )
        report.append("Potential BRUTE FORCE ATTACK in progress.")
        report.append("")

    # Summary statistics section
    # :, adds comma separators to large numbers (15,247 not 15247)
    # :.1f formats percentages to one decimal place (75.0%)
    report.append("-" * 70)
    report.append("SUMMARY STATISTICS")
    report.append("-" * 70)
    report.append(f"Total Events:        {total_events:,}")
    report.append(
        f"Successful Logins:   {results['total_success']:,}"
        f"  ({success_rate:.1f}%)"
    )
    report.append(
        f"Failed Attempts:     {results['total_fail']:,}"
        f"  ({failure_rate:.1f}%)"
    )
    report.append(f"Parse Errors:        {total_errors:,}")
    report.append("")

    # Top targeted accounts with severity labels.
    # CRITICAL = more than 5 attempts (heavy targeting)
    # HIGH = more than 2 attempts
    # MEDIUM = 1-2 attempts
    report.append("-" * 70)
    report.append("TOP 5 TARGETED ACCOUNTS")
    report.append("-" * 70)
    for i, (user, count) in enumerate(
        results['failed_by_user'].most_common(5), 1
    ):
        if count > 5:
            severity = "CRITICAL"
        elif count > 2:
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        # :20 pads the username to 20 characters so columns line up
        report.append(
            f"{i}. {user:20} {count:,} failed attempts"
            f"  >> {severity}"
        )
    report.append("")

    # Top attacking IPs with recommended action.
    # More than 5 attempts from one IP = block it immediately.
    report.append("-" * 70)
    report.append("TOP 5 ATTACKING SOURCE IPs")
    report.append("-" * 70)
    for i, (ip, count) in enumerate(
        results['failed_by_ip'].most_common(5), 1
    ):
        if count > 5:
            action = "BLOCK IMMEDIATELY"
        else:
            action = "INVESTIGATE"
        report.append(
            f"{i}. {ip:20} {count:,} failed attempts"
            f"  >> {action}"
        )
    report.append("")

    # Recommended actions only appear if failure rate is high.
    # These are the real-world steps a SOC team would take.
    if failure_rate > 10:
        report.append("-" * 70)
        report.append("RECOMMENDED ACTIONS")
        report.append("-" * 70)
        report.append("[ IMMEDIATE ]")

        top_ips = [ip for ip, _ in results['failed_by_ip'].most_common(3)]
        report.append(f"  - Block IPs: {', '.join(top_ips)}")
        report.append(
            "  - Lock targeted accounts and require password reset"
        )
        report.append("  - Enable MFA on all privileged accounts")
        report.append("  - Escalate to Incident Response team")
        report.append("")
        report.append("[ HIGH PRIORITY ]")
        report.append(
            "  - Review logs for successful logins from attacking IPs"
        )
        report.append(
            "  - Check for lateral movement from compromised accounts"
        )
        report.append(
            "  - Implement rate limiting on authentication endpoints"
        )
        report.append("")

    # Footer
    report.append("=" * 70)
    report.append("Report generated by: SOC Automation Platform")
    report.append("=" * 70)

    # join() takes every item in the list and connects them
    # with a newline character so each append becomes one line
    final_report = "\n".join(report)

    with open(filename, 'w') as f:
        f.write(final_report)

    return final_report


def main():
    """
    Main function that ties everything together.

    Gets the filename from the command line, runs the analysis,
    generates both reports, and prints a summary to the screen.
    """
    # sys.argv holds command-line arguments.
    # argv[0] is the script name, argv[1] is the filename we want.
    if len(sys.argv) < 2:
        print("Usage: python auth_scanner.py <logfile>")
        print("Example: python auth_scanner.py auth_test.log")
        sys.exit(1)

    filename = sys.argv[1]

    # Make sure the file actually exists before trying to process it
    try:
        with open(filename, 'r') as f:
            pass
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

    # Print header
    print("Authentication Log Scanner")
    print("=" * 50)
    print(f"Processing: {filename}")
    print()

    # Run the analysis — this does all the parsing and counting
    results = analyze_logs(filename)

    # Calculate rates for the screen output
    total_events = results['successful_parses']
    total_errors = sum(results['parse_errors'].values())
    if total_events > 0:
        failure_rate = (results['total_fail'] / total_events) * 100
        success_rate = (results['total_success'] / total_events) * 100
    else:
        failure_rate = 0
        success_rate = 0

    # Print parsing statistics so we know how clean the data was
    parse_rate = 0
    if results['total_lines'] > 0:
        parse_rate = (total_events / results['total_lines']) * 100
    print("Parsing Statistics:")
    print(f"  Total lines: {results['total_lines']}")
    print(f"  Successfully parsed: {total_events} ({parse_rate:.1f}%)")
    print(f"  Parse failures: {total_errors}")
    print()

    # Print analysis results
    print("Analysis Complete:")
    print(f"  Total events: {total_events}")
    print(f"  Successful logins: {results['total_success']} ({success_rate:.1f}%)")
    print(f"  Failed logins: {results['total_fail']} ({failure_rate:.1f}%)")

    # Alert if failure rate is above normal (2-5% is baseline)
    if failure_rate > 10:
        print(f"  !! ALERT: High failure rate detected ({failure_rate:.1f}%)")
    print()

    # Generate both reports — JSON for machines, text for humans
    generate_json_report(results)
    generate_text_report(results)

    # Confirm what files were created
    print("Reports generated:")
    print("  + incident_report.json")
    print("  + incident_report.txt")
    print("  + parse_errors.log")
    print("=" * 50)


if __name__ == '__main__':
    main()
