# ============================================================
# drift_checker.py
# CVNP2646 - Week 11 Project
# Configuration Drift Checker
# Tamara Arnott
# ============================================================
# What this program does:
# A Security Operations Center (SOC) analyst needs to know
# when a firewall configuration has changed from its approved
# "golden" baseline. This tool loads two JSON config files,
# compares them recursively, and reports every difference --
# missing settings, extra settings, and changed values.
#
# Think of it like comparing last year's approved org chart
# to what the division actually looks like today. Any
# difference gets flagged and reported to leadership.
# ============================================================

import json


# ============================================================
# THE BLUEPRINT (CLASS)
# ============================================================
# In higher education, every faculty evaluation follows the
# same form template -- same fields, same rating scale, same
# export format. But each completed form belongs to one
# specific faculty member.
#
# DriftResult is that template. Every time we find a
# difference between the baseline and current config, we
# fill out one of these forms. The class (blueprint) defines
# what every finding will contain and what it can do.
# ============================================================

class DriftResult:
    """
    Represents a single configuration drift finding.

    Think of this like a standardized incident report form.
    Every difference detected between the baseline and current
    config gets its own filled-out form (instance) with the
    same fields and the same built-in actions.

    Attributes:
        path (str):            Where in the config drift was found
                               e.g. "logging.enabled" or "rules[0].port"
        drift_type (str):      Type of drift: "missing", "extra", or "changed"
        baseline_value (any):  What the config should say (the approved value)
        current_value (any):   What the config actually says right now
        severity (str):        How serious this finding is: "high", "medium", "low"
    """

    # These keywords in a config path signal high-stakes drift.
    # Like a list of trigger words in a student grievance that
    # automatically escalates it to the AVP level for review.
    CRITICAL_KEYWORDS = ['password', 'secret', 'admin', 'root', 'enabled']

    def __init__(self, path, drift_type, baseline_value, current_value):
        """
        __init__ is the intake form -- it runs automatically
        the moment we create a new DriftResult.

        Like the moment a new adjunct file is opened at ATCC:
        the name gets recorded, credentials get filed, and the
        system immediately calculates their pay grade without
        anyone having to manually trigger those steps.

        Args:
            path:            Location in the config where drift was detected
            drift_type:      "missing", "extra", or "changed"
            baseline_value:  Expected value from the approved baseline config
            current_value:   Actual value found in the current config
        """
        # Store each piece of information on this specific instance.
        # Like filling in the fields on the faculty evaluation form.
        self.path = path
        self.drift_type = drift_type
        self.baseline_value = baseline_value
        self.current_value = current_value

        # Severity is calculated automatically the moment this
        # DriftResult is created -- we never have to think about
        # it manually. Like D2L automatically flagging at-risk
        # students the moment their grade drops below threshold.
        self.severity = self._calculate_severity()

    def _calculate_severity(self):
        """
        Private helper that figures out how serious this drift is.

        The underscore prefix means internal use only -- like a
        staff-only checkbox on the intake form that the employee
        never sees. This method is called automatically by __init__
        and is not intended to be called from outside the class.

        Severity rules:
            high:   Path contains a critical keyword (password, enabled, etc.)
            medium: A setting is missing from the current config
            low:    Everything else

        Returns:
            str: "high", "medium", or "low"
        """
        # Check if the config path contains any critical keywords.
        # Like scanning a student file for academic standing flags
        # that require immediate escalation.
        for keyword in self.CRITICAL_KEYWORDS:
            if keyword in self.path.lower():
                return "high"

        # Missing configurations are concerning -- like a student
        # whose required financial aid paperwork has disappeared.
        # Something that should be there isn't.
        if self.drift_type == "missing":
            return "medium"

        # Everything else is lower priority for now.
        return "low"

    def __str__(self):
        """
        Controls what prints when you do: print(result)

        Like the one-line summary at the top of an incident report --
        just enough information to know what happened at a glance.

        Icons used:
            [-]  missing  -- something expected is gone
            [+]  extra    -- something unexpected appeared
            [~]  changed  -- a value was modified

        Returns:
            str: e.g. "[~] logging.enabled (high)"
        """
        icons = {"missing": "[-]", "extra": "[+]", "changed": "[~]"}
        icon = icons.get(self.drift_type, "[?]")
        return f"{icon} {self.path} ({self.severity})"

    def to_dict(self):
        """
        Converts this DriftResult into a plain Python dictionary.

        Needed when we want to save results to a JSON file for
        records. Like exporting a completed faculty evaluation
        from the system into a CSV for HR's reporting database.

        Returns:
            dict: All attributes as a plain dictionary
        """
        return {
            "path": self.path,
            "type": self.drift_type,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "severity": self.severity
        }

    def is_critical(self):
        """
        Quick yes/no check: is this a high-severity finding?

        Like asking the system: "Is this student on academic
        probation?" -- returns True or False, nothing more.

        Returns:
            bool: True if severity is "high", False otherwise
        """
        return self.severity == "high"


# ============================================================
# PART 1: LOAD THE CONFIG FILES
# ============================================================

def load_config(filepath):
    """
    Opens a JSON configuration file and returns it as a
    Python dictionary.

    Think of this like sending a staff member to the filing
    cabinet to retrieve a folder. If the folder exists, they
    bring it back. If it's missing, they report back with a
    clear message instead of disappearing or crashing.

    Error handling covers two scenarios:
        FileNotFoundError:  The file doesn't exist at that path
        JSONDecodeError:    The file exists but the JSON inside is broken

    Args:
        filepath (str): Path to the JSON file to load

    Returns:
        dict: Parsed JSON content, or None if an error occurred
    """
    try:
        with open(filepath, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{filepath}': {e}")
        return None


# ============================================================
# PART 2: THE RECURSIVE COMPARISON ENGINE
# ============================================================

def compare_configs(baseline, current, path=""):
    """
    Recursively compares two configurations and returns a list
    of DriftResult objects for every difference found.

    This function works like an auditor reviewing ATCC's budget
    binders. The same rule applies at every level:

        Rule 1 - Dictionary: Check the keys at this level, then
                 open each matching section and apply this same
                 rule to what's inside. (recursion)

        Rule 2 - List: Check each item by slot number, then
                 apply this same rule to each item. (recursion)

        Rule 3 - Plain value: We've reached an actual value
                 (a number, True/False, a string). Just compare
                 it directly and stop going deeper. (base case)

    The path parameter works like breadcrumbs -- it tracks
    exactly where we are in the config so every finding can
    report its precise location, e.g. "rules[0].port".

    Args:
        baseline (dict/list/value): The approved "golden" config
        current  (dict/list/value): The actual current config
        path     (str):             Current location in the config tree

    Returns:
        list: List of DriftResult objects, one per difference found
    """
    results = []

    # ── CASE 1: BOTH ARE DICTIONARIES ──────────────────────
    # Like comparing two org charts -- check who appears on
    # each one, then open each matching department to compare
    # what's inside.
    if isinstance(baseline, dict) and isinstance(current, dict):
        baseline_keys = set(baseline.keys())
        current_keys = set(current.keys())

        # Who's in the baseline but missing from current?
        # Like finding a required position that was eliminated
        # from the org chart without AVP approval.
        for key in baseline_keys - current_keys:
            full_path = f"{path}.{key}" if path else key
            results.append(DriftResult(
                full_path,
                "missing",
                baseline[key],
                None
            ))

        # Who's in current but wasn't in the baseline?
        # Like finding an unauthorized position added to the
        # org chart that was never approved.
        for key in current_keys - baseline_keys:
            full_path = f"{path}.{key}" if path else key
            results.append(DriftResult(
                full_path,
                "extra",
                None,
                current[key]
            ))

        # For keys that appear in both, go one level deeper --
        # call this same function on the values inside.
        # Like opening each matching folder to check its contents.
        # results.extend() adds ALL findings from that deeper
        # call into our main results list.
        for key in baseline_keys & current_keys:
            full_path = f"{path}.{key}" if path else key
            results.extend(
                compare_configs(baseline[key], current[key], full_path)
            )

    # ── CASE 2: BOTH ARE LISTS ──────────────────────────────
    # Like comparing two course schedules by time slot.
    # Check each slot by index number, then go deeper into
    # whatever is at that slot.
    elif isinstance(baseline, list) and isinstance(current, list):
        max_len = max(len(baseline), len(current))

        for i in range(max_len):
            idx_path = f"{path}[{i}]"

            if i >= len(baseline):
                # Current has more items than baseline --
                # like finding an extra section added to the
                # schedule that was never approved.
                results.append(DriftResult(
                    idx_path,
                    "extra",
                    None,
                    current[i]
                ))
            elif i >= len(current):
                # Baseline has more items than current --
                # like a scheduled course section that
                # disappeared from the system.
                results.append(DriftResult(
                    idx_path,
                    "missing",
                    baseline[i],
                    None
                ))
            else:
                # Same index exists in both -- go deeper
                # and compare what's at this slot.
                results.extend(
                    compare_configs(baseline[i], current[i], idx_path)
                )

    # ── CASE 3: PLAIN VALUES (BASE CASE) ───────────────────
    # We've reached an actual value -- a number, a string,
    # True or False. This is the innermost layer, like finally
    # opening the smallest Russian nesting doll.
    # Just compare the two values directly and stop here.
    else:
        if baseline != current:
            results.append(DriftResult(
                path,
                "changed",
                baseline,
                current
            ))

    return results


# ============================================================
# PART 3: THE REPORT GENERATOR
# ============================================================

def display_drift_report(results):
    """
    Prints a formatted configuration drift report to the screen.

    Like the executive summary Tamara would send to leadership
    after an audit -- totals and severity counts up top,
    detailed findings listed below. Clear enough that someone
    who didn't run the tool can still understand what changed.

    Args:
        results (list): List of DriftResult objects from compare_configs
    """
    # Handle the case where no drift was detected at all
    if not results:
        print("✓ No configuration drift detected!")
        return

    print("=" * 60)
    print("CONFIGURATION DRIFT REPORT")
    print("=" * 60)

    # Count findings by drift type
    # Like tallying an audit report: how many missing items,
    # how many unauthorized additions, how many changes?
    type_counts = {"missing": 0, "extra": 0, "changed": 0}
    for result in results:
        type_counts[result.drift_type] += 1

    # Count findings by severity level
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for result in results:
        severity_counts[result.severity] += 1

    # Print the summary -- like the cover page of an audit report
    print(f"\nSummary:")
    print(f"  Total Drift Findings: {len(results)}")
    print(f"  By Type     - Missing: {type_counts['missing']}, "
          f"Extra: {type_counts['extra']}, "
          f"Changed: {type_counts['changed']}")
    print(f"  By Severity - High: {severity_counts['high']}, "
          f"Medium: {severity_counts['medium']}, "
          f"Low: {severity_counts['low']}")

    print(f"\nDetailed Findings:")
    print("-" * 60)

    # Print each finding -- like the detail pages of the audit.
    # print(result) automatically calls __str__ on the DriftResult,
    # which gives us the formatted one-line summary with icon.
    for result in results:
        print(result)
        if result.drift_type == "changed":
            print(f"    Baseline: {result.baseline_value}")
            print(f"    Current:  {result.current_value}")
        elif result.drift_type == "missing":
            print(f"    Expected: {result.baseline_value}")
        else:  # extra
            print(f"    Found:    {result.current_value}")


# ============================================================
# PART 4: MAIN -- THE PROCESS COORDINATOR
# ============================================================

def main():
    """
    Coordinates the entire drift checking process in order.

    Think of this like Tamara's role as AVP -- she doesn't
    do every task herself, she calls the right person for
    each step and checks that each step succeeded before
    moving to the next one.

    Pipeline:
        1. Load the baseline (approved) config
        2. Load the current (observed) config
        3. Verify both loaded successfully
        4. Run the recursive comparison
        5. Display the drift report
        6. Save results to a JSON file for records
    """
    # Step 1 & 2: Load both configuration files
    print("Loading configurations...")
    baseline = load_config('baseline.json')
    current = load_config('current.json')

    # Step 3: If either file failed to load, stop here.
    # Like discovering one of the org charts is missing --
    # you can't compare what you don't have.
    if baseline is None or current is None:
        print("Error: Could not load configuration files.")
        return

    # Step 4: Run the recursive comparison
    print("Comparing configurations...\n")
    results = compare_configs(baseline, current)

    # Step 5: Display the formatted report
    display_drift_report(results)

    # Step 6: Save results to a JSON file for records.
    # Like filing the completed audit report in the shared drive
    # so there's a permanent record of what was found.
    if results:
        output = [result.to_dict() for result in results]
        with open('drift_report.json', 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\n✓ Report saved to drift_report.json")


# ============================================================
# ENTRY POINT
# ============================================================
# This line means: only run main() if this file is being
# executed directly. Like saying "only start the meeting
# if YOU called it -- not if someone else referenced
# your agenda from their own document."
# ============================================================

if __name__ == "__main__":
    main()
