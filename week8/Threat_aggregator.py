# ============================================================
# THREAT INTELLIGENCE AGGREGATOR
# Tamara Arnott - CVNP2646 Week 8
# ============================================================
#
# WHAT THIS SCRIPT DOES IN PLAIN LANGUAGE:
#
# Imagine your institution receives student transfer records
# from three different colleges. Each college uses different
# column headers on their transcripts:
#   - College A calls it "Credits Earned"
#   - College B calls it "Credit Hours"
#   - College C calls it "Units Completed"
#
# This script reads all three sets of records (vendor feeds),
# translates everything into ONE consistent format,
# flags incomplete or invalid records, removes courses
# that appear more than once, filters out records that
# do not meet our standards, and produces three final
# outputs for different offices:
#
#   1. firewall_blocklist.json  -- a block list for the firewall
#   2. siem_feed.json           -- a detailed feed for the SIEM tool
#   3. summary_report.txt       -- a plain English summary for staff
#
# This is called ETL: Extract (load the data), Transform
# (normalize, clean, filter), Load (write the outputs).
# It is one of the most common patterns in data engineering.
# ============================================================

import json
from datetime import datetime, timezone
from collections import Counter

# ============================================================
# CONFIGURABLE FILTERS
# These are the three minimum standards that decide which
# threat indicators are worth acting on.
#
# Think of it like setting transfer credit acceptance standards:
#   - Only courses with a grade of C or better advance
#   - Only courses from accredited institutions qualify
#   - Only courses in approved subject areas are eligible
#
# Change the values here and the whole script adjusts --
# you never have to hunt through the rest of the code
# to update a standard. One place, one change.
# ============================================================
MIN_CONFIDENCE = 85                          # Minimum score to keep (like a C or better)
ALLOWED_THREAT_LEVELS = ["high", "critical"] # Only act on serious threats
ALLOWED_TYPES = ["ip", "domain"]             # Firewalls can only block these two types


# ============================================================
# FUNCTION 1: LOAD FEED
#
# This is the registrar receiving transcripts from different
# colleges and universities. Each institution sends their
# records in their own format and the registrar brings them
# into our system so we can begin processing them.
#
# If a transcript packet never arrived (file not found)
# or arrived damaged and unreadable (invalid JSON),
# it logs the problem instead of crashing the entire
# processing run.
# ============================================================
def load_feed(filepath):
    """Open a JSON vendor file and return the contents as a Python dictionary."""
    try:
        with open(filepath, "r") as f:
            return json.load(f)  # converts the JSON text into a Python dictionary
    except FileNotFoundError:
        # The file does not exist at the path we gave it
        # Like a transcript packet that was never received
        print(f"ERROR: File not found: {filepath}")
        return None
    except json.JSONDecodeError:
        # The file exists but the JSON inside it is broken
        # Like receiving a transcript that is corrupted and unreadable
        print(f"ERROR: Invalid JSON in file: {filepath}")
        return None


# ============================================================
# FUNCTION 2: NORMALIZE INDICATOR
#
# This is the TRANSLATION step -- the first half of our
# normalize/denormalize process.
#
# Think of it like a transfer evaluator who accepts
# ENGL 101 from a sending institution and maps it to
# ENGL 1410 at ATCC. The course content is the same --
# only the label changed. The evaluator reads whichever
# prefix and number the sending institution used and
# maps it to OUR standard ATCC equivalent.
#
# After this step, every indicator looks identical
# regardless of which vendor it came from -- just like
# every transfer course gets mapped to its ATCC equivalent
# regardless of what the sending college called it.
#
# The .get() method tries each vendor's field name in order.
# The first one that returns a real value wins.
# Example:
#   indicator.get("type") or indicator.get("indicator_type") or indicator.get("category")
#   -- tries "type" first, if empty tries "indicator_type",
#      if still empty tries "category"
# ============================================================
def normalize_indicator(indicator, source_name):
    """Translate one vendor's field names into our standard internal format."""
    return {
        # ID: the vendor's internal tracking number for this threat
        # Like a course reference number unique to the sending institution
        "id":           indicator.get("id") or indicator.get("ioc_id") or indicator.get("threat_id"),

        # TYPE: what kind of threat indicator is this? (ip, domain, hash, url)
        # VendorA uses "type", VendorB uses "indicator_type", VendorC uses "category"
        "type":         indicator.get("type") or indicator.get("indicator_type") or indicator.get("category"),

        # VALUE: the actual threat data -- the IP address, domain name, or file hash
        # VendorA uses "value", VendorB uses "indicator_value", VendorC uses "ioc"
        "value":        indicator.get("value") or indicator.get("indicator_value") or indicator.get("ioc"),

        # CONFIDENCE: how certain is the vendor? (0-100, like a course completion percentage)
        # VendorA uses "confidence", VendorB uses "score", VendorC uses "reliability"
        "confidence":   indicator.get("confidence") or indicator.get("score") or indicator.get("reliability"),

        # THREAT LEVEL: how serious is this threat?
        # VendorA uses "threat", VendorB uses "severity", VendorC uses "risk"
        "threat_level": indicator.get("threat") or indicator.get("severity") or indicator.get("risk"),

        # FIRST SEEN: when was this threat first reported?
        # VendorA uses "first_seen", VendorB uses "discovered", VendorC uses "seen_at"
        "first_seen":   indicator.get("first_seen") or indicator.get("discovered") or indicator.get("seen_at"),

        # SOURCES: which vendor reported this threat?
        # Starts as a single-item list because it may grow later if the same
        # threat appears across multiple vendor feeds -- like a course that
        # appears on transcripts from more than one sending institution
        "sources":      [source_name]
    }


# ============================================================
# FUNCTION 3: VALIDATE INDICATORS
#
# This is the advisor checking that we have received all
# the transcripts for transfer evaluation that we were
# expecting. Before any evaluation begins, the advisor
# confirms every required document is present and complete.
#
# Missing transcripts, impossible grades, unsupported course
# types, or blank course names get flagged and set aside.
# Complete, valid records move forward to evaluation.
#
# This function returns THREE things at once:
#   1. The clean list of indicators that passed review
#   2. A count of how many problems were found
#   3. A list of messages describing each problem
# ============================================================
def validate_indicators(indicators):
    """
    Check each indicator for data quality issues.
    Returns (valid_indicators, error_count, error_messages).
    """
    valid = []
    error_count = 0
    error_messages = []

    # These are the only four indicator types our system accepts
    # Like a list of approved transfer credit subject areas
    valid_types = ["ip", "domain", "hash", "url"]

    for indicator in indicators:
        errors = []

        # CHECK 1: All four required fields must be present
        # Like confirming that every transcript includes
        # course name, credit hours, grade, and term
        for field in ["id", "type", "value", "confidence"]:
            if indicator.get(field) is None:
                errors.append(f"Missing required field: {field}")

        # CHECK 2: Confidence must be a number between 0 and 100
        # A score of 150 or -5 is impossible --
        # like a course grade that exceeds the maximum possible points
        confidence = indicator.get("confidence")
        if confidence is not None:
            if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 100):
                errors.append(f"Invalid confidence value: {confidence}")

        # CHECK 3: Type must be one of our four accepted values
        # Like checking that a transfer course falls within
        # an approved subject area -- unknown categories are flagged
        ioc_type = indicator.get("type")
        if ioc_type is not None and ioc_type not in valid_types:
            errors.append(f"Invalid type: {ioc_type}")

        # CHECK 4: Value must not be empty or blank
        # Like a transcript that lists a course row but leaves
        # the course name blank -- there is nothing to evaluate
        value = indicator.get("value")
        if value is not None and str(value).strip() == "":
            errors.append("Empty value field")

        # Sort into valid or invalid based on whether any errors were found
        if errors:
            # This indicator failed at least one check
            # Record what went wrong but do not add it to the valid list
            error_count += len(errors)
            for msg in errors:
                error_messages.append(f"{indicator.get('id', 'UNKNOWN')}: {msg}")
        else:
            # This indicator passed all checks -- add it to the clean list
            valid.append(indicator)

    return valid, error_count, error_messages


# ============================================================
# FUNCTION 4: DEDUPLICATE INDICATORS
#
# This removes indicators that appear more than once --
# the same threat reported by multiple vendor sources.
#
# Think of it like a student record that accidentally lists
# the same course twice. We use only one of the records --
# the one with the higher confidence score -- and note that
# the course appeared in more than one place.
#
# The clever part: we use a Python dictionary where the KEY
# is a combination of type + value (like course prefix + number).
# Dictionaries cannot have duplicate keys, so the moment
# we try to add a second ("ip", "203.0.113.10") entry,
# Python automatically tells us it already exists --
# no complicated comparison loops needed.
# ============================================================
def deduplicate_indicators(indicators):
    """
    Remove duplicate indicators across feeds.
    Keeps highest confidence version and merges sources lists.
    Returns (unique_indicators, duplicate_count).
    """
    # seen is our lookup dictionary
    # key = (type, value) tuple   value = the indicator dictionary
    seen = {}
    duplicate_count = 0

    for indicator in indicators:
        # Build the deduplication key from type + value combined
        # Example: ("ip", "203.0.113.10")
        # Using BOTH type AND value means the same IP address reported
        # as two different types would NOT be treated as a duplicate
        key = (indicator["type"], indicator["value"])

        if key not in seen:
            # First time we have seen this indicator -- add it
            seen[key] = indicator
        else:
            # Already exists in our dictionary -- this is a duplicate
            duplicate_count += 1
            existing = seen[key]

            # Keep whichever version has higher confidence
            # Like keeping the more complete course record and noting
            # that it appeared more than once in the student file
            if indicator["confidence"] > existing["confidence"]:
                # New one has higher confidence -- it becomes the keeper
                # But carry over the merged sources list so we do not
                # lose the history of where each record came from
                indicator["sources"] = list(set(existing["sources"] + indicator["sources"]))
                seen[key] = indicator
            else:
                # Existing one has higher or equal confidence -- it stays
                # Just add the new source to its sources list
                existing["sources"] = list(set(existing["sources"] + indicator["sources"]))

    unique_indicators = list(seen.values())
    return unique_indicators, duplicate_count


# ============================================================
# FUNCTION 5: FILTER INDICATORS
#
# This applies our three minimum standards to decide which
# indicators are worth acting on.
#
# Think of it like our transfer credit acceptance policy.
# Before any course gets evaluated for transfer credit,
# it must meet three minimum standards:
#   - The student must have earned a C or better in the course
#     (like our minimum confidence threshold of 85)
#   - The course must be from a regionally accredited institution
#     (like our requirement for high or critical threat level only)
#   - The course must map to an approved subject area at ATCC
#     (like our requirement for ip or domain type only)
#
# A course that fails any one of those three standards does
# not get evaluated further -- it gets counted and noted
# but removed from the process entirely.
#
# The three standards are set at the top of the script --
# update them there and every filter adjusts automatically.
# ============================================================
def filter_indicators(indicators, min_conf=MIN_CONFIDENCE,
                      levels=ALLOWED_THREAT_LEVELS,
                      types=ALLOWED_TYPES):
    """
    Filter indicators by confidence, threat level, and type.
    Returns (filtered_indicators, filtered_count).
    """
    filtered = []
    filtered_count = 0

    for indicator in indicators:
        confidence   = indicator.get("confidence", 0)
        threat_level = indicator.get("threat_level", "")
        ioc_type     = indicator.get("type", "")

        # Must meet all three standards to be kept
        # The backslash \ means the condition continues on the next line
        if confidence >= min_conf and \
           threat_level in levels and \
           ioc_type in types:
            filtered.append(indicator)
        else:
            # Did not meet at least one standard -- count it but do not keep it
            filtered_count += 1

    return filtered, filtered_count


# ============================================================
# FUNCTION 6: TRANSFORM TO FIREWALL
#
# This is the DENORMALIZATION step for the firewall --
# the second half of our normalize/denormalize process.
#
# Think of it like submitting a Transferology report that
# shows the original course prefix and number from the
# sending institution alongside ATCC's equivalent prefix
# and number. The underlying evaluation data is the same --
# we are just presenting it in the format Transferology
# requires, using their specific field structure.
#
# Firewalls only need: what to block, urgency level, and why.
# They do not need internal IDs, dates, or confidence numbers.
# ============================================================
def transform_to_firewall(indicators):
    """
    Reshape our normalized indicators into firewall blocklist format.
    Returns a dictionary ready to be written as JSON.
    """
    blocklist = []

    for indicator in indicators:
        entry = {
            # Firewalls call the threat value an "address" not "value"
            "address":  indicator["value"],

            # Every entry in a blocklist is always "block" -- never changes
            # The entire purpose of this output is to tell the firewall what to block
            "action":   "block",

            # Priority comes from threat_level (not confidence)
            # critical = highest urgency,  high = second highest
            "priority": indicator["threat_level"],

            # Reason combines threat_level AND confidence into one readable sentence
            # An f-string inserts the actual values at runtime
            # Example: "Threat level: critical, Confidence: 95%"
            "reason":   f"Threat level: {indicator['threat_level']}, Confidence: {indicator['confidence']}%",

            # Sources stays the same -- all vendors who flagged this threat
            "sources":  indicator["sources"]
        }
        blocklist.append(entry)

    # Wrap the blocklist in a container with a timestamp and total entry count
    firewall_output = {
        "generated_at":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_entries": len(blocklist),
        "blocklist":     blocklist
    }

    return firewall_output


# ============================================================
# FUNCTION 7: TRANSFORM TO SIEM
#
# This is the DENORMALIZATION step for the SIEM tool.
#
# Same idea as the Transferology report, but for a different
# college or university that uses their own course prefixes
# and numbers. The evaluation data is identical -- we are
# just presenting it in the format that institution requires,
# using their specific field names and structure.
#
# The SIEM needs richer detail than the firewall because it
# correlates data across many sources. More context means
# better matches.
#
# Two important format changes happen here:
#   1. Type names get more specific: "ip" becomes "ipv4"
#   2. Dates get a time appended: "2024-11-15" becomes
#      "2024-11-15T00:00:00Z" (full ISO timestamp)
# ============================================================
def transform_to_siem(indicators):
    """
    Reshape our normalized indicators into SIEM feed format.
    Returns a dictionary ready to be written as JSON.
    """
    # SIEM tools use more specific type names than our internal format
    # A dictionary lookup is cleaner than a chain of if/elif statements
    type_map = {
        "ip":     "ipv4",   # ip becomes ipv4 (more specific)
        "domain": "domain", # domain stays domain
        "hash":   "md5",    # hash becomes md5 (more specific)
        "url":    "url"     # url stays url
    }

    siem_indicators = []

    for indicator in indicators:
        # SIEM wants a full timestamp, not just a date
        # Our normalized format has "2024-11-15" (10 characters)
        # SIEM needs "2024-11-15T00:00:00Z" -- we add the time portion
        # Like adding a specific meeting time to a calendar date
        first_seen = indicator.get("first_seen", "")
        if len(first_seen) == 10:  # YYYY-MM-DD is exactly 10 characters
            first_seen = first_seen + "T00:00:00Z"

        entry = {
            # SIEM calls the threat value an "indicator" not "value"
            "indicator":  indicator["value"],

            # Look up the SIEM-specific type name in our type_map dictionary
            # The second argument is a fallback -- if the type is not in the map,
            # use whatever value is already there rather than failing
            "type":       type_map.get(indicator["type"], indicator["type"]),

            # Confidence stays as a number -- SIEM uses it for correlation scoring
            "confidence": indicator["confidence"],

            # SIEM calls it "severity" not "threat_level"
            "severity":   indicator["threat_level"],

            # Sources stays the same
            "sources":    indicator["sources"],

            # Full ISO timestamp
            "first_seen": first_seen
        }
        siem_indicators.append(entry)

    # Wrap indicators in a container with version and timestamp metadata
    siem_output = {
        "feed_version": "1.0",
        "timestamp":    datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "indicators":   siem_indicators
    }

    return siem_output


# ============================================================
# FUNCTION 8: GENERATE STATISTICS
#
# This creates a report that the student can easily read
# to understand how their previous coursework counts and
# applies toward graduation at ATCC.
#
# No technical field names, no raw data structures --
# just clear numbers and plain language organized so
# anyone can understand what was accepted, what was not,
# and why.
#
# collections.Counter works like a course tally --
# hand it a list of course types and it automatically
# counts how many fall into each category.
# No manual counting needed.
# ============================================================
def generate_statistics(stats_data, filtered_indicators):
    """
    Calculate statistics and generate a plain text summary report.
    Returns the report as a string.
    """
    # Count how many indicators are IPs vs domains
    # Counter works like a course category tally --
    # hand it a list, it counts each unique value automatically
    type_counts = Counter(i["type"] for i in filtered_indicators)

    # Count how many are critical vs high threat level
    severity_counts = Counter(i["threat_level"] for i in filtered_indicators)

    # Count how many indicators each vendor contributed
    # One indicator can count for multiple vendors if sources were
    # merged during deduplication -- so we loop through each
    # indicator's full sources list, not just the first source
    source_counts = Counter()
    for indicator in filtered_indicators:
        for source in indicator["sources"]:
            source_counts[source] += 1

    # Build the full report as one big text block using an f-string
    # The {stats_data['key']} placeholders fill in with real numbers at runtime
    # Like a degree audit template where the credit counts
    # populate automatically from the student record system
    report = f"""
================================================================
         THREAT INTELLIGENCE AGGREGATION REPORT
================================================================
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

INPUT SUMMARY
----------------------------------------------------------------
Feeds processed:           {stats_data['feeds_processed']}
Total indicators loaded:   {stats_data['total_loaded']}
Valid indicators:          {stats_data['valid_count']}
Validation errors:         {stats_data['error_count']}

DEDUPLICATION
----------------------------------------------------------------
Unique indicators:         {stats_data['unique_count']}
Duplicates removed:        {stats_data['duplicate_count']}

FILTERING
----------------------------------------------------------------
Confidence threshold:      >= {MIN_CONFIDENCE}
Threat levels:             {', '.join(ALLOWED_THREAT_LEVELS)}
Indicator types:           {', '.join(ALLOWED_TYPES)}
Indicators passing:        {stats_data['passing_count']}
Filtered out:              {stats_data['filtered_count']}

OUTPUT GENERATED
----------------------------------------------------------------
✓ firewall_blocklist.json  ({stats_data['passing_count']} entries)
✓ siem_feed.json           ({stats_data['passing_count']} indicators)

DISTRIBUTION BY TYPE
----------------------------------------------------------------
IP Addresses:              {type_counts.get('ip', 0)}
Domains:                   {type_counts.get('domain', 0)}

DISTRIBUTION BY SEVERITY
----------------------------------------------------------------
Critical:                  {severity_counts.get('critical', 0)}
High:                      {severity_counts.get('high', 0)}

TOP SOURCES (by unique indicators contributed)
----------------------------------------------------------------"""

    # Add each vendor ranked by how many indicators they contributed
    # most_common() sorts highest to lowest automatically --
    # like a ranked list of transfer institutions by credits accepted,
    # already sorted, no extra sorting code needed
    # enumerate(..., 1) adds a rank number starting at 1
    for rank, (source, count) in enumerate(source_counts.most_common(), 1):
        report += f"\n{rank}. {source}:              {count} indicators"

    # Close the report with the bottom border
    report += "\n\n================================================================"

    return report


# ============================================================
# FUNCTION 9: WRITE OUTPUTS
#
# This writes the report three different ways to meet what
# each particular office needs:
#   - The financial aid office needs specific information
#     to determine aid eligibility based on credit load
#   - The registrar's office needs the official course
#     equivalencies to update the student's academic record
#   - The dean needs a summary to determine which courses
#     still need to be added to the schedule
#
# JSON files use json.dump() which automatically converts
# our Python data into properly formatted JSON text.
# The text report uses f.write() since it is already a string.
#
# indent=2 makes the JSON files readable by humans --
# without it everything would be compressed onto one long line.
# ============================================================
def write_outputs(firewall_data, siem_data, report_text):
    """
    Save all three output files to disk.
    JSON files use json.dump(), the text report uses f.write().
    """
    # Save the firewall blocklist as formatted JSON
    # indent=2 adds indentation so a human can read the file if needed
    with open("firewall_blocklist.json", "w") as f:
        json.dump(firewall_data, f, indent=2)
    print("✓ firewall_blocklist.json written")

    # Save the SIEM feed as formatted JSON
    with open("siem_feed.json", "w") as f:
        json.dump(siem_data, f, indent=2)
    print("✓ siem_feed.json written")

    # Save the plain text summary report
    # f.write() just writes the string directly -- no conversion needed
    with open("summary_report.txt", "w") as f:
        f.write(report_text)
    print("✓ summary_report.txt written")


# ============================================================
# FUNCTION 10: MAIN -- THE ORCHESTRATOR
#
# This directs the onboarding plan we use for every new
# student who transfers to ATCC. It does not do the
# detailed work itself -- it calls the right specialist
# at the right time and passes results from one step
# to the next, just like a student onboarding workflow
# moves a new transfer student through each office
# in the correct sequence:
#
#   Step 1: Registrar receives transcripts from all institutions
#   Step 2: Advisor checks that all documents are complete
#   Step 3: Remove any duplicate course records
#   Step 4: Apply transfer credit acceptance standards
#   Step 5: Compile the summary numbers for reporting
#   Step 6: Format outputs for each office's needs
#   Step 7: Publish all three formatted outputs
#   Step 8: Print the summary to the console
#
# This is the ETL pattern in action:
#   Extract   = Step 1  (load the raw data)
#   Transform = Steps 2 through 6  (clean, process, reshape)
#   Load      = Step 7  (write finished outputs to disk)
# ============================================================
def main():
    """
    Orchestrate the full threat intelligence processing pipeline.
    Load → Normalize → Validate → Deduplicate → Filter → Transform → Output
    """
    print("Starting Threat Intelligence Aggregator...")
    print("=" * 64)

    # --------------------------------------------------------
    # STEP 1: LOAD AND NORMALIZE
    # Registrar receives transcripts from each institution
    # and the transfer evaluator maps every course to its
    # ATCC equivalent -- like accepting ENGL 101 as ENGL 1410.
    # --------------------------------------------------------
    all_indicators = []

    # Load VendorA -- their indicators list is stored under the key "indicators"
    feed_a = load_feed("vendor_a.json")
    if feed_a:
        for item in feed_a["indicators"]:
            all_indicators.append(normalize_indicator(item, "VendorA"))
        print(f"Loaded {len(feed_a['indicators'])} indicators from VendorA")

    # Load VendorB -- their indicators list is stored under the key "data"
    feed_b = load_feed("vendor_b.json")
    if feed_b:
        for item in feed_b["data"]:
            all_indicators.append(normalize_indicator(item, "VendorB"))
        print(f"Loaded {len(feed_b['data'])} indicators from VendorB")

    # Load VendorC -- their indicators list is stored under the key "threats"
    feed_c = load_feed("vendor_c.json")
    if feed_c:
        for item in feed_c["threats"]:
            all_indicators.append(normalize_indicator(item, "VendorC"))
        print(f"Loaded {len(feed_c['threats'])} indicators from VendorC")

    total_loaded = len(all_indicators)
    print(f"\nTotal indicators loaded: {total_loaded}")

    # --------------------------------------------------------
    # STEP 2: VALIDATE
    # Advisor checks that all expected transcripts and
    # documents have been received and are complete.
    # Incomplete or invalid records are flagged here
    # and go no further in the process.
    # --------------------------------------------------------
    valid_indicators, error_count, error_messages = validate_indicators(all_indicators)

    # Print any validation errors so we can see exactly what was flagged and why
    if error_messages:
        print(f"\nValidation errors found:")
        for msg in error_messages:
            print(f"  ✗ {msg}")

    print(f"\nValid indicators after validation: {len(valid_indicators)}")

    # --------------------------------------------------------
    # STEP 3: DEDUPLICATE
    # Remove any course records that appear more than once.
    # Keep the highest confidence version and note all
    # sources where the duplicate appeared.
    # --------------------------------------------------------
    unique_indicators, duplicate_count = deduplicate_indicators(valid_indicators)

    print(f"Duplicates removed: {duplicate_count}")
    print(f"Unique indicators after deduplication: {len(unique_indicators)}")

    # --------------------------------------------------------
    # STEP 4: FILTER
    # Apply our three transfer credit acceptance standards.
    # Only indicators that meet all three standards advance.
    # --------------------------------------------------------
    filtered_indicators, filtered_count = filter_indicators(unique_indicators)

    print(f"Indicators passing filter: {len(filtered_indicators)}")
    print(f"Indicators filtered out: {filtered_count}")

    # --------------------------------------------------------
    # STEP 5: BUILD STATS DICTIONARY
    # Collect all the numbers gathered during processing.
    # This populates the summary report -- like pulling
    # credit totals into a degree audit before sending
    # it to the student.
    # --------------------------------------------------------
    stats_data = {
        "feeds_processed":  3,
        "total_loaded":     total_loaded,
        "valid_count":      len(valid_indicators),
        "error_count":      error_count,
        "unique_count":     len(unique_indicators),
        "duplicate_count":  duplicate_count,
        "passing_count":    len(filtered_indicators),
        "filtered_count":   filtered_count
    }

    # --------------------------------------------------------
    # STEP 6: TRANSFORM (DENORMALIZE)
    # Format the data for each office's specific needs.
    # This is the reverse of normalization --
    # we translated INTO our standard format at the start,
    # now we translate OUT to each consumer's required format.
    # Same data, three different presentations.
    # --------------------------------------------------------
    firewall_data = transform_to_firewall(filtered_indicators)
    siem_data     = transform_to_siem(filtered_indicators)
    report_text   = generate_statistics(stats_data, filtered_indicators)

    # --------------------------------------------------------
    # STEP 7: WRITE OUTPUTS
    # Publish all three formatted outputs to disk --
    # one for each office that needs the information.
    # --------------------------------------------------------
    write_outputs(firewall_data, siem_data, report_text)

    # --------------------------------------------------------
    # STEP 8: PRINT SUMMARY TO CONSOLE
    # Display the report in the terminal as well as saving it.
    # --------------------------------------------------------
    print("\n" + report_text)
    print("\nAll output files generated successfully!")
    print("=" * 64)


# ============================================================
# ENTRY POINT
# This line means: only run main() if this script is being
# executed directly from the terminal.
# If another script imports this file as a module,
# main() will NOT run automatically.
# It is a standard Python convention included in every
# professional script.
# ============================================================
if __name__ == "__main__":
    main()