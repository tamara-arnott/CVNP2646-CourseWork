Markdown# Network Traffic Monitor
### Week 12 — CVNP2646 Cybersecurity Programming
**A refactored network traffic analyzer that detects port scans and SYN flood attacks.**

---

## What This Does
This tool reads a network traffic log file, analyzes it for suspicious patterns, 
and writes a results file. It detects two types of attacks:
- **Port scans** — when one IP address contacts too many different ports
- **SYN floods** — when one IP address sends too many connection requests

---

## How to Run It
```bash
# Basic usage
python3 network_monitor.py traffic_sample.log

# Save results to a specific file
python3 network_monitor.py traffic_sample.log --output results.json

# See all available options
python3 network_monitor.py --help

# Run the tests
pytest test_network_monitor.py -v
```

---

## Project Files
week12/
├── network_monitor.py          # The refactored program
├── test_network_monitor.py     # 25 automated tests
├── traffic_sample.log          # Sample data used for testing
├── network_monitor.log         # Log file generated when program runs
├── results.json                # Results file generated when program runs
└── README.md                   # This file

---

## How the Program Is Organized

When you run the program, here is what happens in order:
CLI (main)
→ validate_args()             # Checks that arguments make sense
→ setup_logging()             # Sets up the log file and console output
→ load_traffic_log()          # Reads the traffic file (file handling only)
→ parse_packet_line()         # Reads one line at a time
→ _validate_ip()              # Checks that IP addresses are valid
→ analyze_traffic()           # Looks for suspicious patterns (no file access)
→ detect_port_scan()          # Checks for port scanning behavior
→ detect_syn_flood()          # Checks for SYN flood behavior
→ is_syn_packet()             # Identifies SYN packets
→ results.json                # Saves the output

The key design principle here is that file reading and analysis are kept completely 
separate. This makes each piece easier to test independently.

---

## Log Messages Reference

The lecture noted that good security tools should document every log 
message they can produce. Here is every message this program generates, what level 
it is, and what it means:

| Level | Message | What It Means |
|---|---|---|
| INFO | Network Monitor v1.0.0 starting | Program started successfully |
| INFO | Input file: {path} | The file being analyzed |
| INFO | Output file: {path} | Where results will be saved |
| INFO | Loading traffic log: {path} | About to read the file |
| INFO | Loaded {n} lines from file | File was read successfully |
| INFO | Parsed {n} packets, {n} errors | How many lines were usable |
| INFO | Starting traffic analysis on {n} packets | Analysis is starting |
| INFO | Found {n} unique source IPs | How many distinct sources were found |
| INFO | Checking for port scans (threshold: {n}) | Port scan check starting |
| INFO | Checking for SYN floods (threshold: {n}) | SYN flood check starting |
| INFO | Analysis complete: {n} port scans, {n} SYN floods | Analysis finished |
| INFO | Results written to {path} | Output file was saved |
| DEBUG | Parsed packet {n}: {ip} -> {ip}:{port} | Detail on each packet parsed |
| DEBUG | {ip} targeted {n} unique ports | Per-IP port count |
| DEBUG | {ip} sent {n} SYN packets | Per-IP SYN count |
| WARNING | PORT SCAN DETECTED: {ip} scanned {n} ports | Security alert |
| WARNING | SYN FLOOD DETECTED: {ip} sent {n} SYN packets | Security alert |
| ERROR | Parse error at line {n}: {reason} | A line in the file was malformed |
| ERROR | Log file not found: {path} | The input file does not exist |
| ERROR | Permission denied reading file: {path} | File exists but cannot be read |

---

## What Was Wrong with the Original Code

The script you provided to refactor had eight problems:

1. **Global variables** — five variables floating loose at the top of the file, 
   making testing nearly impossible
2. **Magic numbers** — thresholds of 25 and 100 appeared in the code with no 
   explanation of what they meant or why those numbers were chosen
3. **One giant function** — parsing, analysis, alerting, and file reading were all 
   tangled together in one 150-line function
4. **No error handling** — a bare `except:` caught everything silently; file opens 
   had no protection at all
5. **Print statement noise** — 10 print() statements with no timestamps, no severity 
   levels, and no way to filter them
6. **Inefficient code** — lists were used where sets should have been, causing the 
   program to do far more work than necessary
7. **No main guard** — importing the script caused it to run immediately, which 
   broke testing entirely
8. **No input validation** — IP addresses and port numbers were accepted without 
   any checking

---

## How I Fixed It

As suggested, we (Claudeai and I) made one change, 
verifed that it worked and then moved to the next thing.

| Phase | What Changed |
|---|---|
| Phase 2 | Created `NetworkConfig` class to replace all magic numbers |
| Phase 3a | Extracted `parse_packet_line()` as a pure, testable function |
| Phase 3b | Extracted `is_syn_packet()` as a pure function |
| Phase 3c | Extracted `detect_port_scan()` and `detect_syn_flood()` as pure functions |
| Phase 3d | Separated file reading (`load_traffic_log`) from analysis (`analyze_traffic`) |
| Phase 4 | Replaced all print() statements with structured logging |
| Phase 5 | Wrote 25 pytest tests covering normal use, edge cases, and errors |
| Phase 6 | Built a professional CLI using argparse with validation and exit codes |

### Three Improvements Beyond the Requirements

During the work I asked Claude to identify improvements that would strengthen the 
tool beyond the minimum requirements. Three were added:

1. **File error handling** — `load_traffic_log()` now catches specific errors 
   (file not found, permission denied) and logs them before raising them
2. **IP address validation** — added `_validate_ip()` using Python's built-in 
   `ipaddress` module, which handles both IPv4 and IPv6 properly
3. **Port range validation** — ports are now checked to be within the valid 
   range of 0–65535, not just any integer

---

## What This Would Look Like in the Real World

I asked Claude how these improvements would change if this were a real production 
tool at a health system. The answer included many suggestions which demonstrated that the AI could do more, if only I knew more about what the tool was actually supposed to do as a cybersecurity professional (which I am not)!! Some included:

| Concern | This Assignment | Real Production Tool |
|---|---|---|
| IP validation | Nice improvement | Required by compliance |
| Logging | Good practice | Legal and forensic record |
| Performance | Not tested | Critical — millions of packets per hour |
| Output file | Just a file | Security artifact, may need signing |
| Error handling | Prevents crashes | Safety requirement — blind spots = missed attacks |
| Test coverage | 25 tests | Hundreds of tests plus fuzz testing |
| IPv6 support | Not needed | Required |
| SIEM integration | Not needed | Expected |

A security tool that crashes silently or accepts garbage input doesn't just fail 
the programmer — it fails the organization relying on it.

---

## Testing

```bash
# Run all tests with detail
pytest test_network_monitor.py -v

# Run with coverage report
pytest test_network_monitor.py --cov=network_monitor
```

### What Is Tested

| Function | Number of Tests | What Is Covered |
|---|---|---|
| `parse_packet_line()` | 8 | Valid input, too few fields, too many fields, bad src_port, bad dst_port, port as integer, uppercase protocol, empty flags |
| `is_syn_packet()` | 4 | TCP SYN, TCP ACK, UDP, empty flags |
| `detect_port_scan()` | 5 | Above threshold, below threshold, exactly at threshold, duplicate ports, multiple IPs |
| `detect_syn_flood()` | 4 | Above threshold, below threshold, exactly at threshold, non-SYN packets |
| `analyze_traffic()` | 4 | Empty input, port scan detected, SYN flood detected, clean traffic |

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | User error — bad file path or invalid argument |
| 2 | Unexpected program error |
| 130 | User pressed Ctrl+C |

---

## AI-Assisted Development

### Tool Used
Claude (claude.ai)

### How I Used It
I did not ask Claude to fix everything at once. Instead I shared the course 
assignment and worked through each part incrementally — implementing one piece, 
testing it, committing it to GitHub, and then moving to the next. 

### About the Testing Framework Choice
The lecture discussed the two options for writing tests 
in Python — pytest (a third-party module that must be installed) and unittest 
(built into Python). When I asked Claude to generate tests, I specified pytest 
rather than leaving it to default, because the assignment recommended it. Claude noted that 
its simpler function-based style would be easier to read and maintain  
than the class-based unittest approach.

### Questions I Asked That Went Beyond the Code
Rather than only asking for working code, I pushed further:

- *"Can you identify 3 improvements that support greater functionality or integrity?"*
- *"Can you identify additional edge cases we would be smart to include?"*
- *"If this was a real-world work assignment, would it change your recommendations? How?"*

### What Claude Got Right
- Correctly identified all eight problems in the original code
- Generated pure functions that passed tests immediately
- Set up logging with dual handlers correctly on the first attempt
- Generated 25 tests that all passed without modification

### What Required My Judgment
- Recognizing from a previous graded assignment that missing try/except creates opportunity for risk/failure
- Noticing that `analyze_traffic()` was not returning `total_packets` as the rubric required
- Choosing Python's `ipaddress` module over manual string splitting for IP validation
- Recovering from a file corruption incident using git to restore the previous version
- Catching that the test file had been accidentally left empty after a paste error

### What I Learned
Working through this assignment taught me that using AI well is not simply a tool to get the 
answers — it is about asking better questions. The most valuable parts of this 
project came from pushing past the first working version and asking what could 
still go wrong, what a real-world version would need, and what edge cases I should become aware of. 

I also learned that incremental commits are not just good practice — they are 
a safety net. When files got corrupted during this project, git allowed me to 
recover the working version without losing everything.

