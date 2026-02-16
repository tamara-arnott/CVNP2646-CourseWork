# Authentication Log Scanner

## What This Does

This is a Python tool that reads authentication log files and looks for
signs of brute force attacks. It parses each log line, counts failed
login attempts by username and IP address, and generates two reports:
one for automated security tools (JSON) and one for human analysts (text).

## How to Use It

Run from the command line with the log file as an argument:

```
python auth_scanner.py auth_test.log
```

The scanner will print a summary to the screen and create three files:

- `incident_report.json` - structured report for SIEM tools
- `incident_report.txt` - formatted report for human analysts
- `parse_errors.log` - details on any lines that couldn't be parsed

## Features

- Parses authentication logs with key=value format
- Identifies failed login attempts (potential attacks)
- Counts failures per username to find targeted accounts
- Counts failures per IP address to find attack sources
- Ranks the top 5 targeted users and top 5 attacking IPs
- Calculates failure rate and triggers alert if above 10%
- Assigns severity labels (CRITICAL, HIGH, MEDIUM) to findings
- Includes recommended actions for the SOC team
- Handles malformed log entries without crashing

## How It Works

Each log line has two parts: a timestamp (date + time) and then
key=value pairs like status=FAIL, user=admin, ip=198.51.100.45.

The parser splits each line on spaces, grabs the timestamp from the
first two pieces, then splits the remaining pieces on the = sign to
get the field names and values.

I used Counter instead of plain dictionaries because Counter doesn't
crash when it sees a new username for the first time, and it has
most_common() which automatically gives you the top 5 sorted by count.

## Error Handling

The scanner handles these edge cases without crashing:

- Empty lines (skipped)
- Lines missing a timestamp (logged and skipped)
- Key=value pairs missing the = sign (pair skipped, rest of line parsed)
- Empty status values like status= (logged and skipped)
- Lines with no date at all (logged and skipped)

I chose to both count the errors (for the summary reports) and save
the actual bad lines to parse_errors.log. This way the report shows
how many lines had problems, and an analyst can open the error log
to see exactly which lines failed. This matters because malformed
lines could be normal log corruption, or they could be evidence that
someone tampered with the logs after a breach.

## AI Tool Usage

I used Claude to help me understand the concepts and build the scanner
step by step. Specifically:

- Understanding what authentication logs are and how to read them
- Learning why the status field is the most important for detecting attacks
- Understanding how split() breaks strings apart and how key=value
  parsing works
- Learning the difference between Counter and plain dictionaries
- Understanding the three error handling strategies: try/except for
  crash prevention, validation for checking data quality, and tracking
  errors so analysts can investigate bad lines
- Understanding why JSON reports are for machines (SIEM integration)
  and text reports are for humans (incident response)

I can explain every part of the code because we worked through each
concept before writing it.

## Testing

Tested with two log files:

- `auth_test.log` (20 lines) - the provided test file with 4 SUCCESS
  events, multiple FAIL events, and several malformed lines
- `auth_extended.log` (37 lines) - a larger file with additional edge
  cases including blank lines, missing dates, and empty status values

Both ran without crashes and produced accurate reports.

## Challenges

The hardest part was understanding why error handling matters beyond
just preventing crashes. Through our discussion I learned that silently
skipping bad lines can hide evidence of tampering. A scanner that
reports problem lines gives the analyst a clue to investigate further.
That changed my approach from just using try/except to also saving
the bad lines to a separate error log.

## File Structure

```
week6/
├── auth_scanner.py           # Main scanner script
├── auth_test.log             # Test log file (20 lines)
├── auth_extended.log         # Extended test file (37 lines)
├── incident_report.json      # Generated JSON report
├── incident_report.txt       # Generated text report
├── parse_errors.log          # Error details for investigation
└── README.md                 # This file
```
