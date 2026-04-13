# network_monitor.py
# week 12 - network traffic monitor (refactoring in progress)

import sys
import json


# ---------------------------------------------------------------------------
# Phase 2: Configuration class - replaces all magic numbers
# ---------------------------------------------------------------------------

class NetworkConfig:
    """Configuration for network traffic analysis.
    
    Centralizes all thresholds and defaults so magic numbers
    never appear scattered through the code.
    """

    # Class-level defaults - documented so meaning is clear
    DEFAULT_PORT_SCAN_THRESHOLD = 25   # unique destination ports before flagging as port scan
    DEFAULT_SYN_FLOOD_THRESHOLD = 100  # SYN packets from one IP before flagging as flood
    DEFAULT_LOG_FILE = "network_monitor.log"
    DEFAULT_OUTPUT_FILE = "results.json"

    def __init__(self, port_scan_threshold=None, syn_flood_threshold=None):
        """Allow runtime customization of thresholds.
        
        Args:
            port_scan_threshold: Override default port scan detection limit
            syn_flood_threshold: Override default SYN flood detection limit
        """
        self.port_scan_threshold = (
            port_scan_threshold if port_scan_threshold is not None
            else self.DEFAULT_PORT_SCAN_THRESHOLD
        )
        self.syn_flood_threshold = (
            syn_flood_threshold if syn_flood_threshold is not None
            else self.DEFAULT_SYN_FLOOD_THRESHOLD
        )
        self.log_file = self.DEFAULT_LOG_FILE
        self.output_file = self.DEFAULT_OUTPUT_FILE


# ---------------------------------------------------------------------------
# Original code below - will be refactored in later phases
# ---------------------------------------------------------------------------

# global variables (bad practice - will fix in Phase 3)
packets = []
scan_results = []
flood_results = []
total = 0
errors = 0

def run_monitor():
    global packets, scan_results, flood_results, total, errors

    # crude argument parsing (will fix in Phase 6)
    if len(sys.argv) < 2:
        print("Usage: python network_monitor.py <log_file>")
        print("Optional: python network_monitor.py <log_file> <output_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    config = NetworkConfig()  # use config instead of magic numbers
    output_file = config.output_file
    if len(sys.argv) >= 3:
        output_file = sys.argv[2]

    print("starting network monitor...")
    print(f"reading file: {log_file}")

    # read the file - no error handling (will fix in Phase 3)
    f = open(log_file, 'r')
    lines = f.readlines()
    f.close()

    print(f"loaded {len(lines)} lines")

    # parse every line
    for i, line in enumerate(lines):
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue

        parts = line.split(",")

        try:
            src_ip = parts[0]
            dst_ip = parts[1]
            src_port = int(parts[2])
            dst_port = int(parts[3])
            protocol = parts[4]
            flags = parts[5]

            packet = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "flags": flags
            }
            packets.append(packet)
            total += 1
            print(f"parsed packet {i}: {src_ip} -> {dst_ip}:{dst_port}")
        except:
            errors += 1
            print(f"ERROR: could not parse line {i}: {line}")

    print(f"parsed {total} packets, {errors} errors")

    src_ips = []
    for p in packets:
        if p["src_ip"] not in src_ips:
            src_ips.append(p["src_ip"])

    print(f"found {len(src_ips)} unique source IPs")
    print("checking for port scans...")

    for ip in src_ips:
        dst_ports = []
        for p in packets:
            if p["src_ip"] == ip:
                if p["dst_port"] not in dst_ports:
                    dst_ports.append(p["dst_port"])

        print(f"  {ip} targeted {len(dst_ports)} unique ports")

        if len(dst_ports) > config.port_scan_threshold:  # no more magic number
            print(f"WARNING: PORT SCAN DETECTED from {ip} ({len(dst_ports)} ports)")
            scan_results.append({
                "src_ip": ip,
                "unique_ports": len(dst_ports),
                "ports": dst_ports
            })

    print("checking for SYN floods...")

    for ip in src_ips:
        syn_count = 0
        for p in packets:
            if p["src_ip"] == ip:
                if p["protocol"] == "TCP" and "SYN" in p["flags"]:
                    syn_count += 1

        print(f"  {ip} sent {syn_count} SYN packets")

        if syn_count > config.syn_flood_threshold:  # no more magic number
            print(f"WARNING: SYN FLOOD DETECTED from {ip} ({syn_count} SYN packets)")
            flood_results.append({
                "src_ip": ip,
                "syn_count": syn_count
            })

    results = {
        "total_packets": total,
        "parse_errors": errors,
        "port_scans": scan_results,
        "syn_floods": flood_results,
        "summary": f"Scanned {total} packets. Found {len(scan_results)} port scans, {len(flood_results)} SYN floods."
    }

    f = open(output_file, 'w')
    json.dump(results, f, indent=2)
    f.close()

    print(f"\nResults written to {output_file}")
    print(f"Port scans detected: {len(scan_results)}")
    print(f"SYN floods detected: {len(flood_results)}")
    print("done!")

# just call the function directly - no main guard (will fix in Phase 6)
run_monitor()