# network_monitor.py
# week 12 - network traffic monitor (refactoring in progress)

import sys
import json


# ---------------------------------------------------------------------------
# Phase 2: Configuration class
# ---------------------------------------------------------------------------

class NetworkConfig:
    """Configuration for network traffic analysis.
    
    Centralizes all thresholds and defaults so magic numbers
    never appear scattered through the code.
    """

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
# Phase 3a: Pure function - parse a single packet line
# ---------------------------------------------------------------------------

def parse_packet_line(line: str) -> dict:
    """Parse a single CSV packet line into a dictionary.
    
    Pure function - no side effects, no globals, easy to test.
    
    Args:
        line: CSV string with format src_ip,dst_ip,src_port,dst_port,protocol,flags
        
    Returns:
        Dictionary with keys: src_ip, dst_ip, src_port, dst_port, protocol, flags
        
    Raises:
        ValueError: If line does not have exactly 6 fields
        ValueError: If src_port or dst_port are not valid integers
    """
    parts = line.strip().split(",")
    
    if len(parts) != 6:
        raise ValueError(f"Expected 6 fields, got {len(parts)}: '{line.strip()}'")
    
    src_ip = parts[0].strip()
    dst_ip = parts[1].strip()
    protocol = parts[4].strip().upper()
    flags = parts[5].strip()
    
    try:
        src_port = int(parts[2].strip())
    except ValueError:
        raise ValueError(f"Invalid src_port '{parts[2].strip()}' - must be an integer")
    
    try:
        dst_port = int(parts[3].strip())
    except ValueError:
        raise ValueError(f"Invalid dst_port '{parts[3].strip()}' - must be an integer")
    
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "flags": flags
    }


# ---------------------------------------------------------------------------
# Phase 3b: Pure function - check if a packet is a TCP SYN packet
# ---------------------------------------------------------------------------

def is_syn_packet(packet: dict) -> bool:
    """Check if a packet is a TCP SYN packet.
    
    Pure function - takes a packet dictionary, returns True or False.
    No side effects, no globals, easy to test.
    
    Args:
        packet: Dictionary with keys protocol and flags
        
    Returns:
        True if packet is TCP with SYN flag, False otherwise
    """
    return packet["protocol"] == "TCP" and "SYN" in packet["flags"]


# ---------------------------------------------------------------------------
# Phase 3c: Pure functions - detect port scan and SYN flood
# ---------------------------------------------------------------------------

def detect_port_scan(packets: list, src_ip: str, threshold: int) -> bool:
    """Detect if a source IP is performing a port scan.
    
    Pure function - takes data, returns True or False.
    No side effects, no globals, easy to test.
    
    A port scan is detected when a single source IP contacts
    more unique destination ports than the threshold allows.
    
    Args:
        packets: List of all parsed packet dictionaries
        src_ip: Source IP address to check
        threshold: Number of unique destination ports that triggers detection
        
    Returns:
        True if port scan detected, False otherwise
    """
    unique_ports = {
        p["dst_port"] for p in packets
        if p["src_ip"] == src_ip
    }
    return len(unique_ports) > threshold


def detect_syn_flood(packets: list, src_ip: str, threshold: int) -> bool:
    """Detect if a source IP is performing a SYN flood attack.
    
    Pure function - takes data, returns True or False.
    No side effects, no globals, easy to test.
    
    A SYN flood is detected when a single source IP sends
    more TCP SYN packets than the threshold allows.
    
    Args:
        packets: List of all parsed packet dictionaries
        src_ip: Source IP address to check
        threshold: Number of SYN packets that triggers detection
        
    Returns:
        True if SYN flood detected, False otherwise
    """
    syn_count = sum(
        1 for p in packets
        if p["src_ip"] == src_ip and is_syn_packet(p)
    )
    return syn_count > threshold


# ---------------------------------------------------------------------------
# Phase 3d: Separate I/O from logic
# ---------------------------------------------------------------------------

def load_traffic_log(filepath: str) -> tuple:
    """Load and parse packets from a traffic log file.
    
    I/O function - handles all file reading and line parsing.
    Returns parsed packets and error count separately.
    
    Args:
        filepath: Path to the CSV traffic log file
        
    Returns:
        Tuple of (packets list, error count)
        
    Raises:
        FileNotFoundError: If the log file does not exist
    """
    packets = []
    errors = 0

    with open(filepath, 'r') as f:
        lines = f.readlines()

    print(f"loaded {len(lines)} lines")

    for i, line in enumerate(lines):
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        try:
            packet = parse_packet_line(line)
            packets.append(packet)
            print(f"parsed packet {i}: {packet['src_ip']} -> {packet['dst_ip']}:{packet['dst_port']}")
        except ValueError as e:
            errors += 1
            print(f"ERROR: could not parse line {i}: {e}")

    return packets, errors


def analyze_traffic(packets: list, config: NetworkConfig) -> dict:
    """Analyze parsed packets for suspicious patterns.
    
    Pure logic function - no file I/O, no side effects.
    Takes data, returns results. Easy to test with fake data.
    
    Args:
        packets: List of parsed packet dictionaries
        config: NetworkConfig with detection thresholds
        
    Returns:
        Dictionary with keys: total_packets, parse_errors,
        port_scans, syn_floods, summary
    """
    src_ips = list({p["src_ip"] for p in packets})

    port_scans = []
    syn_floods = []

    print("checking for port scans...")
    for ip in src_ips:
        unique_ports = {p["dst_port"] for p in packets if p["src_ip"] == ip}
        print(f"  {ip} targeted {len(unique_ports)} unique ports")

        if detect_port_scan(packets, ip, config.port_scan_threshold):
            print(f"WARNING: PORT SCAN DETECTED from {ip} ({len(unique_ports)} ports)")
            port_scans.append({
                "src_ip": ip,
                "unique_ports": len(unique_ports),
                "ports": list(unique_ports)
            })

    print("checking for SYN floods...")
    for ip in src_ips:
        syn_count = sum(1 for p in packets if p["src_ip"] == ip and is_syn_packet(p))
        print(f"  {ip} sent {syn_count} SYN packets")

        if detect_syn_flood(packets, ip, config.syn_flood_threshold):
            print(f"WARNING: SYN FLOOD DETECTED from {ip} ({syn_count} SYN packets)")
            syn_floods.append({
                "src_ip": ip,
                "syn_count": syn_count
            })

    return {
        "port_scans": port_scans,
        "syn_floods": syn_floods
    }


# ---------------------------------------------------------------------------
# run_monitor - now just orchestrates: load -> analyze -> save
# No globals, no mixed concerns
# ---------------------------------------------------------------------------

def run_monitor():
    """Main orchestration function - glues I/O and logic together."""

    if len(sys.argv) < 2:
        print("Usage: python network_monitor.py <log_file>")
        print("Optional: python network_monitor.py <log_file> <output_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    config = NetworkConfig()
    output_file = config.output_file
    if len(sys.argv) >= 3:
        output_file = sys.argv[2]

    print("starting network monitor...")
    print(f"reading file: {log_file}")

    # Step 1: Load (I/O)
    packets, errors = load_traffic_log(log_file)
    print(f"parsed {len(packets)} packets, {errors} errors")
    print(f"found {len({p['src_ip'] for p in packets})} unique source IPs")

    # Step 2: Analyze (pure logic)
    results = analyze_traffic(packets, config)

    # Step 3: Save (I/O)
    output = {
        "total_packets": len(packets),
        "parse_errors": errors,
        "port_scans": results["port_scans"],
        "syn_floods": results["syn_floods"],
        "summary": f"Scanned {len(packets)} packets. Found {len(results['port_scans'])} port scans, {len(results['syn_floods'])} SYN floods."
    }

    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\nResults written to {output_file}")
    print(f"Port scans detected: {len(results['port_scans'])}")
    print(f"SYN floods detected: {len(results['syn_floods'])}")
    print("done!")


# no main guard yet - will fix in Phase 6
run_monitor()