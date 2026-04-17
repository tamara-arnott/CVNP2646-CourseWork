# network_monitor.py
# week 12 - network traffic monitor (refactoring in progress)

import sys
import json
import logging
import argparse
import os
import ipaddress


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
# Phase 4: Professional logging setup
# ---------------------------------------------------------------------------

def setup_logging(log_file: str = "network_monitor.log",
                  log_level: str = "INFO") -> logging.Logger:
    """Configure logging with both file and console output.
    
    File handler: logs everything at DEBUG level and above (complete record).
    Console handler: logs at the configured level (less noisy).
    
    Args:
        log_file: Path to the log file
        log_level: Minimum level for console output (DEBUG/INFO/WARNING/ERROR)
        
    Returns:
        Configured logger instance
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    logger = logging.getLogger("network_monitor")
    logger.setLevel(logging.DEBUG)

    # Clear any existing handlers
    logger.handlers = []

    # File handler - captures everything
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)

    # Console handler - respects configured level
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# Module-level logger - used by all functions below
logger = logging.getLogger("network_monitor")


# ---------------------------------------------------------------------------
# Phase 3a: Pure function - parse a single packet line
# ---------------------------------------------------------------------------

def _validate_ip(ip: str) -> str:
    """Validate IP address format using Python's ipaddress module.
    
    Args:
        ip: IP address string to validate
        
    Returns:
        The validated IP address string
        
    Raises:
        ValueError: If the IP address format is invalid
    """
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValueError(f"Invalid IP address: '{ip}'")


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
        ValueError: If src_port or dst_port are out of valid range (0-65535)
        ValueError: If IP addresses are invalid format
    """
    parts = line.strip().split(",")

    if len(parts) != 6:
        raise ValueError(f"Expected 6 fields, got {len(parts)}: '{line.strip()}'")

    src_ip = _validate_ip(parts[0].strip())
    dst_ip = _validate_ip(parts[1].strip())
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

    if not 0 <= src_port <= 65535:
        raise ValueError(f"Invalid src_port {src_port} - must be between 0 and 65535")

    if not 0 <= dst_port <= 65535:
        raise ValueError(f"Invalid dst_port {dst_port} - must be between 0 and 65535")

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
# Phase 3d: Separated I/O and logic - with proper logging and error handling
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
        PermissionError: If the log file cannot be read
    """
    packets = []
    errors = 0

    logger.info("Loading traffic log: %s", filepath)

    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error("Log file not found: %s", filepath)
        raise FileNotFoundError(f"Log file not found: {filepath}")
    except PermissionError:
        logger.error("Permission denied reading file: %s", filepath)
        raise PermissionError(f"Cannot read file - permission denied: {filepath}")

    logger.info("Loaded %d lines from file", len(lines))

    for i, line in enumerate(lines):
        line = line.strip()
        if line == "" or line.startswith("#"):
            continue
        try:
            packet = parse_packet_line(line)
            packets.append(packet)
            logger.debug("Parsed packet %d: %s -> %s:%s",
                         i, packet['src_ip'], packet['dst_ip'], packet['dst_port'])
        except ValueError as e:
            errors += 1
            logger.error("Parse error at line %d: %s", i, str(e))

    logger.info("Parsed %d packets successfully, %d errors", len(packets), errors)
    return packets, errors


def analyze_traffic(packets: list, config: NetworkConfig) -> dict:
    """Analyze parsed packets for suspicious patterns.
    
    Pure logic function - no file I/O, no side effects.
    Takes data, returns results. Easy to test with fake data.
    
    Args:
        packets: List of parsed packet dictionaries
        config: NetworkConfig with detection thresholds
        
    Returns:
        Dictionary with keys: total_packets, port_scans, syn_floods
    """
    logger.info("Starting traffic analysis on %d packets", len(packets))

    src_ips = list({p["src_ip"] for p in packets})
    logger.info("Found %d unique source IPs", len(src_ips))

    port_scans = []
    syn_floods = []

    logger.info("Checking for port scans (threshold: %d ports)",
                config.port_scan_threshold)
    for ip in src_ips:
        unique_ports = {p["dst_port"] for p in packets if p["src_ip"] == ip}
        logger.debug("  %s targeted %d unique ports", ip, len(unique_ports))

        if detect_port_scan(packets, ip, config.port_scan_threshold):
            logger.warning("PORT SCAN DETECTED: %s scanned %d ports (threshold: %d)",
                           ip, len(unique_ports), config.port_scan_threshold)
            port_scans.append({
                "src_ip": ip,
                "unique_ports": len(unique_ports),
                "ports": list(unique_ports)
            })

    logger.info("Checking for SYN floods (threshold: %d packets)",
                config.syn_flood_threshold)
    for ip in src_ips:
        syn_count = sum(1 for p in packets if p["src_ip"] == ip and is_syn_packet(p))
        logger.debug("  %s sent %d SYN packets", ip, syn_count)

        if detect_syn_flood(packets, ip, config.syn_flood_threshold):
            logger.warning("SYN FLOOD DETECTED: %s sent %d SYN packets (threshold: %d)",
                           ip, syn_count, config.syn_flood_threshold)
            syn_floods.append({
                "src_ip": ip,
                "syn_count": syn_count
            })

    logger.info("Analysis complete: %d port scans, %d SYN floods detected",
                len(port_scans), len(syn_floods))

    return {
        "total_packets": len(packets),
        "port_scans": port_scans,
        "syn_floods": syn_floods
    }


# ---------------------------------------------------------------------------
# Phase 6: Professional CLI with argparse
# ---------------------------------------------------------------------------

def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description='Network Traffic Monitor - Detect suspicious network patterns',
        epilog='Example: %(prog)s traffic_sample.log --output results.json -v'
    )

    parser.add_argument(
        'input_file',
        type=str,
        help='Path to network traffic log file (CSV format)'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        default=NetworkConfig.DEFAULT_OUTPUT_FILE,
        help='Output file for results (default: results.json)'
    )

    parser.add_argument(
        '--port-scan-threshold', '-p',
        type=int,
        default=NetworkConfig.DEFAULT_PORT_SCAN_THRESHOLD,
        metavar='N',
        help='Unique ports before flagging as port scan (default: 25)'
    )

    parser.add_argument(
        '--syn-flood-threshold', '-s',
        type=int,
        default=NetworkConfig.DEFAULT_SYN_FLOOD_THRESHOLD,
        metavar='N',
        help='SYN packets before flagging as flood (default: 100)'
    )

    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging verbosity (default: INFO)'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output - sets log level to DEBUG'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    return parser


def validate_args(args) -> None:
    """Validate command-line arguments.

    Raises:
        FileNotFoundError: If input file does not exist
        ValueError: If thresholds are not positive integers
    """
    if not os.path.exists(args.input_file):
        raise FileNotFoundError(f"Input file not found: {args.input_file}")

    if not os.path.isfile(args.input_file):
        raise ValueError(f"Input path is not a file: {args.input_file}")

    if args.port_scan_threshold < 1:
        raise ValueError("Port scan threshold must be at least 1")

    if args.syn_flood_threshold < 1:
        raise ValueError("SYN flood threshold must be at least 1")

    if args.verbose:
        args.log_level = 'DEBUG'


def main() -> int:
    """Main entry point. Returns exit code."""
    parser = create_parser()
    args = parser.parse_args()

    try:
        validate_args(args)

        setup_logging(log_level=args.log_level)

        logger.info("Network Monitor v1.0.0 starting")
        logger.info("Input file: %s", args.input_file)
        logger.info("Output file: %s", args.output)

        config = NetworkConfig(
            port_scan_threshold=args.port_scan_threshold,
            syn_flood_threshold=args.syn_flood_threshold
        )

        # Step 1: Load
        packets, errors = load_traffic_log(args.input_file)

        # Step 2: Analyze
        results = analyze_traffic(packets, config)

        # Step 3: Save
        output = {
            "total_packets": results["total_packets"],
            "parse_errors": errors,
            "port_scans": results["port_scans"],
            "syn_floods": results["syn_floods"],
            "summary": f"Scanned {results['total_packets']} packets. Found {len(results['port_scans'])} port scans, {len(results['syn_floods'])} SYN floods."
        }

        with open(args.output, 'w') as f:
            json.dump(output, f, indent=2)

        logger.info("Results written to %s", args.output)

        print(f"\n✓ Analysis complete")
        print(f"  Total packets:  {results['total_packets']}")
        print(f"  Parse errors:   {errors}")
        print(f"  Port scans:     {len(results['port_scans'])}")
        print(f"  SYN floods:     {len(results['syn_floods'])}")
        print(f"\n  Results saved to: {args.output}")

        return 0

    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        print("\nAborted by user", file=sys.stderr)
        return 130

    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        logger.exception("Unexpected error")
        return 2


if __name__ == "__main__":
    sys.exit(main())