# test_network_monitor.py
# week 12 - unit tests for network_monitor.py
# run with: pytest test_network_monitor.py -v

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from network_monitor import (
    NetworkConfig,
    parse_packet_line,
    is_syn_packet,
    detect_port_scan,
    detect_syn_flood,
    analyze_traffic
)


# ---------------------------------------------------------------------------
# Fixtures - reusable test data
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_config():
    """Standard config for testing."""
    return NetworkConfig(port_scan_threshold=25, syn_flood_threshold=100)


@pytest.fixture
def valid_packet_line():
    """A well-formed packet line."""
    return "192.168.1.5,10.0.0.1,54321,443,TCP,SYN"


@pytest.fixture
def syn_packet():
    """A parsed TCP SYN packet."""
    return {
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "flags": "SYN"
    }


@pytest.fixture
def ack_packet():
    """A parsed TCP ACK packet (not a SYN)."""
    return {
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "flags": "ACK"
    }


@pytest.fixture
def udp_packet():
    """A parsed UDP packet (no flags)."""
    return {
        "src_ip": "192.168.1.20",
        "dst_ip": "10.0.0.1",
        "src_port": 48200,
        "dst_port": 53,
        "protocol": "UDP",
        "flags": ""
    }


# ---------------------------------------------------------------------------
# Tests for parse_packet_line()
# ---------------------------------------------------------------------------

def test_parse_valid_packet(valid_packet_line):
    """Happy path: parse a well-formed packet line."""
    packet = parse_packet_line(valid_packet_line)
    assert packet["src_ip"] == "192.168.1.5"
    assert packet["dst_ip"] == "10.0.0.1"
    assert packet["src_port"] == 54321
    assert packet["dst_port"] == 443
    assert packet["protocol"] == "TCP"
    assert packet["flags"] == "SYN"


def test_parse_protocol_uppercased():
    """Protocol should be uppercased regardless of input case."""
    packet = parse_packet_line("192.168.1.5,10.0.0.1,54321,443,tcp,SYN")
    assert packet["protocol"] == "TCP"


def test_parse_udp_empty_flags():
    """UDP packets with empty flags field should parse correctly."""
    packet = parse_packet_line("192.168.1.20,10.0.0.1,48200,53,UDP,")
    assert packet["protocol"] == "UDP"
    assert packet["flags"] == ""


def test_parse_too_few_fields():
    """Error case: fewer than 6 fields should raise ValueError."""
    with pytest.raises(ValueError, match="Expected 6 fields"):
        parse_packet_line("192.168.1.5,10.0.0.1,443")


def test_parse_too_many_fields():
    """Error case: more than 6 fields should raise ValueError."""
    with pytest.raises(ValueError, match="Expected 6 fields"):
        parse_packet_line("192.168.1.5,10.0.0.1,54321,443,TCP,SYN,EXTRA")


def test_parse_invalid_src_port():
    """Error case: non-numeric src_port should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid src_port"):
        parse_packet_line("192.168.1.5,10.0.0.1,not_a_port,443,TCP,SYN")


def test_parse_invalid_dst_port():
    """Error case: non-numeric dst_port should raise ValueError."""
    with pytest.raises(ValueError, match="Invalid dst_port"):
        parse_packet_line("192.168.1.5,10.0.0.1,54321,not_a_port,TCP,SYN")


def test_parse_ports_are_integers(valid_packet_line):
    """Ports should be returned as integers, not strings."""
    packet = parse_packet_line(valid_packet_line)
    assert isinstance(packet["src_port"], int)
    assert isinstance(packet["dst_port"], int)


# ---------------------------------------------------------------------------
# Tests for is_syn_packet()
# ---------------------------------------------------------------------------

def test_is_syn_packet_true(syn_packet):
    """TCP SYN packet should return True."""
    assert is_syn_packet(syn_packet) is True


def test_is_syn_packet_false_ack(ack_packet):
    """TCP ACK packet should return False."""
    assert is_syn_packet(ack_packet) is False


def test_is_syn_packet_false_udp(udp_packet):
    """UDP packet should return False."""
    assert is_syn_packet(udp_packet) is False


def test_is_syn_packet_false_empty_flags():
    """Packet with empty flags should return False."""
    packet = {"protocol": "TCP", "flags": ""}
    assert is_syn_packet(packet) is False


# ---------------------------------------------------------------------------
# Tests for detect_port_scan()
# ---------------------------------------------------------------------------

def test_port_scan_detected_above_threshold(sample_config):
    """Port scan should be detected when unique ports exceed threshold."""
    packets = [
        {"src_ip": "10.0.1.99", "dst_port": port}
        for port in range(1, 31)
    ]
    assert detect_port_scan(packets, "10.0.1.99", sample_config.port_scan_threshold) is True


def test_port_scan_not_detected_below_threshold(sample_config):
    """Port scan should NOT be detected below threshold."""
    packets = [
        {"src_ip": "192.168.1.10", "dst_port": port}
        for port in [80, 443, 22]
    ]
    assert detect_port_scan(packets, "192.168.1.10", sample_config.port_scan_threshold) is False


def test_port_scan_exactly_at_threshold(sample_config):
    """Edge case: exactly at threshold should NOT trigger (condition is >, not >=)."""
    packets = [
        {"src_ip": "192.168.1.10", "dst_port": port}
        for port in range(1, 26)
    ]
    assert detect_port_scan(packets, "192.168.1.10", sample_config.port_scan_threshold) is False


def test_port_scan_duplicate_ports_count_once(sample_config):
    """Duplicate destination ports should only count as one unique port."""
    packets = [
        {"src_ip": "192.168.1.10", "dst_port": 80},
        {"src_ip": "192.168.1.10", "dst_port": 80},
        {"src_ip": "192.168.1.10", "dst_port": 443},
    ]
    assert detect_port_scan(packets, "192.168.1.10", sample_config.port_scan_threshold) is False


def test_port_scan_only_checks_given_ip(sample_config):
    """Port scan detection should only count ports for the specified IP."""
    packets = [
        {"src_ip": "10.0.1.99", "dst_port": port}
        for port in range(1, 31)
    ] + [
        {"src_ip": "192.168.1.10", "dst_port": 80}
    ]
    assert detect_port_scan(packets, "192.168.1.10", sample_config.port_scan_threshold) is False


# ---------------------------------------------------------------------------
# Tests for detect_syn_flood()
# ---------------------------------------------------------------------------

def test_syn_flood_detected_above_threshold(sample_config):
    """SYN flood should be detected when SYN count exceeds threshold."""
    packets = [
        {"src_ip": "172.16.0.77", "dst_port": 80, "protocol": "TCP", "flags": "SYN"}
        for _ in range(110)
    ]
    assert detect_syn_flood(packets, "172.16.0.77", sample_config.syn_flood_threshold) is True


def test_syn_flood_not_detected_below_threshold(sample_config):
    """SYN flood should NOT be detected below threshold."""
    packets = [
        {"src_ip": "192.168.1.10", "dst_port": 80, "protocol": "TCP", "flags": "SYN"}
        for _ in range(10)
    ]
    assert detect_syn_flood(packets, "192.168.1.10", sample_config.syn_flood_threshold) is False


def test_syn_flood_exactly_at_threshold(sample_config):
    """Edge case: exactly at threshold should NOT trigger (condition is >, not >=)."""
    packets = [
        {"src_ip": "192.168.1.10", "dst_port": 80, "protocol": "TCP", "flags": "SYN"}
        for _ in range(100)
    ]
    assert detect_syn_flood(packets, "192.168.1.10", sample_config.syn_flood_threshold) is False


def test_syn_flood_ignores_non_syn_packets(sample_config):
    """Only SYN packets should count toward flood detection."""
    packets = [
        {"src_ip": "172.16.0.77", "dst_port": 80, "protocol": "TCP", "flags": "ACK"}
        for _ in range(110)
    ]
    assert detect_syn_flood(packets, "172.16.0.77", sample_config.syn_flood_threshold) is False


# ---------------------------------------------------------------------------
# Tests for analyze_traffic()
# ---------------------------------------------------------------------------

def test_analyze_empty_packets(sample_config):
    """Analysis of empty packet list should return empty results."""
    results = analyze_traffic([], sample_config)
    assert results["port_scans"] == []
    assert results["syn_floods"] == []


def test_analyze_detects_port_scan(sample_config):
    """analyze_traffic should detect a port scan scenario."""
    packets = [
        {"src_ip": "10.0.1.99", "dst_ip": "10.0.0.5",
         "dst_port": port, "protocol": "TCP", "flags": "SYN"}
        for port in range(1, 31)
    ]
    results = analyze_traffic(packets, sample_config)
    assert len(results["port_scans"]) == 1
    assert results["port_scans"][0]["src_ip"] == "10.0.1.99"


def test_analyze_detects_syn_flood(sample_config):
    """analyze_traffic should detect a SYN flood scenario."""
    packets = [
        {"src_ip": "172.16.0.77", "dst_ip": "10.0.0.2",
         "dst_port": 80, "protocol": "TCP", "flags": "SYN"}
        for _ in range(110)
    ]
    results = analyze_traffic(packets, sample_config)
    assert len(results["syn_floods"]) == 1
    assert results["syn_floods"][0]["src_ip"] == "172.16.0.77"


def test_analyze_clean_traffic_no_alerts(sample_config):
    """Normal traffic should produce no alerts."""
    packets = [
        {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
         "dst_port": 80, "protocol": "TCP", "flags": "SYN"},
        {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
         "dst_port": 443, "protocol": "TCP", "flags": "ACK"},
    ]
    results = analyze_traffic(packets, sample_config)
    assert results["port_scans"] == []
    assert results["syn_floods"] == []