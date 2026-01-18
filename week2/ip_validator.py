def validate_ip(ip_address):
    """
    Validates if a string is a valid IPv4 address.
    Returns True if valid, False if invalid.
    """
    try:
        # Split the IP address into octets
        octets = ip_address.split('.')
        
        # Check if there are exactly 4 octets
        if len(octets) != 4:
            return False
        
        # Check each octet
        for octet in octets:
            # Check if it contains only digits
            if not octet.isdigit():
                return False
            
            # Convert to integer and check range (0-255)
            num = int(octet)
            if num < 0 or num > 255:
                return False
        
        # If all checks pass, IP is valid
        return True
        
    except:
        # If any error occurs, IP is invalid
        return False


# Test cases - at least 3 different IP addresses
test_ips = [
'192.168.1.1',      # Valid
'256.1.1.1',        # Invalid - 256 is too high
'10.0.0.1',         # Valid
'192.168.1',        # Invalid - only 3 octets
'192.168.1.256',    # Invalid - last octet too h
'abc.def.ghi.jkl'   #Invalid - not numbers
]

print("=" * 50)
print("IP ADDRESS VALIDATOR")
print("=" * 50)
print()

for ip in test_ips:
    result = validate_ip(ip)
    status = "VALID" if result else "INVALID"
    print(f"{ip:20} -> {status}")

print()
print("=" * 50)