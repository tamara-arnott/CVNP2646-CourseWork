#!/usr/bin/env python3
# subnet_calculator.py
# Calculates network information for IPv4 subnets
# This helps determine how many devices can be on a network

def calculate_subnet(network_ip, subnet_mask):
    
    """
    Figures out how many devices can fit on a network.
    
    I am thinking about this like: "The main building at ATCC has 
    hallways with classrooms. Each classroom is like a subnet - it's 
    a separate space where devices can connect and talk to each other.
    
    This piece of code tells us: given a specific classroom (subnet) 
    and its size indicator (like /24 or /28), how many desks (IP addresses) 
    can fit in that classroom?
    
    The numbers after the / have been defined so a /16 would be a huge 
    classroom with thousands of desks, and /28 would be a tiny classroom 
    with just 14 desks. This code provides a dictionary that tells us 
    this specific information for ONE classroom.
    """
    
    # Calculate total IP addresses (desks) available in this classroom (subnet)
    # Formula: 2^(32 - subnet_mask)
    # The ** symbol means "to the power of" in Python
    # Example: /24 means 2^(32-24) = 2^8 = 256 desks
    #          /28 means 2^(32-28) = 2^4 = 16 desks
    #          /20 means 2^(32-20) = 2^12 = 4,096 desks
    total_ips = 2 ** (32 - subnet_mask)
    
    # Subtract 2 because two "desks" are reserved and can't be used for students
    # First desk = the teacher's desk (network address - identifies the classroom)
    # Last desk = the teacher's microphone (broadcast address - talks to everyone)
    # Whatever number we calculated above, we subtract 2 to get usable student desks
    usable_hosts = total_ips - 2
    
 # This part figures out which ATCC building this network belongs to (network class)
    # We look at the first number of the IP address:
    # 1-127 = Class A (like Main Building - biggest)
    # 128-191 = Class B (like 700 Building - medium)
    # 192-223 = Class C (like 800 Building - smallest)
    
    # Split the IP address by the dots and grab the first number
    # Example: "192.168.1.0" becomes ["192", "168", "1", "0"], we take "192"
    # Then convert it from text to a number so we can compare it
    first_octet = int(network_ip.split('.')[0])
    
    # Now check which range the first number falls into
    if 1 <= first_octet <= 127:
        network_class = "A"  # Main Building range
    elif 128 <= first_octet <= 191:
        network_class = "B"  # 700 Building range
    elif 192 <= first_octet <= 223:
        network_class = "C"  # 800 Building range
    else:
        network_class = "Unknown"  # Outside normal ranges
    
     
    # The return statement sends all the calculated information back in a Python dictionary
    # This works like a data dictionary I'm familiar with from my work with the USNCC data tech team. 
    # It labels each piece of data including format and purpose.
    # In Python, the dictionary keeps everything organized with clear labels (keys)
    
    return {
        'network_ip': network_ip,
        'subnet_mask': subnet_mask,
        'total_ips': total_ips,
        'usable_hosts': usable_hosts,
        'network_class': network_class
    }


# Main program starts here
# The equals signs create a visual border for the output
print("=" * 60)
print("NETWORK SUBNET CALCULATOR")
print("=" * 60 + "\n")

# Test Case 1: /24 subnet (common for small office networks)
print("Test Case 1: Common Small Network")
print("-" * 60)
result1 = calculate_subnet("192.168.1.0", 24)
print(f"Network Address: {result1['network_ip']}/{result1['subnet_mask']}")
print(f"Network Class: Class {result1['network_class']}")
# The :, in the f-string adds commas to numbers (256 becomes 256)
print(f"Total IP Addresses: {result1['total_ips']:,}")
print(f"Usable Host IPs: {result1['usable_hosts']:,}")
# Show the calculation so we understand how we got the answer
print(f"Calculation: 2^(32-{result1['subnet_mask']}) = 2^{32-result1['subnet_mask']} = {result1['total_ips']}\n")

# Test Case 2: /28 subnet (smaller network for better security)
print("Test Case 2: Security Segmented Subnet")
print("-" * 60)
result2 = calculate_subnet("10.0.10.0", 28)
print(f"Network Address: {result2['network_ip']}/{result2['subnet_mask']}")
print(f"Network Class: Class {result2['network_class']}")
print(f"Total IP Addresses: {result2['total_ips']}")
print(f"Usable Host IPs: {result2['usable_hosts']}")
print(f"Calculation: 2^(32-{result2['subnet_mask']}) = 2^{32-result2['subnet_mask']} = {result2['total_ips']}\n")

# Interactive mode - let the user enter their own values
print("=" * 60)
print("INTERACTIVE MODE")
print("=" * 60)

# Get input from the user
# input() always returns text, so we need to convert the mask to an integer
network = input("\nEnter network IP address (e.g., 172.16.0.0): ")
mask = int(input("Enter subnet mask (CIDR notation, e.g., 24): "))

# Calculate using the function we created above
result = calculate_subnet(network, mask)

# Display the results in a nicely formatted report
print("\n" + "=" * 60)
print("SUBNET CALCULATION RESULTS")
print("=" * 60)
print(f"Network Address:    {result['network_ip']}/{result['subnet_mask']}")
print(f"Network Class:      Class {result['network_class']}")
print(f"Total IP Addresses: {result['total_ips']:,}")
print(f"Usable Host IPs:    {result['usable_hosts']:,}")
print(f"\nFormula: 2^(32-{result['subnet_mask']}) = {result['total_ips']}")
print("=" * 60)

# Give a security tip based on the subnet size
print("\n💡 Security Note:")
if result['total_ips'] > 256:
    print("   Large subnet - consider segmentation for security isolation")
elif result['total_ips'] <= 16:
    print("   Small subnet - good for critical infrastructure isolation")
else:
    print("   Medium subnet - suitable for departmental segmentation")