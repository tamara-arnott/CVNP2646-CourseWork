# ============================================
# PYTHON BASICS DEMONSTRATION
# Tamara Arnott - CVNP2646
# Week 2 Assignment
# ============================================

# This script demonstrates Python concepts I'm learning in this course.
# I've organized it into sections for each different type of action or element.

# This part of the code creates a visual header using string multiplication
# The "*" operator repeats "=" 50 times to make a clean border
print("=" * 50)
print("PYTHON FUNDAMENTALS DEMONSTRATION")
print("=" * 50)
# Empty print() adds a blank line for readability
print()

# ============================================
# SECTION 1: VARIABLES AND DATA TYPES
# ============================================
# Python has several built-in data types explained in the week2 lecture and reading materials.

print("SECTION 1: Variables and Data Types")
print("-" * 50)

# String: text data in quotes
student_name = "Tamara Arnott"
# f-strings let me embed variables directly in text using curly braces to simplify coding
print(f"String: {student_name}")

# Integer: whole numbers, no decimal point
port_number = 443
print(f"Integer: {port_number}")

# Float: numbers with decimals, per the reading this was managed differently in Python2 - in division it would not show the decimal just the integer.
success_rate = 98.5
print(f"Float: {success_rate}")

# Boolean: True/False values -note use of upper case T and F. 
is_secure = True
print(f"Boolean: {is_secure}")

# List: ordered collection of items in square brackets
# Lists are changable in [] - I can add, remove, or change items. If () is used, these represent a "tuple" and the values can not be changed.
security_tools = ["Wireshark", "Nmap", "Metasploit"]
print(f"List: {security_tools}")

print()

# ============================================
# SECTION 2: CONDITIONAL STATEMENTS
# ============================================
# Conditionals let programs make decisions based on conditions.
# This example checks a port number and provides relevant information.
# Claudeai told me that a port is like an apartment in a building. Different activities are happening in each separate apartment in the building.

print("SECTION 2: Conditional Logic")
print("-" * 50)

test_port = 22

# Check conditions in order - first match executes, then exits the block
# Note: "==" tests equality, while "=" assigns values
if test_port == 22:
    print(f"Port {test_port}: SSH - Secure Shell Protocol")
elif test_port == 80:
    print(f"Port {test_port}: HTTP - Unencrypted Web Traffic")
elif test_port == 443:
    print(f"Port {test_port}: HTTPS - Encrypted Web Traffic")
else:
    print(f"Port {test_port}: Unknown or Custom Port")

print()

# ============================================
# SECTION 3: LOOPS
# ============================================
# Loops automate repetitive tasks. Python has two main types: for and while.

print("SECTION 3: Loops")
print("-" * 50)

# FOR LOOP - goes through each item in a list, one at a time
# Use this when you have a specific list of things to process
# You can use 'break' to exit the loop early if needed, like when you find the thing you are looking for you can stop looking for it, like finding the first error.
print("Common Security Tools:")
for tool in security_tools:
    print(f"  - {tool}")

print()

# WHILE LOOP - keeps repeating as long as the condition is true
# Example: if I write "while 5 < 10:" it would loop forever because 5 is always less than 10
# That's why I need to change current_port inside the loop (with the +=1)- so it eventually becomes 86 and stops
print("Scanning ports 80-85:")
current_port = 80
while current_port <= 85:
    print(f"  Scanning port {current_port}...")
    # Increment: add 1 to move to the next port
    # This ensures we eventually reach 86 and exit the loop
    current_port += 1

print()

# ============================================
# SUMMARY
# ============================================

print("=" * 50)
print("DEMONSTRATION COMPLETE")
print("=" * 50)
print()
print("This script demonstrated:")
print("  ✓ Five data types: string, int, float, boolean, list")
print("  ✓ Conditional statements: if/elif/else")
print("  ✓ For loop: iterating through a list")
print("  ✓ While loop: counting with a condition")
print("  ✓ Comments explaining each section")
print()
print("=" * 50)