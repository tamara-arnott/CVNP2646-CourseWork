def check_password_strength(password):
    """
    Evaluates password strength based on multiple criteria.
    Returns: 'WEAK', 'MEDIUM', or 'STRONG'
    """
    # Check length
    has_length = len(password) >= 8
    
    # Check for uppercase letters
    has_upper = any(c.isupper() for c in password)
    
    # Check for lowercase letters
    has_lower = any(c.islower() for c in password)
    
    # Check for numbers
    has_digit = any(c.isdigit() for c in password)
    
    # Check for special characters
    special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    has_special = any(c in special_chars for c in password)
    
    # Count how many criteria are met
    criteria_met = sum([has_length, has_upper, has_lower, has_digit, has_special])
    
    # Provide feedback on what's missing
    feedback = []
    if not has_length:
        feedback.append("- Needs at least 8 characters")
    if not has_upper:
        feedback.append("- Missing uppercase letters")
    if not has_lower:
        feedback.append("- Missing lowercase letters")
    if not has_digit:
        feedback.append("- Missing numbers")
    if not has_special:
        feedback.append("- Missing special characters (!@#$%^&* etc.)")
    
    # Determine strength rating
    if criteria_met == 5:
        return "STRONG", feedback
    elif criteria_met >= 3:
        return "MEDIUM", feedback
    else:
        return "WEAK", feedback


# Test with at least 3 different passwords
test_passwords = [
    'password',           # Weak - no uppercase, numbers, or special chars
    'Password123',        # Medium - missing special characters
    'P@ssw0rd!2024',      # Strong - has everything
    'abc',                # Weak - too short, missing everything
    'MySecureP@ss123'     # Strong - has everything
]

# Print header
print("=" * 60)
print("PASSWORD STRENGTH CHECKER")
print("=" * 60)
print()

# Test each password
for pwd in test_passwords:
    strength, feedback = check_password_strength(pwd)
    
    # Print password and strength
    print(f"Password: {pwd:20} -> Strength: {strength}")
    
    # Print feedback if password is not strong
    if strength != "STRONG":
        print("  Feedback:")
        for item in feedback:
            print(f"    {item}")
    
    print()

print("=" * 60)