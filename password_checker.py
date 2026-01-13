# Password Strength Calculator
# This tool checks how strong a password is based on # of characters (length) and # of different character types are entered.
# Get password from the user
password = input('Enter a password to test its strength: ')

# This counts how many characters are in the password and can be used later when we print the output.
password_length = len(password)

# Check for different types of characters
has_uppercase = False  # Does it have capital letters?
has_lowercase = False  # Does it have lowercase letters?
has_numbers = False    # Does it have numbers?
has_special = False    # Does it have special characters like !@#$?

# Confirm use of at least one of each character type - upper lower number symbol 
for character in password:
    if character.isupper():  # Is it a capital letter?
        has_uppercase = True
    elif character.islower():  # Is it a lowercase letter?
        has_lowercase = True
    elif character.isdigit():  # Is it a number?
        has_numbers = True
    else:  # Must be a special character
        has_special = True

# Count how many different types of characters are used
# We add +1 for each type that's present
character_variety = 0
if has_uppercase:
    character_variety += 1
if has_lowercase:
    character_variety += 1
if has_numbers:
    character_variety += 1
if has_special:
    character_variety += 1

# Calculate a strength score (0-35)
# Longer passwords and more variety = higher score
length_score = min(password_length * 4, 15)  # Up to 20 points for length (max points at 10 characters)
variety_score = character_variety * 5  # 5 points for each type of character used

total_score = length_score + variety_score

# Decide the strength level based on the score
if total_score >= 28:
    strength = "Strong"
    color = "🟢"  # Green circle emoji
elif total_score >= 22:
    strength = "Medium"
    color = "🟡"  # Yellow circle emoji
else:
    strength = "Weak"
    color = "🔴"  # Red circle emoji

# Use the F string format to grab the len(password) number stored from the code above and present it to the user using f-strings for nice formatting
print(f"\n{'='*50}")
print(f"Password Strength Analysis")
print(f"{'='*50}")
print(f"Password: {'*' * password_length}")  # Hide the actual password
print(f"Length: {password_length} characters")
print(f"Has uppercase letters: {'Yes' if has_uppercase else 'No'}")
print(f"Has lowercase letters: {'Yes' if has_lowercase else 'No'}")
print(f"Has numbers: {'Yes' if has_numbers else 'No'}")
print(f"Has special characters: {'Yes' if has_special else 'No'}")
print(f"\nStrength Score: {total_score}/35")
print(f"Overall Strength: {color} {strength}")
print(f"{'='*50}\n")

# This code prints out the rating and provides hints to improve the password strength
if strength == "Weak":
    print("💡 Tips to improve your password:")
    if password_length < 8:
        print("   - Make it at least 8 characters long")
    if not has_uppercase:
        print("   - Add some uppercase letters (A-Z)")
    if not has_lowercase:
        print("   - Add some lowercase letters (a-z)")
    if not has_numbers:
        print("   - Add some numbers (0-9)")
    if not has_special:
        print("   - Add special characters (!@#$%^&*)")
elif strength == "Medium":
    print("💡 Your password is decent, but could be stronger!")
    if password_length < 12:
        print("   - Try making it 12+ characters for extra security")
    if character_variety < 4:
        print("   - Use all 4 types of characters for maximum strength")
else:
    print("✅ Great job! This is a strong password!")