import math
import re

# -----------------------------
# Secured Password Strength Checker
# -----------------------------

COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "111111", "abc123",
    "letmein", "admin", "welcome", "dragon", "monkey", "password123!"
}

DICTIONARY_WORDS = {
    "hello", "world", "love", "football", "sun", "moon",
    "name", "flower", "computer", "python"
}

def calculate_entropy(password: str) -> float:
    """Estimate password entropy based on character set size and length."""
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 32

    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)


def check_patterns(password: str) -> list:
    """Check for common weak patterns."""
    warnings = []

    if password.lower() in COMMON_PASSWORDS:
        warnings.append("Password is a very common password.")

    if password.isdigit():
        warnings.append("Password contains only numbers.")

    if password.isalpha():
        warnings.append("Password contains only letters.")

    if re.match(r"(.)\1{4,}", password):
        warnings.append("Password contains repeated characters.")

    if len(password) < 8:
        warnings.append("Password is shorter than 8 characters.")

    for word in DICTIONARY_WORDS:
        if word in password.lower():
            warnings.append(f"Contains dictionary word: '{word}'")

    return warnings


def score_password(password: str) -> int:
    """Score the password from 0 to 100."""
    entropy = calculate_entropy(password)
    score = 0

    # Entropy scoring
    if entropy < 28:
        score += 10
    elif entropy < 36:
        score += 25
    elif entropy < 60:
        score += 50
    else:
        score += 70

    # Bonus points for variety
    if re.search(r"[a-z]", password): score += 5
    if re.search(r"[A-Z]", password): score += 5
    if re.search(r"[0-9]", password): score += 5
    if re.search(r"[^a-zA-Z0-9]", password): score += 5

    # Length bonus
    score += min(len(password) * 2, 20)

    # Penalties
    penalties = len(check_patterns(password)) * 5
    final_score = max(score - penalties, 0)

    return min(final_score, 100)


def strength_label(score: int) -> str:
    if score < 30: return "VERY WEAK"
    if score < 50: return "WEAK"
    if score < 70: return "MODERATE"
    if score < 90: return "STRONG"
    return "VERY STRONG"


def main():
    print("=== Password Strength Checker ===")
    pw = input("Enter password to check: ")

    entropy = calculate_entropy(pw)
    score = score_password(pw)
    warnings = check_patterns(pw)
    label = strength_label(score)

    print("\n--- Results ---")
    print(f"Score: {score}/100")
    print(f"Strength: {label}")
    print(f"Entropy: {entropy} bits")

    if warnings:
        print("\nWeaknesses detected:")
        for w in warnings:
            print(f"- {w}")
    else:
        print("\nNo major weaknesses found.")

    print("\nDone.")


if __name__ == "__main__":
    main()
