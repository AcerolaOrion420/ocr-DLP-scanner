"""
Algorithmic verification functions for DLP.
Implements:
1. Verhoeff algorithm (used by Aadhaar)
2. Luhn algorithm (used by Credit/Debit cards)
"""

from typing import Optional

# --- Verhoeff Algorithm Tables ---
# Multiplication table (Dihedral group D5)
_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

# Permutation table
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)

# Inverse table
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_validate(number_str: str) -> bool:
    """
    Validate a number using Verhoeff algorithm.
    Used for Indian Aadhaar number checksum validation.
    """
    clean = "".join(ch for ch in str(number_str) if ch.isdigit())
    if not clean:
        return False

    c = 0
    # Process from right to left (i=0 is check digit, i=1 is penultimate, ...)
    for i, digit in enumerate(reversed(clean)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(digit)]]

    return c == 0


def verhoeff_generate(base_number_str: str) -> str:
    """
    Generate a full number with Verhoeff check digit appended.
    Useful for generating test cases.
    """
    clean = "".join(ch for ch in str(base_number_str) if ch.isdigit())
    if not clean:
        raise ValueError("Input must contain at least one digit")

    c = 0
    for i, digit in enumerate(reversed(clean)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(digit)]]

    return clean + str(_VERHOEFF_INV[c])


# --- Luhn Algorithm (Mod 10) ---

def luhn_validate(card_str: str) -> bool:
    """
    Validate a number using the Luhn (Mod 10) algorithm.
    Used for credit and debit card number validation.
    Valid card numbers typically have between 13 and 19 digits.
    """
    digits = [int(ch) for ch in str(card_str) if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Check for trivially invalid sequences like all identical digits
    if len(set(digits)) == 1:
        return False

    checksum = 0
    # Process digits right to left
    reversed_digits = digits[::-1]
    for i, digit in enumerate(reversed_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += (doubled - 9) if doubled > 9 else doubled
        else:
            checksum += digit

    return checksum % 10 == 0


def identify_card_issuer(card_str: str) -> str:
    """
    Identify card network / brand based on standard IIN/BIN prefixes.
    """
    clean = "".join(ch for ch in str(card_str) if ch.isdigit())
    if not clean:
        return "Unknown"

    # RuPay (India)
    # Starts with 6061-6085, 6521-6530, 81, 82, 508, 353, 356
    if (
        clean.startswith(("81", "82", "508", "353", "356"))
        or (len(clean) >= 4 and 6061 <= int(clean[:4]) <= 6085)
        or (len(clean) >= 4 and 6521 <= int(clean[:4]) <= 6530)
    ):
        return "RuPay"

    # Visa: starts with 4
    if clean.startswith("4"):
        return "Visa"

    # Mastercard: 51-55 or 2221-2720
    if len(clean) >= 2 and 51 <= int(clean[:2]) <= 55:
        return "Mastercard"
    if len(clean) >= 4 and 2221 <= int(clean[:4]) <= 2720:
        return "Mastercard"

    # American Express: 34 or 37 (15 digits)
    if clean.startswith(("34", "37")):
        return "American Express"

    # Discover: 6011, 622126-622925, 644-649, 65
    if clean.startswith("6011") or clean.startswith("65"):
        return "Discover"
    if len(clean) >= 3 and 644 <= int(clean[:3]) <= 649:
        return "Discover"
    if len(clean) >= 6 and 622126 <= int(clean[:6]) <= 622925:
        return "Discover"

    # Diners Club: 300-305, 36, 38
    if clean.startswith(("36", "38")):
        return "Diners Club"
    if len(clean) >= 3 and 300 <= int(clean[:3]) <= 305:
        return "Diners Club"

    # JCB: 3528-3589
    if len(clean) >= 4 and 3528 <= int(clean[:4]) <= 3589:
        return "JCB"

    # Maestro
    if clean.startswith(("50", "56", "57", "58")):
        return "Maestro"

    return "Credit / Debit Card"
