"""
PII and Sensitive Data Verifiers for DLP Engine.
Includes:
- Aadhaar (Algorithmic: Verhoeff)
- Credit / Debit Cards (Algorithmic: Luhn)
- PAN Card (Regex + Structure validation)
- Driving License (Regex + State Code validation)
- Passport (Regex)
- Voter ID / EPIC (Regex)
- Phone numbers (Regex)
- Email addresses (Regex)
- Bank IFSC code (Regex)
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from dlp.algorithms import verhoeff_validate, luhn_validate, identify_card_issuer


# State codes for Indian Driving Licenses
INDIAN_STATE_CODES = {
    "AN": "Andaman and Nicobar Islands",
    "AP": "Andhra Pradesh",
    "AR": "Arunachal Pradesh",
    "AS": "Assam",
    "BR": "Bihar",
    "CG": "Chhattisgarh",
    "CH": "Chandigarh",
    "DD": "Daman and Diu",
    "DL": "Delhi",
    "DN": "Dadra and Nagar Haveli",
    "GA": "Goa",
    "GJ": "Gujarat",
    "HP": "Himachal Pradesh",
    "HR": "Haryana",
    "JH": "Jharkhand",
    "JK": "Jammu and Kashmir",
    "KA": "Karnataka",
    "KL": "Kerala",
    "LA": "Ladakh",
    "LD": "Lakshadweep",
    "MH": "Maharashtra",
    "ML": "Meghalaya",
    "MN": "Manipur",
    "MP": "Madhya Pradesh",
    "MZ": "Mizoram",
    "NL": "Nagaland",
    "OD": "Odisha",
    "OR": "Odisha",
    "PB": "Punjab",
    "PY": "Puducherry",
    "RJ": "Rajasthan",
    "SK": "Sikkim",
    "TN": "Tamil Nadu",
    "TR": "Tripura",
    "TS": "Telangana",
    "UA": "Uttarakhand",
    "UK": "Uttarakhand",
    "UP": "Uttar Pradesh",
    "WB": "West Bengal",
}

PAN_STATUS_CODES = {
    "P": "Individual (Person)",
    "C": "Company",
    "H": "Hindu Undivided Family (HUF)",
    "F": "Partnership Firm / LLP",
    "A": "Association of Persons (AOP)",
    "T": "Trust",
    "B": "Body of Individuals (BOI)",
    "L": "Local Authority",
    "J": "Artificial Juridical Person",
    "G": "Government Agency",
}


@dataclass
class RawFinding:
    verifier_name: str
    category: str
    severity: str
    is_algorithmic: bool
    raw_value: str
    start: int
    end: int
    masked_value: str
    validation_method: str
    details: Dict[str, Any]


class BaseVerifier:
    name: str = "Base"
    category: str = "Unknown"
    severity: str = "MEDIUM"
    is_algorithmic: bool = False

    def find_all(self, text: str) -> List[RawFinding]:
        raise NotImplementedError

    def mask(self, raw: str) -> str:
        return "****"


class AadhaarVerifier(BaseVerifier):
    """
    Aadhaar Card Verifier:
    Format: 12 digits, cannot start with 0 or 1.
    Separators: space, hyphen, or none.
    Validation: Verhoeff algorithm.
    """
    name = "Aadhaar Card"
    category = "National ID"
    severity = "CRITICAL"
    is_algorithmic = True

    # Matches 12-digit numbers formatted as 4-4-4 or 12 consecutive digits
    PATTERN = re.compile(
        r"(?<!\d)([2-9]\d{3})[\s-]?(\d{4})[\s-]?(\d{4})(?!\d)"
    )

    def find_all(self, text: str) -> List[RawFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            raw = match.group(0)
            digits = "".join(ch for ch in raw if ch.isdigit())
            
            # Must be exactly 12 digits
            if len(digits) != 12:
                continue

            # Cannot be all repeating identical digits (e.g. 2222 2222 2222)
            if len(set(digits)) == 1:
                continue

            # Algorithmic Verhoeff verification
            if verhoeff_validate(digits):
                findings.append(
                    RawFinding(
                        verifier_name=self.name,
                        category=self.category,
                        severity=self.severity,
                        is_algorithmic=True,
                        raw_value=raw,
                        start=match.start(),
                        end=match.end(),
                        masked_value=self.mask(raw),
                        validation_method="Algorithmic (Verhoeff Checksum Validated)",
                        details={
                            "formatted": f"{digits[:4]} {digits[4:8]} {digits[8:]}",
                            "algorithm": "Verhoeff Checksum",
                            "status": "Verified Genuine Aadhaar Format",
                        },
                    )
                )
        return findings

    def mask(self, raw: str) -> str:
        digits = "".join(ch for ch in raw if ch.isdigit())
        if len(digits) == 12:
            return f"XXXX-XXXX-{digits[-4:]}"
        return "XXXX-XXXX-" + raw[-4:] if len(raw) >= 4 else "XXXX"


class CreditCardVerifier(BaseVerifier):
    """
    Credit / Debit Card Verifier:
    Format: 13 to 19 digits.
    Separators: spaces, hyphens, or none.
    Validation: Luhn (Mod 10) algorithm + IIN/BIN network recognition.
    """
    name = "Credit / Debit Card"
    category = "Financial"
    severity = "CRITICAL"
    is_algorithmic = True

    # Matches 13-19 digit card numbers with optional space or hyphen groupings
    # E.g. 4 groups of 4 (16), 4-6-5 (15 Amex), 3-4-4-3, or 13-19 continuous digits
    PATTERN = re.compile(
        r"(?<!\d)(?:(?:\d{4}[ -]?){3}\d{4}|\d{4}[ -]?\d{6}[ -]?\d{5}|\d{13,19})(?!\d)"
    )

    def find_all(self, text: str) -> List[RawFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            raw = match.group(0)
            digits = "".join(ch for ch in raw if ch.isdigit())

            # Avoid capturing 12-digit numbers here
            if len(digits) < 13 or len(digits) > 19:
                continue

            # Algorithmic Luhn verification
            if luhn_validate(digits):
                issuer = identify_card_issuer(digits)
                findings.append(
                    RawFinding(
                        verifier_name=f"{issuer} Card" if issuer != "Credit / Debit Card" else self.name,
                        category=self.category,
                        severity=self.severity,
                        is_algorithmic=True,
                        raw_value=raw,
                        start=match.start(),
                        end=match.end(),
                        masked_value=self.mask(raw),
                        validation_method=f"Algorithmic (Luhn Mod-10 Validated - {issuer})",
                        details={
                            "issuer": issuer,
                            "card_length": len(digits),
                            "last_four": digits[-4:],
                            "algorithm": "Luhn Checksum (Mod 10)",
                        },
                    )
                )
        return findings

    def mask(self, raw: str) -> str:
        digits = "".join(ch for ch in raw if ch.isdigit())
        if len(digits) >= 12:
            return f"{digits[:4]}-XXXX-XXXX-{digits[-4:]}"
        return "****-****-" + digits[-4:] if len(digits) >= 4 else "****"


class PANVerifier(BaseVerifier):
    """
    Permanent Account Number (PAN) Card Verifier:
    Format: 5 letters, 4 digits, 1 letter (e.g., ABCDE1234F).
    Validation: Regex + 4th character structure check (Individual, Company, Trust, etc.).
    """
    name = "PAN Card"
    category = "Tax ID"
    severity = "HIGH"
    is_algorithmic = False

    PATTERN = re.compile(
        r"(?<![A-Za-z0-9])([A-Za-z]{3})([A-Za-z])([A-Za-z])([0-9]{4})([A-Za-z])(?![A-Za-z0-9])"
    )

    def find_all(self, text: str) -> List[RawFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            raw = match.group(0).upper()
            status_char = raw[3]
            holder_type = PAN_STATUS_CODES.get(status_char, "Other Entity")
            
            # Numeric sequence 0000 is invalid in PAN
            num_part = raw[5:9]
            if num_part == "0000":
                continue

            findings.append(
                RawFinding(
                    verifier_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    is_algorithmic=False,
                    raw_value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    masked_value=self.mask(raw),
                    validation_method=f"Regex + Structural Validation (Status: {holder_type})",
                    details={
                        "pan_uppercase": raw,
                        "status_code": status_char,
                        "entity_type": holder_type,
                        "surname_initial": raw[4],
                    },
                )
            )
        return findings

    def mask(self, raw: str) -> str:
        pan = raw.strip().upper()
        if len(pan) == 10:
            return f"{pan[:2]}*****{pan[-2:]}"
        return "PAN-******"


class DrivingLicenseVerifier(BaseVerifier):
    """
    Indian Driving License (DL) Verifier:
    Format:
    - Standard Sarathi: SS-RR-YYYYNNNNNNN (e.g. MH-01-20150001234 or DL-0420110012345)
    - Legacy state formats: SS/RR/YYYY/NNNNNNN or SS-RR-YYYY-NNNNNNN
    Validation: Regex + Indian State Code lookup.
    """
    name = "Driving License"
    category = "Identity & Transport"
    severity = "HIGH"
    is_algorithmic = False

    # Standard 15-16 character Sarathi or legacy DL pattern
    PATTERN = re.compile(
        r"(?<![A-Za-z0-9])([A-Za-z]{2})[-/\s]?([0-9]{2})[-/\s]?((?:19|20)[0-9]{2})[-/\s]?([0-9]{7})(?![0-9])|"
        r"(?<![A-Za-z0-9])([A-Za-z]{2})[-/\s]?([0-9]{13})(?![0-9])"
    )

    def find_all(self, text: str) -> List[RawFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            raw = match.group(0)
            state_code = raw[:2].upper()

            # Must be a recognized Indian State or UT code
            if state_code not in INDIAN_STATE_CODES:
                continue

            state_name = INDIAN_STATE_CODES[state_code]
            findings.append(
                RawFinding(
                    verifier_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    is_algorithmic=False,
                    raw_value=raw,
                    start=match.start(),
                    end=match.end(),
                    masked_value=self.mask(raw),
                    validation_method=f"Regex + State Code Validation ({state_name})",
                    details={
                        "state_code": state_code,
                        "state_name": state_name,
                    },
                )
            )
        return findings

    def mask(self, raw: str) -> str:
        clean = raw.strip()
        state = clean[:2].upper()
        return f"{state}-XX-****-{clean[-4:]}" if len(clean) >= 6 else f"{state}-******"


class PassportVerifier(BaseVerifier):
    """
    Indian Passport Verifier:
    Format: 1 letter (uppercase, typically excluding Q, X, Z) followed by 7 digits.
    """
    name = "Passport"
    category = "National ID"
    severity = "HIGH"
    is_algorithmic = False

    # Starts with a letter A-Z (excluding Q, X, Z), followed by 7 digits (first digit 1-9)
    PATTERN = re.compile(
        r"(?<![A-Za-z0-9])([A-PR-WYa-pr-wy])([1-9][0-9]{6})(?![0-9])"
    )

    def find_all(self, text: str) -> List[RawFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFinding(
                    verifier_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    is_algorithmic=False,
                    raw_value=raw,
                    start=match.start(),
                    end=match.end(),
                    masked_value=self.mask(raw),
                    validation_method="Regex (Standard Passport Format)",
                    details={
                        "passport_number": raw.upper(),
                    },
                )
            )
        return findings

    def mask(self, raw: str) -> str:
        clean = raw.strip().upper()
        if len(clean) == 8:
            return f"{clean[0]}****{clean[-3:]}"
        return "PASS-****"


class VoterIDVerifier(BaseVerifier):
    """
    Indian Voter ID (EPIC) Verifier:
    Format: 3 letters followed by 7 digits (e.g., ABC1234567).
    """
    name = "Voter ID (EPIC)"
    category = "National ID"
    severity = "MEDIUM"
    is_algorithmic = False

    PATTERN = re.compile(
        r"(?<![A-Za-z0-9])([A-Za-z]{3})([0-9]{7})(?![0-9])"
    )

    def find_all(self, text: str) -> List[RawFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFinding(
                    verifier_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    is_algorithmic=False,
                    raw_value=raw,
                    start=match.start(),
                    end=match.end(),
                    masked_value=self.mask(raw),
                    validation_method="Regex (Election Commission EPIC Format)",
                    details={
                        "epic_number": raw.upper(),
                    },
                )
            )
        return findings

    def mask(self, raw: str) -> str:
        clean = raw.strip().upper()
        if len(clean) == 10:
            return f"{clean[:3]}****{clean[-3:]}"
        return "EPIC-****"


class PhoneVerifier(BaseVerifier):
    """
    Indian Mobile Phone Number Verifier:
    Format: Optional +91 / 91 / 0 followed by 10 digits starting with 6, 7, 8, or 9.
    """
    name = "Phone Number"
    category = "Contact Information"
    severity = "MEDIUM"
    is_algorithmic = False

    PATTERN = re.compile(
        r"(?<!\d)(?:(?:\+91|91|0)[-.\s]?)?([6-9]\d{4}[-.\s]?\d{5})(?!\d)"
    )

    def find_all(self, text: str) -> List[RawFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            raw = match.group(0)
            digits = "".join(ch for ch in raw if ch.isdigit())

            # Ignore if length doesn't match Indian phone (10 digits or 11 with 0 or 12 with 91)
            if len(digits) not in (10, 11, 12):
                continue

            last_10 = digits[-10:]
            if last_10[0] not in "6789":
                continue

            findings.append(
                RawFinding(
                    verifier_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    is_algorithmic=False,
                    raw_value=raw,
                    start=match.start(),
                    end=match.end(),
                    masked_value=self.mask(raw),
                    validation_method="Regex (Indian Telecom E.164 Format)",
                    details={
                        "standardized": f"+91 {last_10[:5]} {last_10[5:]}",
                    },
                )
            )
        return findings

    def mask(self, raw: str) -> str:
        digits = "".join(ch for ch in raw if ch.isdigit())
        if len(digits) >= 10:
            return f"+91-XXXXX-{digits[-4:]}"
        return "+91-XXXXX-XXXX"


class EmailVerifier(BaseVerifier):
    """
    Email Address Verifier:
    Format: standard RFC email pattern.
    """
    name = "Email Address"
    category = "Contact Information"
    severity = "LOW"
    is_algorithmic = False

    PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    def find_all(self, text: str) -> List[RawFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFinding(
                    verifier_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    is_algorithmic=False,
                    raw_value=raw,
                    start=match.start(),
                    end=match.end(),
                    masked_value=self.mask(raw),
                    validation_method="Regex (RFC 5322 Standard)",
                    details={
                        "domain": raw.split("@")[-1] if "@" in raw else "",
                    },
                )
            )
        return findings

    def mask(self, raw: str) -> str:
        if "@" in raw:
            user, domain = raw.split("@", 1)
            masked_user = user[0] + "***" + user[-1] if len(user) > 2 else user[0] + "***"
            return f"{masked_user}@{domain}"
        return "e***@domain.com"


class IFSCVerifier(BaseVerifier):
    """
    Indian Financial System Code (IFSC) Verifier:
    Format: 4 letters, 0, 6 alphanumeric characters.
    """
    name = "Bank IFSC Code"
    category = "Financial"
    severity = "MEDIUM"
    is_algorithmic = False

    PATTERN = re.compile(
        r"(?<![A-Za-z0-9])([A-Za-z]{4})(0)([A-Za-z0-9]{6})(?![A-Za-z0-9])"
    )

    def find_all(self, text: str) -> List[RawFinding]:
        findings = []
        for match in self.PATTERN.finditer(text):
            raw = match.group(0).upper()
            findings.append(
                RawFinding(
                    verifier_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    is_algorithmic=False,
                    raw_value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    masked_value=self.mask(raw),
                    validation_method="Regex (RBI IFSC Specification)",
                    details={
                        "bank_code": raw[:4],
                        "branch_code": raw[5:],
                    },
                )
            )
        return findings

    def mask(self, raw: str) -> str:
        clean = raw.strip().upper()
        if len(clean) == 11:
            return f"{clean[:4]}0****{clean[-2:]}"
        return "IFSC-******"


# Ordered list of all verifiers
# Note: Algorithmic verifiers (Credit Card, Aadhaar) run first to resolve overlaps
ALL_VERIFIERS = [
    CreditCardVerifier(),
    AadhaarVerifier(),
    PANVerifier(),
    DrivingLicenseVerifier(),
    PassportVerifier(),
    VoterIDVerifier(),
    IFSCVerifier(),
    PhoneVerifier(),
    EmailVerifier(),
]
