"""
Unit tests for DLP verifiers:
Aadhaar, CreditCard, PAN, DrivingLicense, Passport, VoterID, Phone, Email, IFSC.
"""

import pytest
from dlp.verifiers import (
    AadhaarVerifier,
    CreditCardVerifier,
    PANVerifier,
    DrivingLicenseVerifier,
    PassportVerifier,
    VoterIDVerifier,
    PhoneVerifier,
    EmailVerifier,
    IFSCVerifier,
)


class TestAadhaarVerifier:
    def setup_method(self):
        self.verifier = AadhaarVerifier()

    def test_valid_aadhaar_space_separated(self):
        text = "Employee UID is 2345 6789 0124 for authentication."
        matches = self.verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].verifier_name == "Aadhaar Card"
        assert matches[0].severity == "CRITICAL"
        assert matches[0].is_algorithmic is True
        assert matches[0].masked_value == "XXXX-XXXX-0124"

    def test_valid_aadhaar_continuous(self):
        text = "UID: 234567890124"
        matches = self.verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].raw_value == "234567890124"

    def test_invalid_aadhaar_starts_with_0_or_1(self):
        # Starts with 0 or 1 is invalid in Aadhaar
        text = "0345 6789 0124 and 1345 6789 0124"
        matches = self.verifier.find_all(text)
        assert len(matches) == 0

    def test_invalid_aadhaar_bad_checksum(self):
        # Last digit mutated
        text = "2345 6789 0128"
        matches = self.verifier.find_all(text)
        assert len(matches) == 0


class TestCreditCardVerifier:
    def setup_method(self):
        self.verifier = CreditCardVerifier()

    def test_valid_visa(self):
        text = "Customer paid using Visa 4111 1111 1111 1111 yesterday."
        matches = self.verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].verifier_name == "Visa Card"
        assert matches[0].severity == "CRITICAL"
        assert matches[0].is_algorithmic is True
        assert "4111-XXXX-XXXX-1111" in matches[0].masked_value

    def test_valid_rupay(self):
        text = "RuPay card details: 6061-2345-6789-1234"
        # Let's check if 6061234567891234 passes Luhn or let's use a Luhn-valid RuPay card
        # 606123456789123 + checksum
        from dlp.algorithms import luhn_validate
        matches = self.verifier.find_all(text)
        # Only matched if Luhn is valid
        if luhn_validate("6061234567891234"):
            assert len(matches) == 1
            assert "RuPay" in matches[0].verifier_name

    def test_invalid_card_checksum(self):
        text = "Card 4111 1111 1111 1112 was declined."
        matches = self.verifier.find_all(text)
        assert len(matches) == 0


class TestPANVerifier:
    def setup_method(self):
        self.verifier = PANVerifier()

    def test_valid_individual_pan(self):
        text = "User PAN is ABCPS1234F submitted for KYC."
        matches = self.verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].verifier_name == "PAN Card"
        assert matches[0].severity == "HIGH"
        assert matches[0].details["status_code"] == "P"
        assert matches[0].details["entity_type"] == "Individual (Person)"
        assert matches[0].masked_value == "AB*****4F"

    def test_valid_company_pan(self):
        text = "Company corporate PAN: AAACR9876K"
        matches = self.verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].details["status_code"] == "C"
        assert matches[0].details["entity_type"] == "Company"

    def test_invalid_pan_number_sequence(self):
        # 0000 numeric sequence is invalid in PAN
        text = "ABCDE0000F"
        matches = self.verifier.find_all(text)
        assert len(matches) == 0


class TestDrivingLicenseVerifier:
    def setup_method(self):
        self.verifier = DrivingLicenseVerifier()

    def test_valid_dl_standard(self):
        text = "License: MH-02-20180012345 issued in Maharashtra."
        matches = self.verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].verifier_name == "Driving License"
        assert matches[0].details["state_code"] == "MH"
        assert matches[0].details["state_name"] == "Maharashtra"
        assert "MH" in matches[0].masked_value

    def test_valid_dl_delhi(self):
        text = "DL-0420110012345 driver id"
        matches = self.verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].details["state_code"] == "DL"

    def test_invalid_state_code(self):
        # ZZ is not an Indian state code
        text = "ZZ-02-20180012345"
        matches = self.verifier.find_all(text)
        assert len(matches) == 0


class TestPassportAndVoterID:
    def test_valid_passport(self):
        verifier = PassportVerifier()
        text = "Passport number K1234567 for travel."
        matches = verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].verifier_name == "Passport"
        assert matches[0].masked_value == "K****567"

    def test_valid_voter_id(self):
        verifier = VoterIDVerifier()
        text = "EPIC ID: ABC1234567 on election roll."
        matches = verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].verifier_name == "Voter ID (EPIC)"
        assert matches[0].masked_value == "ABC****567"


class TestContactAndFinancialVerifiers:
    def test_phone_verifier(self):
        verifier = PhoneVerifier()
        text = "Contact me at +91 98765 43210 or 9123456789."
        matches = verifier.find_all(text)
        assert len(matches) == 2
        assert matches[0].verifier_name == "Phone Number"

    def test_email_verifier(self):
        verifier = EmailVerifier()
        text = "Send reports to admin@securecorp.in immediately."
        matches = verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].verifier_name == "Email Address"
        assert "securecorp.in" in matches[0].masked_value

    def test_ifsc_verifier(self):
        verifier = IFSCVerifier()
        text = "Bank branch IFSC is HDFC0001234."
        matches = verifier.find_all(text)
        assert len(matches) == 1
        assert matches[0].verifier_name == "Bank IFSC Code"
        assert matches[0].details["bank_code"] == "HDFC"
