"""
Unit and integration tests for DLPScanner:
Tests end-to-end scanning, overlap resolution, redaction, HTML highlighting, and risk metrics.
"""

import pytest
from dlp.scanner import DLPScanner


class TestDLPScanner:
    def setup_method(self):
        self.scanner = DLPScanner()

    def test_clean_text_scan(self):
        text = "This is a clean document with no sensitive data or credentials."
        result = self.scanner.scan(text)

        assert result.findings_count == 0
        assert result.risk_level == "CLEAN"
        assert result.risk_score == 0
        assert result.algorithmic_matches_count == 0
        assert result.redacted_text == text
        assert "dlp-leak" not in result.highlighted_html

    def test_critical_leak_aadhaar_and_credit_card(self):
        text = (
            "Billing Record:\n"
            "Card: 4111 1111 1111 1111\n"
            "Aadhaar: 2345 6789 0124\n"
            "PAN: ABCPS1234F\n"
        )
        result = self.scanner.scan(text)

        assert result.findings_count == 3
        assert result.risk_level == "CRITICAL"
        assert result.risk_score > 70
        assert result.algorithmic_matches_count == 2

        # Check redacted text
        assert "4111 1111 1111 1111" not in result.redacted_text
        assert "2345 6789 0124" not in result.redacted_text
        assert "ABCPS1234F" not in result.redacted_text

        # Check highlighted HTML
        assert "dlp-leak-critical" in result.highlighted_html
        assert "dlp-leak-high" in result.highlighted_html

    def test_overlap_resolution(self):
        # A credit card like 4111 1111 1111 1111 should not be partially matched as a 10-digit phone number
        text = "Visa: 4111 1111 1111 1111"
        result = self.scanner.scan(text)

        assert result.findings_count == 1
        assert "Visa" in result.findings[0].verifier_name
        assert result.findings[0].is_algorithmic is True

    def test_multiple_findings_and_context(self):
        text = "Contact user at test.user@company.com with license MH-02-20180012345."
        result = self.scanner.scan(text)

        assert result.findings_count == 2
        # Verify context snippet includes masking
        dl_finding = next(f for f in result.findings if f.verifier_name == "Driving License")
        assert "MH" in dl_finding.context_snippet

    def test_scanned_dl_ocr_text(self):
        user_ocr_text = """DL No.
NAME
D.O.B

VALID TILL :

: KAO4 20220017889 DOI : 13/09/2022

: OMKAR R REDDY |

: 02/10/2001 BG.: O+
01/10/2041(NT)

VALID THROUGHOUT INDIA
cov : LMV 13/09/2022
: MCWG  109/2022

: RAMESHA REDDY N
: #19 C N K Reddy Garden House Opp C N K

FORM -7
[See Rule 16(2))

}-1000"""
        result = self.scanner.scan(user_ocr_text)
        assert result.findings_count == 1
        finding = result.findings[0]
        assert finding.verifier_name == "Driving License"
        assert finding.raw_value == "KAO4 20220017889"
        assert finding.details["state_code"] == "KA"
        assert finding.details["state_name"] == "Karnataka"
        assert finding.details["rto_code"] == "04"
        assert finding.details["issue_year"] == 2022
        assert finding.details["license_number"] == "0017889"
        assert "KA-XX-****-7889" in result.redacted_text
        assert "KAO4 20220017889" not in result.redacted_text
        assert "dlp-leak-high" in result.highlighted_html

    def test_scanned_eaadhaar_with_vid(self):
        text = """Omkar R Reddy
8618348660
9591 6294 0304
VID : 
VID : 
9197 9191 1925 4976
9197 9191 1925 4976"""
        result = self.scanner.scan(text)
        verifier_names = [f.verifier_name for f in result.findings]
        # Must detect phone, Aadhaar, and VID
        assert "Phone Number" in verifier_names
        assert "Aadhaar Card" in verifier_names
        assert "Aadhaar Virtual ID (VID)" in verifier_names

        # Must NOT flag phantom line-bridging finding '4976\n9197 9191'
        raw_values = [f.raw_value for f in result.findings]
        assert not any("\n" in val for val in raw_values)
        assert "9591 6294 0304" in raw_values
        assert "9197 9191 1925 4976" in raw_values
