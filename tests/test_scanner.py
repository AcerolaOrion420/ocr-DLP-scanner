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
