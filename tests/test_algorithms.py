"""
Unit tests for Verhoeff and Luhn checksum algorithms.
"""

import pytest
from dlp.algorithms import (
    verhoeff_validate,
    verhoeff_generate,
    luhn_validate,
    identify_card_issuer,
)


class TestVerhoeffAlgorithm:
    def test_verhoeff_known_numbers(self):
        # Known valid numbers under Verhoeff algorithm
        # E.g. base 23456789012 + check digit 4
        assert verhoeff_validate("234567890124") is True
        assert verhoeff_validate("2345 6789 0124") is True
        assert verhoeff_validate("2345-6789-0124") is True

        # Mutate last digit
        assert verhoeff_validate("234567890125") is False
        assert verhoeff_validate("234567890128") is False

        # Transposition error (adjacent digit swap)
        assert verhoeff_validate("234576890124") is False

    def test_verhoeff_generate(self):
        base = "31234567890"
        generated = verhoeff_generate(base)
        assert len(generated) == len(base) + 1
        assert verhoeff_validate(generated) is True

    def test_verhoeff_invalid_inputs(self):
        assert verhoeff_validate("") is False
        assert verhoeff_validate("abcdef") is False


class TestLuhnAlgorithm:
    def test_luhn_valid_cards(self):
        # Standard test cards
        # Visa
        assert luhn_validate("4111111111111111") is True
        assert luhn_validate("4111 1111 1111 1111") is True
        assert luhn_validate("4111-1111-1111-1111") is True

        # Mastercard test card
        assert luhn_validate("5424000000000015") is True

    def test_luhn_invalid_cards(self):
        # Mutated last digit
        assert luhn_validate("4111111111111112") is False
        assert luhn_validate("5424000000000019") is False

        # All identical digits (rejected for security)
        assert luhn_validate("1111111111111111") is False

        # Too short / too long
        assert luhn_validate("4111") is False
        assert luhn_validate("1234567890123456789012") is False

    def test_identify_card_issuer(self):
        assert identify_card_issuer("4111111111111111") == "Visa"
        assert identify_card_issuer("5424000000000015") == "Mastercard"
        assert identify_card_issuer("340000000000000") == "American Express"
        assert identify_card_issuer("6061234567891234") == "RuPay"
        assert identify_card_issuer("6500000000000000") == "Discover"
        assert identify_card_issuer("3528000000000000") == "JCB"
