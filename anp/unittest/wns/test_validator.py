"""Tests for anp.wns.validator — pure format validation, no network I/O."""

import unittest

from anp.wns.exceptions import HandleValidationError, WbaUriParseError
from anp.wns.validator import (
    build_resolution_url,
    build_wba_uri,
    normalize_handle,
    parse_wba_uri,
    validate_handle,
    validate_local_part,
)


class TestValidateLocalPart(unittest.TestCase):
    """Spec section 3.1 — local-part syntax rules."""

    def test_simple_alpha(self):
        self.assertTrue(validate_local_part("alice"))

    def test_single_char(self):
        self.assertTrue(validate_local_part("a"))

    def test_alphanumeric(self):
        self.assertTrue(validate_local_part("agent42"))

    def test_with_hyphen(self):
        self.assertTrue(validate_local_part("bob-smith"))

    def test_starts_with_digit(self):
        self.assertTrue(validate_local_part("42agent"))

    def test_max_length(self):
        # 63 chars: starts with 'a', ends with 'z', padded with 'b's
        self.assertTrue(validate_local_part("a" + "b" * 61 + "z"))

    def test_empty(self):
        self.assertFalse(validate_local_part(""))

    def test_starts_with_hyphen(self):
        self.assertFalse(validate_local_part("-alice"))

    def test_ends_with_hyphen(self):
        self.assertFalse(validate_local_part("alice-"))

    def test_consecutive_hyphens(self):
        self.assertFalse(validate_local_part("al--ice"))

    def test_too_long(self):
        self.assertFalse(validate_local_part("a" * 64))

    def test_uppercase_normalised(self):
        # validate_local_part lowercases internally
        self.assertTrue(validate_local_part("Alice"))

    def test_underscore_rejected(self):
        self.assertFalse(validate_local_part("alice_bob"))

    def test_dot_rejected(self):
        self.assertFalse(validate_local_part("alice.bob"))


class TestValidateHandle(unittest.TestCase):
    """Spec section 3.1 — full handle validation."""

    def test_valid_basic(self):
        local, domain = validate_handle("alice.example.com")
        self.assertEqual(local, "alice")
        self.assertEqual(domain, "example.com")

    def test_valid_with_hyphen(self):
        local, domain = validate_handle("bob-smith.example.com")
        self.assertEqual(local, "bob-smith")

    def test_valid_subdomain(self):
        local, domain = validate_handle("agent-42.sub.example.com")
        self.assertEqual(local, "agent-42")
        self.assertEqual(domain, "sub.example.com")

    def test_case_normalisation(self):
        local, domain = validate_handle("Alice.Example.COM")
        self.assertEqual(local, "alice")
        self.assertEqual(domain, "example.com")

    def test_empty_raises(self):
        with self.assertRaises(HandleValidationError):
            validate_handle("")

    def test_no_dot_raises(self):
        with self.assertRaises(HandleValidationError):
            validate_handle("aliceexamplecom")

    def test_invalid_local_raises(self):
        with self.assertRaises(HandleValidationError):
            validate_handle("-alice.example.com")

    def test_consecutive_hyphens_raises(self):
        with self.assertRaises(HandleValidationError):
            validate_handle("al--ice.example.com")

    def test_single_label_domain_raises(self):
        with self.assertRaises(HandleValidationError):
            validate_handle("alice.localhost")

    def test_empty_local_raises(self):
        with self.assertRaises(HandleValidationError):
            validate_handle(".example.com")

    def test_empty_domain_raises(self):
        with self.assertRaises(HandleValidationError):
            validate_handle("alice.")


class TestNormalizeHandle(unittest.TestCase):

    def test_lowercase(self):
        self.assertEqual(normalize_handle("Alice.Example.COM"), "alice.example.com")

    def test_already_lower(self):
        self.assertEqual(normalize_handle("alice.example.com"), "alice.example.com")

    def test_invalid_raises(self):
        with self.assertRaises(HandleValidationError):
            normalize_handle("--bad.example.com")


class TestParseWbaUri(unittest.TestCase):
    """Spec section 3.2 — wba:// URI parsing."""

    def test_valid_uri(self):
        result = parse_wba_uri("wba://alice.example.com")
        self.assertEqual(result.local_part, "alice")
        self.assertEqual(result.domain, "example.com")
        self.assertEqual(result.handle, "alice.example.com")
        self.assertEqual(result.original_uri, "wba://alice.example.com")

    def test_case_normalised(self):
        result = parse_wba_uri("wba://Alice.Example.COM")
        self.assertEqual(result.handle, "alice.example.com")

    def test_missing_scheme_raises(self):
        with self.assertRaises(WbaUriParseError):
            parse_wba_uri("https://alice.example.com")

    def test_empty_after_scheme_raises(self):
        with self.assertRaises(WbaUriParseError):
            parse_wba_uri("wba://")

    def test_invalid_handle_raises(self):
        with self.assertRaises(WbaUriParseError):
            parse_wba_uri("wba://-alice.example.com")


class TestBuildResolutionUrl(unittest.TestCase):

    def test_basic(self):
        url = build_resolution_url("alice", "example.com")
        self.assertEqual(url, "https://example.com/.well-known/handle/alice")

    def test_subdomain(self):
        url = build_resolution_url("bob", "sub.example.com")
        self.assertEqual(url, "https://sub.example.com/.well-known/handle/bob")


class TestBuildWbaUri(unittest.TestCase):

    def test_basic(self):
        uri = build_wba_uri("alice", "example.com")
        self.assertEqual(uri, "wba://alice.example.com")


if __name__ == "__main__":
    unittest.main()
