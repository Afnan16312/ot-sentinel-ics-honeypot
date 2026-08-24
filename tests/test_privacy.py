import unittest

from ot_sentinel.privacy import network_prefix, pseudonymize_ip, sanitize_event


class PrivacyTests(unittest.TestCase):
    def test_pseudonym_is_stable_and_salted(self):
        first_salt = "a" * 32
        second_salt = "b" * 32
        self.assertEqual(
            pseudonymize_ip("203.0.113.4", first_salt),
            pseudonymize_ip("203.0.113.4", first_salt),
        )
        self.assertNotEqual(
            pseudonymize_ip("203.0.113.4", first_salt),
            pseudonymize_ip("203.0.113.4", second_salt),
        )

    def test_short_pseudonymization_salt_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least 32"):
            pseudonymize_ip("203.0.113.4", "too-short")

    def test_sanitize_removes_raw_material(self):
        clean = sanitize_event(
            {
                "source_ip": "203.0.113.8",
                "raw_payload_hex": "deadbeef",
                "source_network": "203.0.113.0/24",
                "decoded": {
                    "operation": "probe",
                    "nested": [{"password": "secret", "safe": "value"}],
                },
            },
            "test-salt-that-is-at-least-32-characters",
        )
        self.assertNotIn("source_ip", clean)
        self.assertNotIn("raw_payload_hex", clean)
        self.assertNotIn("source_network", clean)
        self.assertNotIn("password", clean["decoded"]["nested"][0])
        self.assertEqual(clean["decoded"]["nested"][0]["safe"], "value")

    def test_ipv6_network_prefix(self):
        self.assertEqual(network_prefix("2001:db8::1"), "2001:db8::/48")


if __name__ == "__main__":
    unittest.main()
