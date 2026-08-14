import unittest

from ot_sentinel.privacy import network_prefix, pseudonymize_ip, sanitize_event


class PrivacyTests(unittest.TestCase):
    def test_pseudonym_is_stable_and_salted(self):
        self.assertEqual(pseudonymize_ip("203.0.113.4", "a"), pseudonymize_ip("203.0.113.4", "a"))
        self.assertNotEqual(pseudonymize_ip("203.0.113.4", "a"), pseudonymize_ip("203.0.113.4", "b"))

    def test_sanitize_removes_raw_material(self):
        clean = sanitize_event(
            {
                "source_ip": "203.0.113.8",
                "raw_payload_hex": "deadbeef",
                "decoded": {"operation": "probe", "password": "secret"},
            },
            "test-salt",
        )
        self.assertNotIn("source_ip", clean)
        self.assertNotIn("raw_payload_hex", clean)
        self.assertNotIn("password", clean["decoded"])
        self.assertEqual(clean["source_network"], "203.0.113.0/24")

    def test_ipv6_network_prefix(self):
        self.assertEqual(network_prefix("2001:db8::1"), "2001:db8::/48")


if __name__ == "__main__":
    unittest.main()

