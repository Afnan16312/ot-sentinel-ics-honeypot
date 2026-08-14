import unittest

from ot_sentinel.mapper import map_event


class MapperTests(unittest.TestCase):
    def ids(self, matches):
        return {match.technique_id for match in matches}

    def test_connection_alone_is_not_attack_mapping(self):
        self.assertEqual(map_event("modbus", "connection", {}), [])

    def test_modbus_read_is_discovery_and_low_confidence_collection(self):
        matches = map_event(
            "modbus", "protocol_request", {"operation": "device_probe", "function_code": 3}
        )
        self.assertEqual(self.ids(matches), {"T0846.001", "T0877"})

    def test_write_is_unauthorized_command_hypothesis(self):
        matches = map_event("modbus", "protocol_request", {"operation": "write_single"})
        self.assertEqual(self.ids(matches), {"T1692.001", "T0836"})

    def test_exploitation_requires_signature(self):
        no_signature = map_event("s7", "known_exploit_probe", {"operation": "device_probe"})
        with_signature = map_event(
            "s7", "known_exploit_probe", {"operation": "device_probe", "signature": "TEST"}
        )
        self.assertNotIn("T0866", self.ids(no_signature))
        self.assertIn("T0866", self.ids(with_signature))


if __name__ == "__main__":
    unittest.main()

