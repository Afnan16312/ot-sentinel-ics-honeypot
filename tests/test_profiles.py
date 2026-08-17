import tempfile
import unittest
from pathlib import Path

from ot_sentinel.profiles import ProfileRuntime, ProfileValidationError, load_profile
from ot_sentinel.protocols import modbus_response, parse_modbus

ROOT = Path(__file__).resolve().parents[1]


class ProfileTests(unittest.TestCase):
    def test_all_bundled_profiles_are_fictional_and_valid(self):
        profiles = [load_profile(path) for path in sorted((ROOT / "profiles").glob("*.yaml"))]
        self.assertEqual(len(profiles), 3)
        self.assertEqual({item.sector for item in profiles}, {"water", "power", "ports"})

    def test_write_changes_simulated_memory_and_reset_restores_it(self):
        runtime = ProfileRuntime(load_profile(ROOT / "profiles" / "water-treatment.yaml"))
        write = parse_modbus(bytes.fromhex("00020000000601060010002a"))
        runtime.enrich("modbus", write)
        self.assertTrue(write["simulated_write_applied"])

        read = parse_modbus(bytes.fromhex("000100000006010300100001"))
        runtime.enrich("modbus", read)
        self.assertEqual(read["simulated_values"], [42])
        response = modbus_response(bytes.fromhex("000100000006010300100001"), read)
        self.assertEqual(int.from_bytes(response[9:11], "big"), 42)

        runtime.reset()
        read_after_reset = parse_modbus(bytes.fromhex("000100000006010300100001"))
        runtime.enrich("modbus", read_after_reset)
        self.assertEqual(read_after_reset["simulated_values"], [50])

    def test_out_of_range_write_is_recorded_but_not_applied(self):
        runtime = ProfileRuntime(load_profile(ROOT / "profiles" / "water-treatment.yaml"))
        write = parse_modbus(bytes.fromhex("00020000000601060000002a"))
        runtime.enrich("modbus", write)
        self.assertFalse(write["simulated_write_applied"])
        self.assertEqual(write["simulated_rejected_addresses"], [0])

    def test_multiple_register_write_is_applied_and_acknowledged(self):
        runtime = ProfileRuntime(load_profile(ROOT / "profiles" / "water-treatment.yaml"))
        payload = bytes.fromhex("00030000000b01100010000204002a002b")
        write = parse_modbus(payload)
        runtime.enrich("modbus", write)
        self.assertTrue(write["simulated_write_applied"])
        self.assertEqual(write["write_values"], [42, 43])
        self.assertEqual(modbus_response(payload, write).hex(), "000300000006011000100002")

    def test_active_profile_content_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe.yaml"
            path.write_text(
                '{"schema_version":1,"profile_id":"unsafe-profile","display_name":"Unsafe",'
                '"fictional":true,"sector":"test","description":"Test only",'
                '"device":{},"modbus":{"holding_registers":{},"writable_ranges":[]},'
                '"s7":{},"iec104":{},"shell":"whoami"}',
                encoding="utf-8",
            )
            with self.assertRaises(ProfileValidationError):
                load_profile(path)


if __name__ == "__main__":
    unittest.main()
