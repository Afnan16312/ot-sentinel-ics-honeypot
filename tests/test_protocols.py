import unittest

from ot_sentinel.protocols import (
    iec104_response,
    modbus_response,
    parse_iec104,
    parse_modbus,
    parse_s7,
    s7_response,
)


class ModbusTests(unittest.TestCase):
    def test_read_holding_registers(self):
        request = bytes.fromhex("000100000006010300000003")
        decoded = parse_modbus(request)
        self.assertTrue(decoded["valid"])
        self.assertEqual(decoded["function_code"], 3)
        self.assertEqual(decoded["operation"], "device_probe")
        response = modbus_response(request, decoded)
        self.assertEqual(response[:2], b"\x00\x01")
        self.assertEqual(response[7], 3)
        self.assertEqual(response[8], 6)

    def test_write_register_classification(self):
        request = bytes.fromhex("00020000000601060010002a")
        decoded = parse_modbus(request)
        self.assertEqual(decoded["operation"], "write_single")
        self.assertEqual(modbus_response(request, decoded)[7:12], request[7:12])

    def test_truncated_request_is_bounded(self):
        decoded = parse_modbus(b"\x00\x01")
        self.assertFalse(decoded["valid"])
        self.assertEqual(modbus_response(b"\x00\x01", decoded), b"")


class S7Tests(unittest.TestCase):
    def test_cotp_connection_request(self):
        request = bytes.fromhex("0300001611e00000000100c0010ac1020100c2020102")
        decoded = parse_s7(request)
        self.assertTrue(decoded["valid"])
        self.assertEqual(decoded["cotp_pdu_type"], "0xe0")
        self.assertTrue(s7_response(request, decoded).startswith(b"\x03\x00"))


class IEC104Tests(unittest.TestCase):
    def test_startdt(self):
        request = bytes.fromhex("680407000000")
        decoded = parse_iec104(request)
        self.assertEqual(decoded["frame_type"], "U")
        self.assertEqual(iec104_response(request, decoded), bytes.fromhex("68040b000000"))


if __name__ == "__main__":
    unittest.main()

