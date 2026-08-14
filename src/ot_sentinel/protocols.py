from __future__ import annotations

import struct
from typing import Any

MODBUS_FUNCTIONS = {
    1: "read_coils",
    2: "read_discrete_inputs",
    3: "read_holding_registers",
    4: "read_input_registers",
    5: "write_single_coil",
    6: "write_single_register",
    15: "write_multiple_coils",
    16: "write_multiple_registers",
    22: "mask_write_register",
    23: "read_write_multiple_registers",
}


def parse_modbus(payload: bytes) -> dict[str, Any]:
    decoded: dict[str, Any] = {"valid": False, "operation": "device_probe"}
    if len(payload) < 8:
        decoded["error"] = "truncated_mbap"
        return decoded
    transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", payload[:7])
    function_code = payload[7]
    decoded.update(
        {
            "valid": protocol_id == 0,
            "transaction_id": transaction_id,
            "protocol_id": protocol_id,
            "declared_length": length,
            "unit_id": unit_id,
            "function_code": function_code,
            "function_name": MODBUS_FUNCTIONS.get(function_code, "unknown"),
        }
    )
    if function_code in {1, 2, 3, 4}:
        decoded["operation"] = "device_probe"
    elif function_code in {5, 6}:
        decoded["operation"] = "write_single"
    elif function_code in {15, 16, 22, 23}:
        decoded["operation"] = "write_multiple"
    if len(payload) >= 12:
        decoded["address"] = int.from_bytes(payload[8:10], "big")
        decoded["value_or_quantity"] = int.from_bytes(payload[10:12], "big")
    return decoded


def modbus_response(payload: bytes, decoded: dict[str, Any]) -> bytes:
    """Return a bounded decoy reply. No request can affect host or physical state."""
    if len(payload) < 8 or not decoded.get("valid"):
        return b""
    transaction_id = int(decoded["transaction_id"])
    unit_id = int(decoded["unit_id"])
    function_code = int(decoded["function_code"])
    if function_code in {3, 4}:
        quantity = min(max(int(decoded.get("value_or_quantity", 1)), 1), 16)
        registers = [1200, 62, 410, 1, 0, 77, 24, 900][:quantity]
        registers.extend([0] * (quantity - len(registers)))
        pdu = bytes([function_code, quantity * 2]) + b"".join(
            value.to_bytes(2, "big") for value in registers
        )
    elif function_code in {1, 2}:
        pdu = bytes([function_code, 1, 0])
    elif function_code in {5, 6} and len(payload) >= 12:
        pdu = payload[7:12]
    else:
        pdu = bytes([function_code | 0x80, 1])
    mbap = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def parse_s7(payload: bytes) -> dict[str, Any]:
    decoded: dict[str, Any] = {"valid": False, "operation": "connection_setup"}
    if len(payload) < 4 or payload[0] != 0x03:
        decoded["error"] = "not_tpkt"
        return decoded
    declared_length = int.from_bytes(payload[2:4], "big")
    decoded.update({"valid": True, "tpkt_length": declared_length})
    if len(payload) > 5:
        decoded["cotp_pdu_type"] = hex(payload[5] & 0xF0)
    s7_offset = payload.find(b"\x32")
    if s7_offset >= 0 and len(payload) > s7_offset + 10:
        decoded["rosctr"] = payload[s7_offset + 1]
        parameter_length = int.from_bytes(payload[s7_offset + 6 : s7_offset + 8], "big")
        decoded["parameter_length"] = parameter_length
        param_start = s7_offset + 10
        if len(payload) > param_start:
            function = payload[param_start]
            decoded["s7_function"] = function
            if function in {0x1A, 0x1B, 0x1C, 0x1D}:
                decoded["operation"] = "program_download"
    return decoded


def s7_response(payload: bytes, decoded: dict[str, Any]) -> bytes:
    # ISO-on-TCP COTP Connection Confirm for connection requests only.
    if decoded.get("cotp_pdu_type") == "0xe0":
        return bytes.fromhex("0300001611d00001000100c0010ac1020100c2020102")
    return b""


IEC104_COMMAND_TYPES = set(range(45, 52)) | set(range(58, 65))


def parse_iec104(payload: bytes) -> dict[str, Any]:
    decoded: dict[str, Any] = {"valid": False, "operation": "interrogation"}
    if len(payload) < 6 or payload[0] != 0x68:
        decoded["error"] = "not_iec104_apdu"
        return decoded
    decoded.update({"valid": True, "apdu_length": payload[1]})
    control = payload[2:6]
    if control[0] & 0x01 == 0:
        decoded["frame_type"] = "I"
        if len(payload) > 6:
            type_id = payload[6]
            decoded["type_id"] = type_id
            if type_id in IEC104_COMMAND_TYPES:
                decoded["operation"] = "single_command" if type_id in {45, 46, 47, 58, 59, 60} else "setpoint_command"
    elif control[0] & 0x03 == 1:
        decoded["frame_type"] = "S"
    else:
        decoded["frame_type"] = "U"
        decoded["u_function"] = hex(control[0])
        decoded["operation"] = "connection_setup"
    return decoded


def iec104_response(payload: bytes, decoded: dict[str, Any]) -> bytes:
    if decoded.get("frame_type") == "U" and decoded.get("u_function") == "0x7":
        return bytes.fromhex("68040b000000")  # STARTDT confirmation
    return b""

