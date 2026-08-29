import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from ot_sentinel.sensor import JsonlWriter, LowInteractionSensor


class SensorIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_configured_payload_limit_cannot_exceed_512_bytes(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "hard 512-byte limit"),
        ):
            LowInteractionSensor(
                host="127.0.0.1",
                ports={"modbus": 0},
                writer=JsonlWriter(Path(directory) / "events.jsonl"),
                sensor_id="integration-test",
                max_payload=513,
            )

    async def test_modbus_request_creates_bounded_events_and_reply(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "events.jsonl"
            sensor = LowInteractionSensor(
                host="127.0.0.1",
                ports={"modbus": 0},
                writer=JsonlWriter(log_path),
                sensor_id="integration-test",
                timeout=2,
            )
            await sensor.start()
            port = sensor.servers[0].sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(bytes.fromhex("000100000006010300000003"))
            await writer.drain()
            response = await asyncio.wait_for(reader.read(64), timeout=2)
            self.assertEqual(response[7], 3)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.05)
            for server in sensor.servers:
                server.close()
                await server.wait_closed()

            events = [json.loads(line) for line in log_path.read_text().splitlines()]
            self.assertEqual([event["event_type"] for event in events], ["connection", "protocol_request"])
            self.assertLessEqual(len(events[1]["raw_payload_hex"]), 1024)
            ids = {item["technique_id"] for item in events[1]["techniques"]}
            self.assertEqual(ids, {"T0846.001", "T0877"})


if __name__ == "__main__":
    unittest.main()
