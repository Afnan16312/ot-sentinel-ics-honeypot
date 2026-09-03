from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.soc.generate_pcap import archive_previous_output
from tests.soc.inject_alert import NEGATIVES, POSITIVE, run_logtest, verify_outputs
from tests.soc.verify_suricata import verify

ROOT = Path(__file__).resolve().parents[1]


def test_compose_binds_declared_ports_to_loopback_only():
    compose = (ROOT / "tests" / "soc" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "0.0.0.0:" not in compose
    for port in (1514, 1515, 5601, 9200, 55000):
        assert f'"127.0.0.1:{port}:' in compose


def test_wazuh_fixtures_are_synthetic_and_evidence_specific():
    assert POSITIVE["decoded"] == {"operation": "write_single", "function_code": 6}
    assert all(event["is_demo"] is True for event in [POSITIVE, *NEGATIVES])
    assert NEGATIVES[0]["event_type"] == "connection"
    assert NEGATIVES[1]["decoded"]["function_code"] == 3


def test_wazuh_historical_ingestion_is_local_private_and_fixed_file():
    compose = (ROOT / "tests" / "soc" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    localfile = (ROOT / "tests" / "soc" / "wazuh-localfile.conf").read_text(
        encoding="utf-8"
    )
    assert "./staging:/var/ossec/logs/ot-sentinel:ro" in compose
    assert "./generated/wazuh_manager.conf" in compose
    assert "/var/ossec/logs/ot-sentinel/events.jsonl" in localfile
    assert "*.jsonl" not in localfile
    assert "oracle" not in localfile.lower()


def test_wazuh_logtest_runner_and_result_parser():
    def runner(command, **kwargs):
        assert command[-1] == "/var/ossec/bin/wazuh-logtest"
        assert '"write_single"' in kwargs["input"]
        return subprocess.CompletedProcess(command, 0, "id: '110001'\n", "")

    positive = run_logtest(POSITIVE, runner=runner)
    verify_outputs(positive, ["id: '110000'", "id: '110000'"])


def test_wazuh_parser_rejects_false_positive():
    with pytest.raises(AssertionError, match="harmless"):
        verify_outputs("id: '110001'", ["id: '110001'"])


def test_suricata_result_parser_requires_write_and_quiet_read(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(
        '{"event_type":"alert","src_port":41000,"alert":{"signature_id":4200501}}\n',
        encoding="utf-8",
    )
    verify(eve)

    eve.write_text(
        '{"event_type":"alert","src_port":42000,"alert":{"signature_id":4200501}}\n',
        encoding="utf-8",
    )
    with pytest.raises(AssertionError):
        verify(eve)


def test_suricata_previous_output_is_archived_without_overwrite(tmp_path):
    eve = tmp_path / "eve.json"
    content = b'{"event_type":"alert"}\n'
    eve.write_bytes(content)

    first = archive_previous_output(eve)
    assert first is not None
    assert first.read_bytes() == content
    assert not eve.exists()

    eve.write_bytes(content)
    second = archive_previous_output(eve)
    assert second is not None
    assert second != first
    assert second.read_bytes() == content
    assert first.read_bytes() == content
    assert not eve.exists()


def test_suricata_uses_the_writable_mounted_output_directory():
    config = (ROOT / "tests" / "soc" / "suricata.yaml").read_text(encoding="utf-8")
    assert "default-log-dir: /output" in config
    assert "classification-file: /etc/suricata/classification.config" in config
    assert "reference-config-file: /etc/suricata/reference.config" in config
    assert "threshold-file: /etc/suricata/threshold.config" in config

    compose = (ROOT / "tests" / "soc" / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    assert "./classification.config:/etc/suricata/classification.config:ro" in compose
    assert "./reference.config:/etc/suricata/reference.config:ro" in compose
    assert "./threshold.config:/etc/suricata/threshold.config:ro" in compose
