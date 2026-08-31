from ot_sentinel.operator_assurance import assurance_from_snapshot, load_operator_assurance


def test_operator_assurance_reports_safe_states_without_private_fields():
    result = assurance_from_snapshot(
        {"status": "ok", "total_events": 12, "collector_storage_ready": True, "source_ip": "192.0.2.1"}
    )
    assert result.state == "reported healthy"
    assert result.storage_state == "ready"
    assert "192.0.2.1" not in str(result.to_dict())


def test_load_operator_assurance_ignores_unapproved_health_fields(tmp_path):
    path = tmp_path / "health.json"
    path.write_text('{"status":"ok","source_ip":"192.0.2.1","raw_payload_hex":"private"}', encoding="utf-8")
    result = load_operator_assurance(path)
    assert result is not None
    assert result.state == "reported healthy"
    assert "private" not in str(result.to_dict())
