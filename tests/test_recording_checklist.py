from pathlib import Path


def test_recording_checklist_is_exact_and_honest():
    text = (
        Path(__file__).resolve().parents[1] / "docs" / "RECORDING_CHECKLIST.md"
    ).read_text(encoding="utf-8")
    for required in (
        "6 minutes 15 seconds",
        "Repository and architecture",
        "Streamlit dashboard",
        "ATT&CK Navigator",
        "Collector security",
        "Native Wazuh and Suricata evidence",
        "GitHub Actions",
        "Human action remaining",
        "Do not add a public video link",
    ):
        assert required in text
    assert "recording still required" in text
