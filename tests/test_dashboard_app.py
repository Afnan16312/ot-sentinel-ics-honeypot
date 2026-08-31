from pathlib import Path

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_renders_the_interactive_map_workspace_without_exceptions():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()

    assert not app.exception
    assert [tab.label for tab in app.tabs] == [
        "Observatory",
        "ATT&CK Analysis",
        "Detection Preview",
        "Triage",
        "Session Explorer",
        "Methodology",
    ]
    selectbox_labels = [item.label for item in app.selectbox]
    assert selectbox_labels[:2] == ["Map mode", "Observation window"]
    assert {"Inspect map observation", "Technique focus", "Source group focus"}.issubset(
        selectbox_labels
    )
    assert {
        "Control actions only",
        "Place labels",
        "Observation paths",
        "Group review queue by session",
    }.issubset({item.label for item in app.toggle})
    assert "Export visible map summary" in [
        item.label for item in app.get("download_button")
    ]
    assert "Map observations to compare" in [item.label for item in app.multiselect]
    assert "Export" in [item.label for item in app.get("download_button")]
    assert any("Current dashboard filters" in item.value for item in app.markdown)
    assert "Global observation map" in app.markdown[4].value or any(
        "Global observation map" in item.value for item in app.markdown
    )
    rendered_markdown = "\n".join(item.value for item in app.markdown)
    assert "Number of events matching the selected filters" in rendered_markdown
    assert "Unique pseudonymous source groups" in rendered_markdown
    assert "Countries represented by the filtered" in rendered_markdown
    assert "Different OT protocols present" in rendered_markdown
    assert "Data &amp; privacy context" in rendered_markdown
    assert "Publication-validated public dataset" in rendered_markdown
    assert "Approximate geography" in rendered_markdown
    assert "No raw IPs or payloads" in rendered_markdown
    assert rendered_markdown.count("<details class='metric-info'>") >= 8
    assert "white-space:normal" in rendered_markdown
    assert "overflow-wrap:anywhere" in rendered_markdown
    assert "Several records can come from one session" in rendered_markdown
    assert "Detection Preview" in rendered_markdown
    assert "Detection coverage backlog" in rendered_markdown
    assert "STIX" in rendered_markdown
    assert "What the Observatory can and cannot prove" in [
        item.label for item in app.expander
    ]
    assert "Guided investigation path" in [item.label for item in app.expander]
    assert "What Detection Preview can and cannot prove" in [
        item.label for item in app.expander
    ]
    metrics = {item.label: item.value for item in app.metric}
    assert metrics["Native Wazuh fixture"] == "Passed"
    assert metrics["Native Suricata fixture"] == "Passed"
    assert any("evidence completeness" in item.value.lower() for item in app.caption)
    assert "Reset workspace" in [item.label for item in app.button]
    assert {
        "Prepare lead source in Session Explorer",
        "Prepare ATT&CK evidence review",
    }.issubset({item.label for item in app.button})


def test_time_and_density_modes_render_without_exceptions():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()

    app.selectbox(key="map_mode").select("Density").run()
    assert not app.exception

    app.selectbox(key="map_mode").select("Time playback").run()
    app.selectbox(key="map_window").select("Last 7 days").run()
    assert not app.exception


def test_map_display_controls_and_camera_reset_render_without_exceptions():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()

    app.toggle(key="map_labels").set_value(True).run()
    app.toggle(key="map_flows").set_value(False).run()
    next(button for button in app.button if button.label == "Reset camera").click().run()

    assert not app.exception


def test_custom_window_and_offline_map_fallback_render_without_exceptions():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()

    app.selectbox(key="map_window").select("Custom UTC range").run()
    assert not app.exception


def test_investigation_filters_and_manifest_are_available():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()

    app.toggle(key="filter_control_only").set_value(True).run()

    assert not app.exception


def test_session_first_triage_can_switch_to_event_rows():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()

    app.toggle(key="triage_group_sessions").set_value(False).run()

    assert not app.exception


def test_reset_workspace_restores_defaults_and_preserves_notes():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    app.session_state["local_review_note_synthetic"] = "keep this note"
    app.selectbox(key="map_mode").select("Density").run()
    app.toggle(key="filter_control_only").set_value(True).run()

    app.button(key="reset_workspace").click().run()

    assert not app.exception
    assert app.selectbox(key="map_mode").value == "Flow view"
    assert not app.toggle(key="filter_control_only").value
    assert app.session_state["local_review_note_synthetic"] == "keep this note"


def test_accessible_source_selection_shows_public_review_context():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()

    source_selector = app.selectbox(key="map_accessible_source")
    source_selector.select(source_selector.options[1]).run()

    assert not app.exception
    rendered_markdown = "\n".join(item.value for item in app.markdown)
    assert "Public review score" in rendered_markdown
    assert "Why this public score is ranked" in rendered_markdown
    assert "Recommended next step" in rendered_markdown
    assert "Export view manifest" in [item.label for item in app.get("download_button")]
    app.selectbox(key="map_mode").select("Source bubbles").run()
    app.checkbox(key="map_offline").set_value(True).run()

    assert not app.exception


def test_empty_global_filter_has_a_safe_explainable_state():
    app = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()

    app.multiselect(key="filter_protocols").set_value([]).run()

    assert not app.exception
    assert any(
        "No safely mappable observations" in item.value for item in app.info
    )
    export = next(
        item for item in app.get("download_button") if item.label == "Export visible map summary"
    )
    assert export.disabled
