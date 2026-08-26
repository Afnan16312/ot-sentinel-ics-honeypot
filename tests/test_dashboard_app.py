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
    assert [item.label for item in app.selectbox] == ["Map mode", "Observation window"]
    assert [item.label for item in app.toggle] == ["Place labels", "Observation paths"]
    assert "Export visible map summary" in [
        item.label for item in app.get("download_button")
    ]
    assert "Export" in [item.label for item in app.get("download_button")]
    assert any("Current dashboard filters" in item.value for item in app.markdown)
    assert "Global observation map" in app.markdown[4].value or any(
        "Global observation map" in item.value for item in app.markdown
    )


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
