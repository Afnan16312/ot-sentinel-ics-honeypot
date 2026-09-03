from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_graphify_excludes_private_and_generated_state():
    exclusions = (ROOT / ".graphifyignore").read_text(encoding="utf-8")
    for path in (
        "data/",
        "logs/",
        "reports/private/",
        "exports/private/",
        "tests/soc/vendor/",
        "tests/soc/staging/",
        ".venv/",
        "graphify-out/",
    ):
        assert path in exclusions

    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "graphify-out/" in gitignore
    assert "graph.json" in gitignore


def test_graphify_guidance_is_portable_and_local_first():
    guidance = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    documentation = (ROOT / "docs" / "DEVELOPER_ASSISTANTS.md").read_text(
        encoding="utf-8"
    )

    assert "graphify query" in guidance
    assert "--code-only" in guidance
    assert "C:\\Users\\" not in guidance
    assert "--code-only" in documentation
    assert "without an API key or cloud model" in documentation
