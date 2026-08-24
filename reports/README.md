# Reports

The current publication is a **demonstration research brief** built from deterministic synthetic data. It documents the architecture, evidence model, privacy controls and live-research plan without presenting simulated events as observed attacks.

- [OT Sentinel demonstration research brief (PDF)](../output/pdf/ot-sentinel-demonstration-report.pdf)
- [Synthetic weekly Markdown example](examples/weekly-demo.md)

`scripts/generate_report.py` reads the private/privacy-reduced SQLite index for a reproducible window ending at `--as-of`. Observed output defaults to ignored `reports/private/` and is never published automatically. The Markdown brief counts repeats, lists confidence distributions and states that source pseudonyms do not identify people and ATT&CK mappings do not prove intent or compromise.

After the authorized two-to-four-week collection window, the same pipeline will produce an observed-data edition with an exact date range, sensor uptime, sanitized results and revised limitations.
