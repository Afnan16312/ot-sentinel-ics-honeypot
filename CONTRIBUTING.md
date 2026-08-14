# Contributing

Contributions are welcome when they preserve the low-interaction safety model.

1. Do not add shell execution, uploaded-file execution, attacker callbacks or active response.
2. Add protocol fixtures and tests for parser changes.
3. Keep ATT&CK mappings evidence-qualified and include confidence plus rationale.
4. Never commit raw telemetry, real IP addresses, secrets or GeoIP database files.
5. Run `python -m unittest discover -s tests -v` before opening a pull request.

