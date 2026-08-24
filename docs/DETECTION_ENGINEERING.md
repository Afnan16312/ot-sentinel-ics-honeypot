# Detection engineering pack

This pack turns OT Sentinel observations into rules that defenders can use in three common security tools. It is deliberately separate from the honeypot: the sensor records evidence, while the detection rules decide which evidence deserves an alert.

The pack works locally and costs nothing. Its built-in validator uses only the Python standard library.

## What is detected

| Behavior | Evidence required | ATT&CK for ICS | Sigma | Wazuh | Suricata |
|---|---|---|---|---|---|
| Modbus write | `protocol=modbus` and a decoded single or multiple write | T1692.001, T0836 | Yes | Yes | Native `modbus: access write` |
| IEC-104 control command | A decoded single or setpoint command | T1692.001, T0836 | Yes | Yes | No |
| S7 program transfer | A decoded `program_download` operation | T0843 | Yes | Yes | No |
| Exploit probe | `known_exploit_probe` plus a recorded signature name | T0866 | Yes | Yes | No |
| Modbus broadcast write | Unit 0 plus a write | T1692.001 | No | No | Native unit and access match |
| Unassigned Modbus function | Suricata classifies the function as unassigned | T0846.001 hypothesis | No | No | Native function-class match |
| Modbus function 43 | Encapsulated Interface Transport request, which can include device identification | T0846.001 hypothesis | No | No | Native function-code match |

A TCP connection by itself does not trigger these alert rules. This prevents an ordinary port connection from being mislabeled as exploitation.

## Files

```text
detections/
├── fixtures/events.jsonl
├── sigma/
│   ├── ot_sentinel_iec104_control_command.yml
│   ├── ot_sentinel_known_exploit_probe.yml
│   ├── ot_sentinel_modbus_write.yml
│   └── ot_sentinel_s7_program_download.yml
├── suricata/ot_sentinel_modbus.rules
└── wazuh/ot_sentinel_rules.xml
```

`scripts/validate_detections.py` performs structural checks, detects duplicate identifiers and evaluates every rule against declared positive and negative fixtures. `tests/test_detections.py` adds regression checks for evidence requirements and Modbus rule behavior.

The Streamlit **Detection Preview** reuses these offline matchers to show rule ID, title, severity, ATT&CK mapping and a safe evidence reason for sanitized events. It is labeled an offline prediction and is never presented as native-engine output. Connection-only and normal-read cases remain free of high-severity predictions.

## Run the offline validation

From the repository root:

```powershell
.\.venv\Scripts\python.exe scripts\validate_detections.py
.\.venv\Scripts\python.exe -m unittest tests.test_detections -v
```

On Linux or macOS, replace `.\.venv\Scripts\python.exe` with the Python executable in your environment.

A successful run reports four Sigma rules, four Suricata rules, four Wazuh alert rules and ten fixtures. Three fixtures are intentionally negative: a connection-only event, a normal S7 connection setup and an exploit label without signature evidence.

## Use the Sigma rules

The Sigma files describe detections over OT Sentinel's normalized JSON fields. A SIEM must ingest the JSON and map the dotted names, such as `decoded.operation`, without changing their meaning.

Sigma is a portable rule format rather than an alert engine. Use a Sigma-compatible converter for the SIEM being tested, then inspect the generated query before using it. Field mapping differs between Elastic, Microsoft Sentinel, Splunk and other backends.

The rules follow the official [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html). The repository validator covers this project's supported subset; a Sigma CLI/schema validation should also be run in the destination environment.

## Use the Suricata rules

The rules inspect packets independently from OT Sentinel's JSON pipeline. They use Suricata's native `modbus` keyword instead of raw byte offsets, which makes their intent easier to review.

1. Copy `detections/suricata/ot_sentinel_modbus.rules` to the Suricata rules directory.
2. Add the file to `rule-files` in `suricata.yaml`.
3. Set `$HOME_NET` to the protected or decoy network.
4. If the sensor uses the local demonstration port `1502`, change destination port `502` in the four rules for that test environment.
5. Test the complete Suricata configuration before starting live capture:

```bash
suricata -T -c /etc/suricata/suricata.yaml
```

The Python validator checks identifiers and intended matching behavior, but `suricata -T` remains the authoritative engine syntax check. Suricata documents the supported function, access and unit syntax in its [Modbus keyword guide](https://docs.suricata.io/en/suricata-8.0.0/rules/modbus-keyword.html).

The disposable `tests/soc/` lab pins Suricata 8.0.4, runs alert-only/offline PCAP processing and verifies that the synthetic Modbus write produces SID `4200501` while the harmless read remains quiet. Docker is not installed in the current development environment, so that native output is still required before the lab is called validated.

The broadcast and function 43 alerts may be normal in some industrial networks. Tune them against an approved asset and communication baseline before enabling operational notifications.

## Use the Wazuh rules

Wazuh includes a JSON decoder, so a complete OT Sentinel JSON event can be analyzed directly.

1. Copy `detections/wazuh/ot_sentinel_rules.xml` to `/var/ossec/etc/rules/` on the Wazuh manager.
2. Test representative JSON lines with `/var/ossec/bin/wazuh-logtest`.
3. Restart the Wazuh manager only after the test succeeds.

The parent rule has level 0 and groups OT Sentinel events without alerting. Four child rules generate alerts only when their complete field conditions match. The IDs use Wazuh's documented custom range of 100000–120000.

The child rules include ATT&CK for ICS IDs. Confirm that the Wazuh manager's bundled MITRE database recognizes those IDs during `wazuh-logtest`; database coverage varies by Wazuh release. The field conditions and `ot_sentinel` rule groups still identify the alert independently of the dashboard's MITRE enrichment.

The disposable `tests/soc/` Compose harness extends the official Wazuh 4.14.7 single-node manager/indexer/dashboard stack, binds host services to loopback and mounts the custom rules read-only. Its injector requires rule `110001` for the synthetic write and no child alert for connection/read negatives. Native output is pending because Docker is unavailable locally.

See Wazuh's official guidance for the [JSON decoder](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html), [custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) and [rule field syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).

## Fixture design

Each JSONL fixture contains:

- `case_id`: a stable test name;
- `event`: normalized OT Sentinel fields plus optional semantic Modbus fields for packet-rule tests;
- `expected.sigma`: matching Sigma filenames without `.yml`;
- `expected.wazuh`: matching alert rule IDs;
- `expected.suricata`: matching signature IDs.

The `modbus` fixture object represents Suricata's decoded packet properties; it is test metadata and is not added to public OT Sentinel events.

When adding a rule, add at least one positive fixture. Also add a negative fixture for the closest harmless behavior. This makes rule intent reviewable and helps prevent quiet changes that create alert noise.

## Operational safety and tuning

- Start in alert-only mode. These rules do not authorize blocking industrial traffic.
- Use them only on networks and sensors you are permitted to monitor.
- Keep raw packet data private and follow the project's publication sanitizer before sharing events.
- Treat ATT&CK labels as evidence-backed analytical hypotheses, not attribution.
- Allow-list planned maintenance sources only after the asset owner approves the exception.
- Measure alert volume and false positives before connecting email, ticketing or webhook notifications.
- Record every tuning decision in version control with a positive and negative test case.

The rules are a portfolio-quality starting point, not a substitute for site-specific process knowledge, asset inventories, change windows or safety engineering.
