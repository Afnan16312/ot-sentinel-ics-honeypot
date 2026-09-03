# Five-Minute Demonstration Script

This short speaking outline is complemented by the exact [Synthetic Walkthrough Recording Checklist](RECORDING_CHECKLIST.md). The checklist is authoritative for a public 5–7 minute recording, native SOC prerequisites and frame-by-frame privacy review. No video is currently claimed.

## 1. Explain the problem

“Industrial systems use protocols such as Modbus, S7 and IEC-104. OT Sentinel safely simulates limited services so I can study network behavior without connecting to real machinery.”

## 2. Show the architecture

Open the architecture diagram in the README. Explain the path: decoy listener, structured evidence, ATT&CK mapping, privacy filter, dashboard and defender outputs.

## 3. Show the dashboard

Run `run_dashboard.ps1`. Point out the permanent synthetic-data notice, protocol totals, timeline, ATT&CK layer and session explorer. Explain that the world map is illustrative synthetic data, not a map of confirmed attackers.

## 4. Show security evidence

Open the collector tests and explain that signed valid events are accepted while invalid signatures, unknown sensors, replayed events, malformed bodies and oversized requests are rejected. Mention that the complete suite runs automatically in GitHub Actions.

## 5. Show SOC outputs

Open `detections/` and explain that the same normalized fields support tested Sigma, Wazuh and Suricata rules. Emphasize that a connection alone does not trigger an exploitation alert.

## 6. Explain the live-study boundary

“A separate isolated Oracle sensor collects private evidence. It does not publish raw telemetry to GitHub or Streamlit. The public dashboard stays synthetic until a reviewed aggregate report is approved.”

## 7. Close with what you learned

“This project taught me industrial protocols, safe deception, cloud isolation, privacy engineering, ATT&CK mapping, detection testing, API security and operational documentation.”
