# Synthetic Walkthrough Recording Checklist

Status: **human recording still required**. This checklist is the deliverable that can be prepared safely in the development environment. Do not add a public video link until the finished recording has passed the final review below.

Target length: **6 minutes 15 seconds** (acceptable range: 5–7 minutes). Use only the committed synthetic dataset and synthetic test output.

## 1. Prerequisites—do not record until all are true

- The `feature/phase-2-enhancements` branch is pushed and its GitHub Actions checks are green.
- The public dashboard starts from `data/demo_events.jsonl` and visibly says **DEMONSTRATION DATA**.
- `exports/ot-sentinel-demo-layer.json` is open in ATT&CK Navigator and labeled synthetic.
- Native Wazuh `wazuh-logtest` output proves rule `110001` fires only for the synthetic Modbus write fixture; the connection-only and read fixtures remain quiet.
- Native Suricata `-T` passes and offline PCAP processing produces SID `4200501` only for the synthetic write flow; the read flow remains quiet.
- Any native SOC screenshots have been reviewed to ensure they contain no hostnames, user names, local paths, container credentials, addresses or terminal history.

If the native SOC evidence is not available, stop. Do not replace it with mocked/static-test output or describe it as native proof.

## 2. Prepare a safe recording workspace

1. Close Oracle Cloud, SSH, email, messaging, password managers and unrelated browser tabs.
2. Disable desktop notifications and hide the taskbar if it contains personal information.
3. Use window capture—not whole-desktop capture—for the browser, editor and dashboard.
4. Open a fresh terminal in the repository. Clear the screen and use only the commands listed below; never show shell history.
5. Confirm the dashboard source is `data/demo_events.jsonl`. Do not set a path to observed data.
6. Open these public files in advance: `README.md`, `docs/ARCHITECTURE.md`, `exports/ot-sentinel-demo-layer.json`, `tests/test_collector_blackbox.py`, and `tests/soc/README.md`.
7. Prepare two cropped, reviewed native-lab evidence images: one Wazuh result and one Suricata result. Do not show a terminal prompt or filesystem path.

## 3. Exact 6:15 storyboard

### 0:00–0:35 — Problem and honesty boundary

Show the top of `README.md`.

Say: “OT Sentinel is a low-interaction industrial-system honeypot for simulated Modbus, S7 and IEC-104 services. The public dashboard uses deterministic synthetic events. Private observations are never shown in this demonstration, and a connection alone is not called exploitation.”

### 0:35–1:20 — Repository and architecture

Show the repository folders, then the architecture section.

Point out: sensor, canonical JSONL evidence, optional private SQLite indexes, evidence-qualified ATT&CK mapping, shared publication gate, Streamlit, defender rules and tests. State that JSONL remains authoritative when forwarding fails.

### 1:20–2:35 — Streamlit dashboard

Start before recording or from a cleared terminal:

```powershell
./run_dashboard.ps1
```

Show the synthetic banner, protocol totals, world-map explanation, ATT&CK view and **Detection Preview**. Apply one engine filter. Say that Detection Preview is an offline prediction and not native-engine proof. Do not open browser developer tools or display environment variables.

### 2:35–3:15 — ATT&CK Navigator

Show `exports/ot-sentinel-demo-layer.json` in ATT&CK Navigator. Explain that scores sum repeat counts from a deterministic synthetic SQLite fixture, mappings remain hypotheses, and the layer contains no source/session identifiers or payloads.

### 3:15–4:05 — Collector security and publication controls

Show the relevant collector black-box test names and the shared publication tests. If a terminal result is shown, run only:

```powershell
python -m pytest -q tests/test_collector_blackbox.py tests/test_publication.py
```

Mention valid HMAC acceptance, invalid/missing authentication rejection, timestamp freshness, durable replay rejection, request limits, storage-safe retry, recursive credential removal, mixed-provenance rejection and the independent public-STIX gate.

### 4:05–5:05 — Native Wazuh and Suricata evidence

Show the two pre-reviewed cropped evidence images. State the pinned versions and exact fixtures. Explain that the Modbus write triggers Wazuh rule `110001` and Suricata SID `4200501`, while a connection-only event and harmless Modbus read do not. Do not show Compose credentials, container logs beyond the reviewed result, or any cloud terminal.

### 5:05–5:40 — GitHub Actions

Show the successful check summary for the feature branch. Point out pytest, Ruff, dependency audit, public-data validation, detection validation, OpenAPI 3.1 validation, generated-data reproducibility and supply-chain checks. Do not show account settings, tokens or workflow secrets.

### 5:40–6:15 — Close

Say: “This project demonstrates safe OT protocol simulation, privacy-aware telemetry handling, cautious ATT&CK mapping, authenticated collection, durable delivery, detection engineering and reproducible security testing. It does not claim compromise, attribution, regulatory compliance or a completed two-to-four-week threat study.”

## 4. Final frame-by-frame review

Watch the complete recording at normal speed and again while pausing on every terminal/browser transition. Reject and rerecord if any frame shows:

- a public or private address, network prefix, OCID or cloud resource identifier;
- an SSH key, signature, secret, credential, token, environment variable or Compose password;
- raw payload content, observed event rows or private logs;
- a personal filesystem path, user name, terminal history or unrelated notification;
- Oracle Cloud, live Streamlit data or an unreviewed SOC console;
- wording that calls a TCP connection exploitation or presents ATT&CK hypotheses as proven intent.

Confirm the video is 5–7 minutes, audio is understandable, synthetic labels are readable and native evidence is genuine. Only then upload it, review the hosted copy once more, and add the approved public URL to `README.md` in a separate reviewed change.

## 5. Human action remaining

The project owner must run the native SOC lab on a machine meeting its documented requirements, capture and redact authoritative evidence, record the walkthrough, review every frame, upload the approved video, and add its URL. No recording or public video URL was produced automatically.
