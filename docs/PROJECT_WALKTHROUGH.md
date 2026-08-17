# OT Sentinel: My Project Walkthrough

**Project author:** Mir Afnan Ali  
**GitHub profile:** https://github.com/Afnan16312  
**Repository:** https://github.com/Afnan16312/ot-sentinel-ics-honeypot

This document explains my OT Sentinel project in simple language. I can use it to prepare for a demonstration, presentation or technical interview.

## 1. The project in one sentence

OT Sentinel is a safe industrial-system decoy that records activity aimed at simulated Modbus, Siemens S7 and IEC-104 services, maps supported behavior to MITRE ATT&CK for ICS, removes sensitive data and displays the results in a dashboard.

## 2. The problem I wanted to address

Industrial control systems, often called OT or ICS, operate important services such as electricity, water treatment, factories and ports. Exposing a real industrial controller to unknown internet users would be dangerous.

I therefore built a low-interaction honeypot. It looks like a small part of an industrial system, but it does not control real equipment. Its purpose is to safely observe what visitors try to do.

## 3. What a honeypot means

A honeypot is a decoy system. It is intentionally made visible so that scans and suspicious requests can be recorded for study.

My honeypot is low interaction. This means it understands and replies to a limited set of protocol messages, but it does not provide a full operating system, command shell or real PLC programming environment. This reduces risk.

## 4. The complete information flow

```text
Internet scanner or test client
              |
              v
Simulated Modbus, S7 or IEC-104 service
              |
              v
Private structured JSON event
              |
              v
Protocol normalizer and behavior analysis
              |
              v
MITRE ATT&CK for ICS mapper
              |
              v
Privacy sanitizer
              |
              v
Public dashboard and research report
```

## 5. How it works step by step

### Step 1: The sensor waits for connections

The Python sensor opens three network listeners:

| Protocol | Local demonstration port | Standard deployment port |
|---|---:|---:|
| Modbus/TCP | 1502 | 502 |
| Siemens S7 / ISO-on-TCP | 1102 | 102 |
| IEC-104 | 2404 | 2404 |

These protocols are commonly associated with industrial automation, PLC communication, utilities and process control.

### Step 2: The sensor reads a bounded request

When a client connects, the sensor reads only a limited amount of data. It does not accept unlimited uploads and does not execute operating-system commands.

### Step 3: The protocol parser identifies the request

The parser checks the safe parts of each protocol message. For example, it can distinguish a Modbus read request from a Modbus write request.

### Step 4: A structured event is created

The event is stored as JSON. Important fields include time, protocol, session identifier, action, severity and decoded protocol details.

### Step 5: Behavior is mapped to ATT&CK for ICS

MITRE ATT&CK for ICS is a common language for describing behavior against industrial environments. My mapper uses evidence from the protocol request and adds a confidence level and explanation.

Examples include:

- A protocol-aware scan can support `T0846.001 Remote System Discovery: Port Scan`.
- A Modbus state read can support a low-confidence `T0877 I/O Image` hypothesis.
- A write command can support `T1692.001 Unauthorized Message: Command Message` and `T0836 Modify Parameter`.
- A program-transfer operation can support `T0843 Program Download`.
- A normal connection by itself is not automatically called an exploit.

### Step 6: Sensitive information is removed

Before events are suitable for publication, the privacy layer:

- replaces source IP addresses with salted pseudonyms;
- removes raw network payloads;
- removes decoded fields that could contain credentials;
- keeps only the information needed for analysis.

### Step 7: The dashboard displays the results

The Streamlit dashboard provides five main views:

1. **Observatory:** overview, source distribution, technique summaries and activity timeline.
2. **ATT&CK Layer:** technique intensity separated by industrial protocol.
3. **Triage & Validation:** explainable event priority, review queue and mapper test results.
4. **Session Explorer:** sanitized event records for detailed investigation.
5. **Methodology:** an explanation of what the sensor can and cannot prove.

## 6. What the current dashboard data means

The public dashboard contains 420 deterministic synthetic events. They are computer-generated demonstration records, not claimed as real attacks.

The demonstration currently shows:

- 420 protocol events;
- 418 distinct sessions;
- 10 pseudonymous sources;
- 146 control attempts;
- examples covering Modbus, S7 and IEC-104.

Synthetic data lets anyone reproduce the dashboard and test the complete pipeline without exposing personal information or inventing claims about real attackers.

## 7. Safety decisions I made

- The sensor never connects to a real PLC, HMI or industrial process.
- It provides limited simulated replies only.
- It does not provide a shell or execute received commands.
- Payload capture is bounded.
- Public data excludes raw IP addresses and payloads.
- The project does not retaliate or attempt to identify people.
- ATT&CK mappings are hypotheses, not proof of compromise or attribution.
- The project is not presented as proof of NESA compliance.

## 8. Important project files

| File or folder | What it does |
|---|---|
| `app.py` | Builds the Streamlit dashboard |
| `run_dashboard.ps1` | Starts the dashboard on Windows |
| `src/ot_sentinel/sensor.py` | Runs the three safe protocol listeners |
| `src/ot_sentinel/protocols.py` | Parses bounded protocol messages |
| `src/ot_sentinel/mapper.py` | Maps evidence to ATT&CK for ICS |
| `src/ot_sentinel/privacy.py` | Sanitizes events for publication |
| `src/ot_sentinel/normalizer.py` | Converts events into one consistent format |
| `src/ot_sentinel/stix_export.py` | Exports public or private STIX 2.1 bundles |
| `src/ot_sentinel/triage.py` | Calculates an explainable review priority |
| `src/ot_sentinel/collector.py` | Authenticates events from optional remote sensors |
| `profiles/` | Contains fictional water, power and port device profiles |
| `detections/` | Contains Sigma, Suricata and Wazuh rules |
| `data/demo_events.jsonl` | Contains the synthetic demonstration dataset |
| `tests/` | Contains automated unit and integration tests |
| `infra/azure/` | Contains optional Azure deployment and cleanup files |
| `docker-compose.yml` | Runs the sensor in a hardened container |
| `output/pdf/` | Contains the demonstration research report |

## 9. How I run the dashboard on Windows

Open PowerShell and run:

```powershell
cd "C:\path\to\ot-sentinel-ics-honeypot"
.\run_dashboard.ps1
```

If Windows blocks local scripts:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_dashboard.ps1
```

Then open:

```text
http://localhost:8501
```

I stop a dashboard launched in my terminal by pressing `Ctrl+C`.

## 10. A simple five-minute demonstration

### Minute 1: Explain the problem

“Industrial control systems operate important services. I wanted a safe way to study traffic aimed at industrial protocols without exposing real equipment.”

### Minute 2: Explain the architecture

“The sensor simulates Modbus, S7 and IEC-104. It writes structured events, maps supported behavior to ATT&CK for ICS, sanitizes sensitive fields and sends the public data to the dashboard.”

### Minute 3: Show the dashboard

Show the event count, world map and timeline. Clearly point out the demonstration-data notice.

### Minute 4: Show the analysis

Open the ATT&CK Layer and Session Explorer. Select an event and explain that the mapping contains evidence, confidence and rationale.

### Minute 5: Show engineering quality

Open the GitHub repository and show the tests, GitHub Actions result, ethics policy, Docker files and Azure deployment template.

## 11. My short explanation

“I built OT Sentinel, a low-interaction ICS honeypot that safely simulates Modbus, Siemens S7 and IEC-104 services. It records protocol-level activity, maps evidence-supported behavior to MITRE ATT&CK for ICS, removes sensitive information and visualizes the results in a Streamlit dashboard. The public version uses clearly labeled synthetic data so the complete pipeline can be demonstrated responsibly.”

## 12. My longer explanation

“The project has a collection layer, an analysis layer, a privacy layer and a presentation layer. The collection layer provides bounded industrial-protocol listeners. The analysis layer normalizes requests and maps supported behavior to ATT&CK for ICS with confidence and rationale. The privacy layer pseudonymizes addresses and removes payloads. Finally, the presentation layer shows sanitized trends and events in Streamlit. I also included tests, Docker configuration, Azure infrastructure files, deployment cleanup, ethics documentation and a research report.”

## 13. Questions I may be asked

### Is the current data real?

No. The public dashboard currently uses clearly labeled synthetic data. The architecture is ready for an authorized collection period, but I do not present demonstration events as real attackers.

### Why did you use a low-interaction design?

It limits the attack surface. The sensor can record useful protocol behavior without providing a full system that an attacker could take over.

### Why map events to MITRE ATT&CK?

ATT&CK provides consistent technique names that analysts and security teams understand. It makes the observations easier to compare and communicate.

### Does an open-port connection prove an attack?

No. A connection may be a normal scan. My mapper requires stronger protocol evidence before adding stronger technique hypotheses.

### Can the IP address identify the attacker?

No. IP geolocation is approximate and may represent a cloud host, proxy or compromised system. The project avoids personal attribution.

### Is this a NESA compliance assessment?

No. It is security research tooling designed with the UAE critical-infrastructure context in mind. It does not certify regulatory compliance.

### How did I test it?

The project contains unit and integration tests for protocol parsing, privacy, profiles, ATT&CK mapping, triage, STIX, detections, alerts, transport and release evidence. A socket-level test connects to the Modbus listener and checks the response and recorded event. GitHub Actions runs the full suite after publication.

## 14. Current status and future work

The version 0.2 code, demonstration dashboard, detections, STIX export, triage, profiles, health monitoring, multi-sensor foundation, tests, documentation, Docker deployment, Azure template and synthetic research report are complete.

Possible future phases are:

1. deploy the sensor only with authorized free cloud credit;
2. collect traffic for two to four weeks;
3. sanitize and manually review the observations;
4. replace the demonstration report with a clearly labeled observed-data report;
5. record a short video walkthrough;
6. host the dashboard at a stable public URL.

## 15. Terms to remember

- **OT:** technology that monitors or controls physical processes.
- **ICS:** industrial control system.
- **PLC:** industrial controller used to operate equipment.
- **HMI:** interface used by an operator to view or control a process.
- **Honeypot:** decoy system used to observe activity.
- **TTP:** tactic, technique or procedure used to describe behavior.
- **IOC:** indicator of compromise, such as a suspicious address or file hash.
- **MITRE ATT&CK for ICS:** knowledge base for behavior affecting industrial systems.
- **Pseudonymization:** replacing an identifier with a repeatable protected value.
- **Synthetic data:** artificial data created for testing and demonstration.

The most important point is to explain the project honestly: the system and analysis pipeline work, while the current public events are synthetic until an authorized live collection is completed.
