# Final Data Handoff Runbook

This is the beginner-friendly procedure for processing the private Oracle event file **after the authorized collection window ends**. Everything is offline. Nothing in this procedure connects to Oracle, publishes data, changes the Streamlit demonstration dataset or uploads files to GitHub.

## What remains manual

An authorized person must still:

1. approve the collection end time;
2. stop the Oracle sensor during a controlled maintenance window;
3. make an encrypted backup of the original `events.jsonl`;
4. transfer that file to an approved private analysis computer;
5. decide whether public candidates may be created;
6. review every candidate before any separate publication decision.

Never paste the file, its records, an address, a payload, a key or a cloud identifier into chat, an issue or a Git commit.

## Output classification

| Output | Location | Meaning |
|---|---|---|
| Original evidence | Approved encrypted storage | Private and unchanged |
| Sanitized JSONL | Ignored handoff directory | Private analysis input |
| SQLite index | Ignored handoff directory | Privacy-reduced deduplicated analysis |
| Wazuh JSONL | Ignored handoff directory | Validated local SOC input |
| Weekly report | Ignored handoff directory | Private analyst brief |
| Navigator layer | Ignored handoff directory | Private aggregate ATT&CK hypotheses |
| Streamlit/STIX candidate | Created only with explicit approval | Still private until a separate review approves publication |

The repository ignores `data/private/`, `reports/private/`, `exports/private/`, `tests/soc/staging/` and SQLite files. The commands also refuse an in-repository private output unless Git confirms that it is ignored.

## 1. Open the project

```powershell
cd "C:\Users\afnan\Downloads\honeypot + attack visualization dashboard"
```

Use the virtual environment Python in every command:

```powershell
$Python = ".\.venv\Scripts\python.exe"
& $Python --version
```

## 2. Record and verify the original checksum

Set the path to the private transferred file. The example path is only a placeholder:

```powershell
$PrivateInput = "C:\OT-Sentinel-Private\events.jsonl"
Test-Path -LiteralPath $PrivateInput
Get-FileHash -Algorithm SHA256 -LiteralPath $PrivateInput
```

Save the checksum in the approved private study record. Compare it with the checksum made before transfer. A mismatch means stop: use the verified backup rather than trying to repair the evidence.

Do not rename, edit or format the original file.

## 3. Run privacy-safe preflight

```powershell
& $Python scripts\preflight_events.py $PrivateInput
```

The command prints only checksum, file size, counts, date range, classification and safe error codes. It does not print record values. Exit code `0` means valid. Exit code `2` means processing must stop.

Preflight rejects malformed JSON, an incomplete final line, oversized records, missing fields, invalid timestamps, unknown top-level schema fields, duplicate event IDs and mixed synthetic/observed or raw/sanitized data.

## 4. Create private processing secrets

These values are temporary private analysis secrets. Do not save them in the repository or screenshots.

```powershell
$SaltBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($SaltBytes)
$env:OT_PRIVACY_SALT = [Convert]::ToHexString($SaltBytes)

$FingerprintBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($FingerprintBytes)
$env:OT_FINGERPRINT_SECRET = [Convert]::ToHexString($FingerprintBytes)
```

Store them only under the approved retention policy. Reusing the same privacy salt keeps source pseudonyms stable within the approved study. Losing it does not damage the original evidence, but regenerated pseudonyms will differ.

## 5. Dry-run the complete workflow

```powershell
& $Python scripts\finalize_collection.py $PrivateInput --dry-run
```

Dry-run performs preflight and privacy validation but writes nothing. Confirm that:

- classification is `observed` for the final Oracle study;
- the record count and date range match expectations;
- `publication_performed` is `false`;
- no public-candidate stages are planned.

## 6. Build the private analysis handoff

```powershell
& $Python scripts\finalize_collection.py $PrivateInput
```

The deterministic run directory is created under `data\private\handoff\`. It contains:

```text
sanitized/events.sanitized.jsonl
analysis/observations.sqlite3
wazuh/events.jsonl
reports/weekly-private.md
exports/attack-navigator-private.json
processing-manifest.json
```

The command never overwrites the original file. Writes use transactions or atomic replacement. Re-running the same command verifies the manifest and output checksums, then reports `already_complete_and_verified`.

## 7. Optional public candidates

Do this only after a human has approved creation of review candidates:

```powershell
& $Python scripts\finalize_collection.py $PrivateInput --approve-public-candidates
```

This creates a separate deterministic private run directory containing two additional files:

- `public-candidate/streamlit-summary.json`
- `public-candidate/events.stix.json`

The flag does **not** publish them. The manifest always records `publication: false`, `automatic_upload: false` and `automatic_dashboard_replacement: false`.

Review collection wording, date range, small-count disclosure, geographic uncertainty, ATT&CK hypotheses and every screenshot before making a separate publication decision.

## 8. Start the local Wazuh lab

Wazuh runs only on the laptop through Docker. It is never installed on Oracle.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests\soc\prepare_soc_lab.ps1
docker compose -f tests\soc\docker-compose.yml up -d
docker compose -f tests\soc\docker-compose.yml ps
```

Wait about one minute. The manager, indexer and dashboard must show `Up`. All published ports remain bound to `127.0.0.1`.

## 9. Import approved sanitized events into Wazuh

Set the path to the `wazuh/events.jsonl` created in step 6:

```powershell
$WazuhInput = "C:\path-to-private-handoff\wazuh\events.jsonl"
& $Python scripts\stage_wazuh_events.py $WazuhInput --approve-local-ingestion
```

The command validates every event again, then appends it once to the ignored file watched by Wazuh. A private SQLite staging ledger makes repeated or interrupted runs restart-safe. It never connects to Oracle.

To prove the native path with committed synthetic fixtures:

```powershell
& $Python scripts\stage_wazuh_events.py `
  tests\soc\fixtures\wazuh-ingest-events.jsonl `
  --approve-local-ingestion
& $Python tests\soc\verify_wazuh_ingestion.py
```

The verifier requires rule `110001` to be stored and indexed for the synthetic Modbus write while the connection and read fixtures remain free of custom high-severity alerts.

## 10. Find OT Sentinel alerts in Wazuh

1. Open `https://127.0.0.1:5601`.
2. Sign in with the private local-lab credentials.
3. Open **Threat Intelligence** and then **Threat Hunting**.
4. Select the current time range or the imported event period.
5. Search for `rule.groups: ot_sentinel`.
6. For control alerts, search for `rule.id: 110001 OR rule.id: 110002 OR rule.id: 110003 OR rule.id: 110004`.

The Wazuh indexer stores these alerts, so they remain searchable after a manager restart. A harmless event may be collected without creating a custom high-severity alert; that is intended.

Stop Wazuh while preserving its local volumes:

```powershell
docker compose -f tests\soc\docker-compose.yml stop
```

Start it later:

```powershell
docker compose -f tests\soc\docker-compose.yml start
```

`down --volumes` deletes the disposable local Wazuh data and is only for an intentional lab reset.

## 11. Streamlit, STIX, Navigator and reports

- Streamlit should receive only the reviewed aggregate `streamlit-summary.json`, never raw or row-level observed events.
- The processor does not replace `data/demo_summary.json`; that requires a separate reviewed code change.
- The STIX candidate contains the public profile and passes a second privacy validator.
- The Navigator layer contains technique-frequency aggregates, not source or session identifiers.
- The weekly report remains private and describes ATT&CK mappings as hypotheses.

Suricata cannot ingest this historical JSONL. Suricata examines packets or PCAP files. The project keeps its validated Suricata rules as separate packet-level detection evidence; the Oracle sensor did not collect full packet captures.

## Failure recovery

| Failure | Safe response |
|---|---|
| Checksum mismatch | Stop and recover the verified encrypted backup |
| Preflight exit code 2 | Keep the original unchanged; investigate the safe error codes privately |
| Privacy validation failure | Do not import, display, export or publish the candidate |
| Interrupted final processor | Run the same command again; transactions and checksums recover safely |
| Existing output differs | Stop; quarantine that run directory instead of overwriting it |
| Wazuh unavailable | Keep the validated JSONL; start Wazuh later and repeat staging |
| Wazuh staging interrupted | Repeat the staging command; its ledger repairs or completes the pending append |
| Unexpected alert volume | Stop local ingestion, preserve evidence and review rule tuning offline |

## Rollback

1. Stop local Wazuh with `docker compose -f tests\soc\docker-compose.yml stop`.
2. Keep the original evidence and its checksum unchanged.
3. Move a failed generated run directory to approved quarantine storage.
4. Do not replace Streamlit data or publish candidates.
5. Correct and test the workflow only with synthetic fixtures.
6. Re-run from the verified original input.

Rollback never requires restarting or changing the Oracle sensor.

## Final privacy-review checklist

- [ ] Original checksum matches the transfer record.
- [ ] Original evidence is encrypted and unchanged.
- [ ] Preflight passed with zero invalid and duplicate records.
- [ ] Sanitized JSONL passed the publication validator.
- [ ] No raw address, payload, credential, key, token or cloud identifier appears in a candidate.
- [ ] Synthetic and observed records were not mixed.
- [ ] Processing manifest output checksums match.
- [ ] Wazuh is local-only and no Oracle agent was installed.
- [ ] Streamlit receives aggregate statistics only.
- [ ] Suricata results are not presented as historical JSONL analysis.
- [ ] ATT&CK mappings are described as hypotheses.
- [ ] Geographic and attribution limitations are visible.
- [ ] A human approved every proposed public field and screenshot.
- [ ] Git status shows no private runtime file tracked.

Clear the temporary environment variables when finished:

```powershell
Remove-Item Env:OT_PRIVACY_SALT
Remove-Item Env:OT_FINGERPRINT_SECRET
```
