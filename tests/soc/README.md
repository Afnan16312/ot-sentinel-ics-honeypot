# Disposable SOC validation lab

This lab validates OT Sentinel rules inside native Wazuh and Suricata engines. It is local-only, uses synthetic fixtures and must never be run on the Oracle sensor.

## Requirements

- Docker Desktop or Docker Engine with Compose 2.24.4 or newer (`!override` support)
- At least 4 CPU cores, 8 GB RAM and 50 GB free disk for Wazuh
- `vm.max_map_count=262144` inside the Linux/WSL2 Docker host
- Internet access for the initial pinned image/config download

All published host ports bind to `127.0.0.1`. The lab is not suitable for public exposure.

The pinned native positive and negative checks passed locally on 2026-08-25. See [NATIVE_VALIDATION.md](NATIVE_VALIDATION.md) for the privacy-safe evidence. Re-run the sequence below after changing rules, images or isolation settings.

## Prepare and start Wazuh

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File tests\soc\prepare_soc_lab.ps1
docker compose -f tests\soc\docker-compose.yml config
docker compose -f tests\soc\docker-compose.yml up -d
docker compose -f tests\soc\docker-compose.yml ps
```

Wait until manager, indexer and dashboard are healthy. Then run:

```powershell
python tests\soc\inject_alert.py
```

Success requires native `wazuh-logtest` output containing rule `110001` for the synthetic Modbus write and no `110001` match for connection-only or normal-read fixtures.

Privacy-safe local readiness checks:

```powershell
docker compose -f tests\soc\docker-compose.yml ps
docker compose -f tests\soc\docker-compose.yml exec -T wazuh.manager sh -c 'for process in wazuh-analysisd wazuh-remoted wazuh-db; do pgrep -x "$process" > /dev/null || exit 1; done; pgrep -f "/var/ossec/api/scripts/wazuh_apid.py" > /dev/null'
curl.exe -k -s -o NUL -w "%{http_code}" https://127.0.0.1:5601
```

The dashboard check confirms only local TLS reachability; it does not print or store test credentials.

## Validate Suricata

```powershell
python tests\soc\generate_pcap.py
docker compose -f tests\soc\docker-compose.yml --profile suricata run --rm suricata -T -c /etc/suricata/suricata.yaml
docker compose -f tests\soc\docker-compose.yml --profile suricata run --rm suricata -c /etc/suricata/suricata.yaml -r /fixtures/modbus-write-read.pcap -l /output
python tests\soc\verify_suricata.py
```

Success requires exactly one SID `4200501` alert for source port `41000` and no alert for the harmless read flow on source port `42000`.

## Stop and clean up

```powershell
docker compose -f tests\soc\docker-compose.yml --profile suricata down --volumes --remove-orphans
```

The ignored `tests/soc/vendor/` directory contains the pinned official Wazuh Docker configuration and locally generated certificates. The ignored `tests/soc/output/` directory contains native Suricata results.

Static Python tests prove harness construction and expected-output parsing. They are not a substitute for the native commands above.
