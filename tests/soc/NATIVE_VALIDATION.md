# Native SOC Validation Evidence

Status: **passed locally with synthetic fixtures on 2026-08-25**.

This record contains only privacy-safe summaries. It excludes generated EVE rows, packet payloads, credentials, cloud identifiers, non-loopback addresses and private telemetry. The disposable lab was never run on Oracle.

## Runtime and isolation

- Docker Engine `29.7.2`, Linux/AMD64
- Docker Compose `5.4.0`
- 6 Docker CPUs and 10,429,255,680 bytes of Docker memory
- Linux `vm.max_map_count=262144`
- official Wazuh Docker repository tag `v4.14.7`, commit `adcc5b57d2f7edfcbe6c399272dc76fbdf12b623`
- Wazuh manager, indexer and dashboard images pinned to `4.14.7`
- Suricata image pinned to `8.0.4`
- every published Wazuh host port resolved to `127.0.0.1`
- Suricata used `network_mode: none`, dropped all capabilities and ran offline in IDS mode

Public image digests observed during the run:

| Component | Digest |
|---|---|
| Wazuh manager | `sha256:8665c9807a5765253c79e4b072a1b7462c997bd69be949118a8d82ce44dd33e9` |
| Wazuh indexer | `sha256:66b7640cce54f5f20a65e8320601b4570a1306d9f9b334d30bcaa324720a517c` |
| Wazuh dashboard | `sha256:eeff857a664b3c09d3df4407b8749a351f321e4f366ca60ea1dffaa76f2146a7` |
| Suricata | `sha256:8058c0580c48cae4013bb8d576e5fe7cfe59884ea5526239056825b70c849ec8` |

## Suricata authoritative results

`suricata -T` reported:

- 1 rule file processed;
- 4 rules successfully loaded;
- 0 rules failed;
- 0 rules skipped;
- configuration successfully loaded.

The deterministic offline PCAP contained one synthetic write flow and one harmless read flow. The committed verifier confirmed:

- total alerts: 1;
- SID `4200501` write alerts: 1;
- harmless-read alerts: 0.

Result: **passed**. This proves the pinned native engine accepted the rules and distinguished the positive and negative fixtures. It does not prove attacker intent, exploitation or production tuning suitability.

## Wazuh authoritative results

The official single-node manager, indexer and dashboard started locally. Essential manager processes, including `wazuh-analysisd`, `wazuh-remoted`, `wazuh-db` and `wazuh-apid`, were running before rule tests.

The committed injector ran `/var/ossec/bin/wazuh-logtest` three times and confirmed:

| Synthetic fixture | Rule `110001` |
|---|---:|
| Modbus write-single request | fired |
| Connection-only event | did not fire |
| Normal Modbus read | did not fire |

Result: **passed**. The built-in JSON decoder was sufficient; no custom decoder was added.

## Native defects found and corrected

Native execution caught issues that static matching could not prove:

1. the hardened Suricata container needed an explicitly writable `/output` log directory;
2. its classification, reference and empty threshold files needed explicit read-only mounts;
3. Wazuh requires the reserved static JSON field `protocol` to use the native `<protocol>` rule element rather than `<field name="protocol">`.

Regression tests now assert these configurations. Detection Preview remains an offline explanation and is not substituted for this native evidence.

## Reproduction and cleanup

Run the exact commands in [README.md](README.md). Success requires both committed verifiers to exit zero. After collecting the privacy-safe outcome, stop and remove the disposable containers and volumes with:

```powershell
docker compose -f tests\soc\docker-compose.yml --profile suricata down --volumes --remove-orphans
```

Re-run the complete native sequence after changing detection content, container versions or Compose isolation settings.
