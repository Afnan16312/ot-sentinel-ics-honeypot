# Oracle Cloud Free-Tier Deployment Runbook

This is the reproducible runbook for the isolated Oracle Cloud deployment used by OT Sentinel. It deliberately omits public IP addresses, private keys, cloud identifiers and raw observations.

The public dashboard continues to use synthetic data. Live JSONL remains private until sanitization, automated validation and human review are complete.

## Verified reference deployment

The reference deployment was placed into service in Oracle Cloud's UAE East (Dubai) region on 2026-08-19 with:

- Ubuntu 24.04 on an ARM64 `VM.Standard.A1.Flex` instance;
- 1 OCPU, 6 GB memory and the default boot volume;
- one dedicated VCN, public subnet, ephemeral public address and network security group;
- SSH restricted to the operator's current `/32` address;
- public TCP ports 502, 102 and 2404 only for the decoy services;
- a non-root, read-only and capability-free sensor container;
- host-level blocking of new outbound connections from the container edge network;
- systemd restart management and local log rotation.

This is an operational reference, not a claim of NESA compliance or a production security control.

## Cost boundary

Oracle documents an Always Free allowance for eligible Ampere A1 compute and a shared block-volume allowance. Eligibility, capacity and pricing can change, and the console estimate may show list price before applying tier allowances.

Use only a shape explicitly marked **Always Free-eligible**, keep storage inside the account allowance, deploy in the home region and check Cost Analysis after provisioning. Do not create a second instance, paid backup, load balancer, reserved public address or optional paid monitoring service for this project.

Official references:

- [Oracle Always Free resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
- [Oracle public-subnet quick action](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/quick-action-internet-gateway.htm)
- [Oracle internet gateways](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/managingIGs.htm)
- [Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Docker Compose networks](https://docs.docker.com/reference/compose-file/networks/)
- [Docker `DOCKER-USER` firewall chain](https://docs.docker.com/engine/network/firewall-iptables/)

## Cloud network configuration

Create a dedicated VCN and public subnet that have no peering, VPN or route to a home, corporate or production OT network. Attach an internet gateway and a `0.0.0.0/0` route only because a public honeypot must accept unsolicited traffic.

Use a network security group with these stateful ingress rules:

| Source | Protocol | Destination | Purpose |
|---|---|---:|---|
| Operator's current `/32` | TCP | 22 | SSH administration |
| `0.0.0.0/0` | TCP | 502 | Modbus/TCP decoy |
| `0.0.0.0/0` | TCP | 102 | S7/ISO-on-TCP decoy |
| `0.0.0.0/0` | TCP | 2404 | IEC-104 decoy |

Leave source-port range as **All**. Do not expose Streamlit, Docker, a database, a collector, or SSH to `0.0.0.0/0`. Remove any broad default SSH ingress rule after the restricted NSG rule is confirmed.

## Host installation

Install Docker Engine and the Compose plugin from Docker's official Ubuntu repository. Clone the project into `/opt/ot-sentinel`, then prepare the private log directory:

```bash
cd /opt/ot-sentinel
mkdir -p logs
sudo chown -R 10001:ubuntu logs
sudo chmod 750 logs
```

Create an untracked `.env` containing a non-sensitive sensor label:

```text
OT_SENSOR_ID=uae-dubai-01
```

Never put secrets, private keys, raw logs or cloud identifiers in `.env` or Git.

Install the checked-in host assets:

```bash
sudo install -m 0755 infra/oracle/ot-sentinel-firewall \
  /usr/local/sbin/ot-sentinel-firewall
sudo install -m 0644 infra/oracle/ot-sentinel.service \
  /etc/systemd/system/ot-sentinel.service
sudo install -m 0644 infra/oracle/logrotate.ot-sentinel \
  /etc/logrotate.d/ot-sentinel
```

Build the image, enable the service and start it:

```bash
sudo docker compose build sensor
sudo systemctl daemon-reload
sudo systemctl enable --now ot-sentinel.service
```

The firewall helper creates a small external Docker edge bridge for published ports. The sensor remains attached to its internal Compose network as well. A `DOCKER-USER` rule blocks new outbound connections from the edge subnet while allowing response traffic for inbound sessions.

## Verification

Check lifecycle, port publication and host firewall rules:

```bash
sudo systemctl is-enabled ot-sentinel.service
sudo systemctl is-active ot-sentinel.service
sudo docker compose -f docker-compose.yml \
  -f infra/oracle/docker-compose.oracle.yml ps
sudo iptables -S DOCKER-USER
```

The container should be `Up`; host ports 502, 102 and 2404 should be published. The firewall output must contain an established/related accept rule and a new-connection drop rule for the dedicated edge subnet.

Send one harmless loopback Modbus read:

```bash
python3 - <<'PY'
import socket

request = bytes.fromhex("000100000006010300000003")
with socket.create_connection(("127.0.0.1", 502), timeout=3) as connection:
    connection.sendall(request)
    print("Response:", connection.recv(1024).hex())
PY
```

Confirm the health file exists after the event:

```bash
sudo cat logs/health.json
```

Test outbound isolation from the container:

```bash
sudo docker exec -i ot-sentinel-sensor python - <<'PY'
import socket

try:
    connection = socket.create_connection(("1.1.1.1", 443), timeout=3)
except OSError as error:
    print("Outbound blocked:", type(error).__name__)
else:
    connection.close()
    print("ERROR: outbound connection succeeded")
PY
```

`Outbound blocked: TimeoutError` is the expected result. Stop the service and investigate if outbound initiation succeeds.

## Daily private checks

```bash
cd /opt/ot-sentinel
sudo systemctl is-active ot-sentinel.service
sudo cat logs/health.json
df -h /
sudo du -sh logs
sudo logrotate --debug /etc/logrotate.d/ot-sentinel
```

Do not paste or publish `logs/events.jsonl`. It contains private live evidence, including source addresses and bounded payload material.

## Shutdown

Stop collection without deleting evidence:

```bash
sudo systemctl stop ot-sentinel.service
```

Before terminating the cloud instance, copy private evidence to approved encrypted storage, record the end time, verify retention requirements and check delayed Cost Analysis data. Cloud deletion is a deliberate operator action and is not automated by this repository.

## Known limitation

On the verified Docker 29 ARM64 host, bindings were present in container configuration but were not exposed when the container was attached only to an `internal: true` network. The dedicated edge bridge restored host publication. Because joining a non-internal bridge normally permits egress, the service installs and verifies the host `DOCKER-USER` drop rule before starting the container.

This pattern is specific to Docker's iptables firewall backend. Revalidate the isolation controls before changing Docker networking or switching to the nftables backend.
