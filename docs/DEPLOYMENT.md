# Zero-out-of-pocket deployment guide

The complete software, dashboard, test suite and synthetic demonstration run locally for AED 0. A public Internet collection is optional and is not required to demonstrate the project. Do not expose a personal computer or home network to avoid cloud costs.

Use an **Azure for Students** subscription when eligible. Keep its spending limit enabled and do not upgrade the subscription to pay-as-you-go. The project uses one small Linux VM and no paid Marketplace image.

If no free cloud credit is available, stop after the local demonstration. The repository remains a complete, reproducible engineering project; only claims about observed live traffic must wait.

## Prerequisites

- Azure CLI and Bicep support
- An Azure subscription with sufficient free credit
- An SSH key pair
- Your current public IP expressed as `/32`
- Docker Engine on the VM, or Python 3.11+

## 1. Check cost protection

In Azure Portal, open **Cost Management + Billing → Subscriptions** and verify that a spending limit is active. Create budget alerts at 25%, 50%, and 75%. A budget alert is not a hard cap; the subscription spending limit is the protection.

Do not enable Defender upgrades, Log Analytics, Azure Monitor ingestion, managed databases, or Marketplace appliances for this project.

## 2. Deploy the isolated VM

```powershell
az login
az account show
./infra/azure/deploy.ps1 -SshPublicKeyPath "$env:USERPROFILE/.ssh/id_ed25519.pub" -AdminCidr "YOUR.PUBLIC.IP/32"
```

The template permits SSH only from your `/32` and exposes only TCP 502, 102 and 2404. Password authentication is disabled and Trusted Launch is enabled.

## 3. Install the sensor

Copy this repository to `/opt/ot-sentinel`, build the image, and start the isolated Compose service:

```bash
sudo mkdir -p /opt/ot-sentinel
sudo chown "$USER":"$USER" /opt/ot-sentinel
git clone YOUR_REPOSITORY_URL /opt/ot-sentinel
cd /opt/ot-sentinel
mkdir -p logs
docker compose up -d --build
docker compose ps
```

The container runs as UID 10001, drops all Linux capabilities, has a read-only root filesystem, uses resource limits, and is attached to an internal Docker network with no Internet route.

## 4. Validate safely

From an authorized test machine, send a harmless Modbus read request. Never scan infrastructure you do not own or have permission to test.

```bash
printf '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x03' | nc -w 2 SENSOR_IP 502 | xxd
```

Then confirm `logs/events.jsonl` contains a connection and protocol request.

## 5. Publish only sanitized data

Keep the raw file private. Set a new random salt outside the repository and run:

```bash
export OT_PRIVACY_SALT='replace-with-a-long-random-private-value'
ot-sentinel sanitize logs/events.jsonl data/public_events.jsonl
```

Review the exported file manually before publishing it. The sanitizer removes raw payloads and replaces IP addresses with pseudonymous identifiers, but human review remains required.

## 6. End the experiment

Export the private evidence to an encrypted local archive, then remove the entire project resource group:

```powershell
./infra/azure/destroy.ps1
```

Confirm that the resource group, disk and public IP no longer appear in Azure, and check Cost Analysis after its normal reporting delay.
