# Authorized Live Collection Runbook

This runbook is for a future two-to-four-week study. The current public project uses synthetic data and does not claim live attacker findings.

## Before deployment

1. Obtain written authorization for the cloud subscription, region, public IP, ports and dates.
2. Keep the sensor in a dedicated resource group and virtual network with no route to production, corporate or home systems.
3. Allow only the intended OT ports; restrict administration to one known address with key authentication.
4. Record the owner, emergency contact, start date, end date, retention period and shutdown criteria.
5. Enable a hard spending limit or use approved free credit. Do not convert the subscription to pay-as-you-go for this study.
6. Confirm private logs are excluded from Git and backed up only to approved encrypted storage.

## During collection

- Check the sensor health file, disk use and cloud cost daily.
- Stop if the sensor behaves unexpectedly, resources exceed the agreed limit, isolation changes or authorization expires.
- Do not contact, scan, identify or retaliate against observed sources.
- Do not change the decoy into a real controller or connect it to any physical process.
- Keep analyst notes separate from observed facts.

## Publication gate

1. Copy the private log to an approved analysis system and shut down the public sensor.
2. Sanitize source addresses and remove raw payloads and credential-like content.
3. Run the public-data validator and export the public STIX profile.
4. Manually review every proposed public field and screenshot.
5. Report collection dates, sensor location, limitations and uncertainty.
6. Describe ATT&CK mappings as evidence-supported hypotheses, not proof of identity, intent or compromise.

## End of study

- Destroy the resource group and verify that the VM, disk and public IP are gone.
- Check delayed cloud billing data.
- Retain or delete private logs according to the written retention decision.
- Publish only after the privacy review is signed off.

The only unfinished project milestone is executing this runbook on authorized, isolated public infrastructure. That external study cannot be simulated and should not be claimed until it happens.

