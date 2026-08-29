# ATT&CK Navigator exports

`ot-sentinel-demo-layer.json` is generated only from the deterministic synthetic dataset. It is safe for demonstration and does not describe observed attacker activity.

Private layers generated from reviewed observations belong under `exports/private/`, which is ignored by Git. Navigator layers contain aggregate technique frequencies only; they must not contain source identifiers, session identifiers, addresses or payloads.

The exporter follows ATT&CK Navigator Layer format 4.5 with the `ics-attack` domain, Navigator `5.3.2` and repository-pinned ATT&CK content version `18`. Upgrading the ATT&CK content pin requires regenerating and revalidating the synthetic layer.
