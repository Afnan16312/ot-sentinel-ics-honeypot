# Interactive Threat Map Redesign

## Purpose

The observatory map is an investigation surface for reviewed public data. It helps a viewer answer four questions:

1. Where is the visible protocol activity concentrated?
2. Which industrial protocol is involved?
3. How does activity change across the selected time window?
4. Which pseudonymous source should an analyst inspect next?

It is not an attribution map. A plotted country is an approximate geolocation result, and a network observation does not prove an operator's identity, physical location, infrastructure ownership or travel path.

## Gap analysis of the earlier map

The earlier dashboard used a single static geographic scatter chart. It showed that geographic fields existed, but it did not support an investigation workflow.

| Gap | User impact | Redesign response |
|---|---|---|
| One fixed geographic view | Viewers could not compare paths, bubbles, density or time | Four purpose-specific map modes |
| No point selection | A source could not be inspected from the map | Clickable privacy-safe source bubbles and an investigation panel |
| No map-specific time control | Recent activity was mixed with the complete dataset | 24-hour, 7-day, 14-day and all-observation windows |
| No direct geographic drill-down | Analysts had to manipulate the sidebar manually | One-click country filtering and a restore-all action |
| No visible data-quality state | Missing or invalid coordinates were invisible | Coverage audit with plotted and excluded counts |
| No safe map export | Viewers could not reuse the visible aggregate | Reviewed coarse CSV export |
| Limited navigation | The map acted like an image | Zoom, pan, scroll zoom, reset, fullscreen and PNG controls |
| Dense generic card styling | The interface felt templated and visually noisy | Flat matte surfaces, restrained borders and compact telemetry strips |
| Weak small-screen hierarchy | KPI cards pushed the map far down the page | Responsive 2-by-2 KPI and map-stat grids with a collapsed mobile sidebar |
| Unbounded path rendering risk | A large dataset could make the page sluggish | The flow layer is capped at the 60 most active visible aggregates |

## Shipped interaction model

### Flow view

Shows restrained great-circle observation paths from coarse public source locations to an approximate UAE region marker. Path width reflects relative visible event volume. The paths represent observed network relationships only.

### Source bubbles

Removes paths and emphasizes selectable protocol-colored sources. Bubble size represents aggregate event count. Hover text shows reviewed public fields only.

### Density

Adds a heat layer for concentration analysis while retaining selectable source bubbles. This view is useful when several pseudonymous sources overlap geographically.

### Time playback

Groups visible public observations into six-hour UTC windows and provides a finite Play action plus a draggable timeline. It shows changes in the dataset, not a live feed.

### Shared controls

- observation-window selection;
- optional place labels;
- optional flow paths in Flow view;
- camera reset;
- visible event, source, country and protocol counts;
- point selection and privacy-safe investigation summary;
- one-click country focus and show-all restore action;
- privacy-safe aggregate CSV download;
- synchronized ATT&CK, geographic concentration and activity-cadence views;
- explicit empty states when no safely mappable records remain.

## Visual direction

The redesign uses an operational, industrial visual language instead of a decorative "hacker" theme:

- near-black matte surfaces rather than gradients;
- one-pixel steel-blue borders;
- Manrope for readable interface text and DM Mono for identifiers and telemetry;
- blue for Modbus, amber for S7 and muted violet for IEC-104;
- restrained opacity and line weight so dense paths remain readable;
- compact information hierarchy with no ornamental glass cards or glowing text.

The implementation stays inside Streamlit and Plotly 6. Plotly's MapLibre map traces provide interaction without a paid map token, a separate JavaScript application or another deployment service. CARTO/OpenStreetMap tiles still require browser network access and carry their normal attribution.

## Privacy and safety controls

The map is downstream of the existing public-data validation gate. It never reads the private Oracle telemetry path directly.

- Source identity uses only `source_id`, a pseudonymous public identifier.
- Raw IP addresses, payloads, credentials, OCIDs and cloud identifiers are not copied into map traces, hover data, selections or downloads.
- Coordinates are rounded to one decimal place before aggregation.
- Selection parsing accepts only a reviewed ten-field contract.
- Invalid or missing coordinates are excluded and counted.
- The UAE endpoint is a broad public region, not a sensor or cloud-instance coordinate.
- The CSV export is built from an explicit allowlist of aggregate fields.
- Empty or malformed selection state fails closed.
- Only deterministic synthetic data is committed to the repository.

## Architecture

```text
validated public JSONL
        |
        v
global protocol / severity / country filters
        |
        v
map time window
        |
        +--> coverage audit
        |
        v
coarse source + country + protocol aggregation
        |
        +--> Flow / Bubble / Density / Playback figure
        +--> reviewed click-selection contract
        +--> allowlisted aggregate CSV
        +--> synchronized ATT&CK and cadence summaries
```

`src/ot_sentinel/dashboard_map.py` owns preparation, privacy-safe aggregation and figure construction. `app.py` owns Streamlit state, controls, layout and the investigation workflow. This separation makes the map logic independently testable without a browser.

## Verification matrix

| Area | Evidence |
|---|---|
| Time boundaries | Inclusive UTC unit test, including naive boundary normalization |
| Aggregation | Source/protocol grouping, session count, control attempts and severity tests |
| Privacy | Figure and CSV serialization checks against raw-address, payload and cloud-ID canaries |
| Coordinate safety | Invalid-range exclusion and one-decimal rounding tests |
| Map modes | Figure construction tests for all four modes and playback frames |
| Rendering bounds | Maximum flow-path test |
| Interaction contract | Reviewed selection-field extraction and malformed-state rejection |
| Empty state | Streamlit test clears the global protocol filter and verifies a disabled export |
| Application rendering | Streamlit AppTest exercises default, Density and Time playback views |
| Browser QA | Desktop, tablet and phone viewports; layer switching, labels, selection, country focus, reset and empty-state review |
| Browser diagnostics | Fresh-session console checked for warnings and errors |

## Residual limitations

- Public geolocation is approximate and can be wrong, especially for VPNs, proxies and cloud infrastructure.
- A pseudonymous source can represent shared or changing network infrastructure.
- Flow paths are visual relationships, not packet routes or evidence of physical movement.
- Time playback uses the visible dataset's timestamps and is not real-time streaming.
- CARTO/OpenStreetMap tiles depend on an external network connection.
- The 60-path cap favors readability and responsiveness over displaying every aggregate at once.
- A future React/MapLibre application may be justified if the project needs very large datasets, analyst authentication, linked case management or complex cross-filter state. The current two-purpose Streamlit dashboard does not require that migration.

## Files

- `app.py` — interface, controls, responsive layout and investigation panel
- `src/ot_sentinel/dashboard_map.py` — public aggregation, map modes and safe export
- `tests/test_dashboard_map.py` — map behavior and privacy tests
- `tests/test_dashboard_app.py` — Streamlit rendering and empty-state tests
