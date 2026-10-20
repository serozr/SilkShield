# Package 1 — SOC Detection Engine

SilkShield now includes a safe, deterministic SOC detection layer for Windows Sysmon telemetry.

## Flow

```text
Sysmon XML / JSON / JSONL
        ↓
Normalized DetectionEvent
        ↓
Sigma-style rules
        ↓
DetectionMatch
        ↓
MITRE ATT&CK technique IDs
        ↓
Incident timeline
```

## Included detections

- `SILK-PS-001` — PowerShell encoded command — `T1059.001`
- `SILK-RUNDLL32-001` — Rundll32 JavaScript handler — `T1218.011`
- `SILK-WMIC-001` — WMIC process activity — `T1047`

The rule format intentionally implements only the `condition: selection` subset needed by the initial SOC package. It is not presented as a full Sigma specification implementation.

## Safety boundary

Telemetry is parsed as data. SilkShield does not execute command lines, download payloads, or automatically resolve network indicators during detection.

## Example

```python
from soc.engine import DetectionEngine
from soc.sysmon import load_telemetry

engine = DetectionEngine.from_directory("soc/rules")
events = load_telemetry("sample.jsonl")
matches = engine.detect(events)
timeline = engine.build_timeline(matches)
```

## Why this matters for the portfolio

This package demonstrates detection engineering, Windows telemetry normalization, deterministic alerting, MITRE ATT&CK mapping, and investigation timeline generation. The next package should expose these capabilities through the SilkShield API/UI and add detection quality metrics such as precision, recall, and false-positive rate.
