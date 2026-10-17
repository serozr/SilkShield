# SilkShield Frontend

The dashboard is a static HTML/CSS/JavaScript client served by FastAPI at `/`;
assets are served under `/static`. It uses the same origin for API requests, so
there is no separate frontend build step or API URL configuration. For remote
LinuxONE use, access it through the loopback SSH tunnel documented in the
README.

The dashboard applies the IBM team website's emerald, warm-white, cream, and
charcoal visual identity and supplied SilkShield mascot (`frontend/assets`).
The analysis view remains connected to the `/analyze` API contract. Static
sample-history and scripted-assistant screens from the design handoff are not
used as live analysis data or AI responses.

## Goal

Create a dashboard that makes the security decision immediately
understandable to a judge.

## Main Screen

``` text
SILKSHIELD
AI-Powered Real-Time Threat Decision Engine

[ IOC input                         ] [ ANALYZE ]

THREAT SCORE
87 / 100
HIGH

Classification: PHISHING
Confidence: 94%

AI ANALYSIS
...

EVIDENCE
✓ Multiple detections
✓ Recently registered domain
✓ Suspicious infrastructure

RECOMMENDATION
BLOCK

MITRE ATT&CK
T1566.002
```

## Required UI States

### Idle

Explain what the user can analyze.

### Loading

Show that SilkShield is actively analyzing the IOC.

### Result

Show:

-   risk score
-   risk level
-   classification
-   confidence
-   evidence
-   AI explanation
-   recommendation

### Error

Explain whether the problem is:

-   invalid IOC
-   provider unavailable
-   backend error
-   unsupported IOC type

## Design Principle

A judge should understand the result in less than five seconds.

Do not hide the risk score inside a secondary page.

## Optional

If time permits:

-   threat relationship graph
-   historical analyses
-   MITRE technique cards
-   analysis timeline
