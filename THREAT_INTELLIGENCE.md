# SilkShield Threat Intelligence Layer

## Purpose

Collect external security signals and normalize them into a
provider-independent structure.

## Initial Provider

VirusTotal API.

SilkShield should treat VirusTotal as one intelligence source, not as
the product itself.

## Normalized Internal Object

``` json
{
  "ioc": "example.com",
  "type": "domain",
  "detections": 8,
  "total_engines": 94,
  "detection_ratio": 0.085,
  "reputation": -72,
  "related_indicators": [],
  "metadata": {}
}
```

Actual fields depend on what the provider returns.

## Provider Adapter Pattern

``` text
intelligence/
├── virustotal.py
├── normalize.py
└── ioc.py
```

`virustotal.py` should only understand the provider API.

`normalize.py` converts provider data into SilkShield's internal schema.

This allows another provider to be added without rewriting the ML
pipeline.

## Cache

Cache intelligence results where appropriate.

Reasons:

-   reduce API calls
-   reduce latency
-   protect against rate limits
-   improve demo reliability

## Fallback

The demo must not completely fail if an external provider is
unavailable.

Use clearly labelled demo fixtures for offline testing.

Do not represent mock data as live intelligence.

## Security

-   API keys belong in environment variables.
-   Never commit `.env`.
-   Never log secrets.
-   Validate IOC input.
-   Do not automatically download or execute submitted files.
-   Treat external intelligence as untrusted data.
