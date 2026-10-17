# SilkShield API Contract

## POST /analyze

Main analysis endpoint.

### Request

``` json
{
  "ioc": "example.com",
  "type": "domain"
}
```

`type` may be:

-   `domain`
-   `url`
-   `ip`
-   `hash`

The API may support automatic type detection later.

## Response

``` json
{
  "ioc": "example.com",
  "type": "domain",
  "risk_score": 87,
  "risk_level": "HIGH",
  "classification": "PHISHING",
  "confidence": 0.94,
  "evidence": [
    "Multiple threat intelligence detections",
    "Recently registered domain",
    "Suspicious infrastructure"
  ],
  "ai_analysis": "The IOC demonstrates characteristics consistent with credential phishing.",
  "recommendation": "BLOCK",
  "mitre": [
    "T1566.002"
  ],
  "metadata": {
    "analysis_version": "0.1.0"
  }
}
```

## GET /health

Expected response:

``` json
{
  "status": "ok",
  "service": "silkshield"
}
```

## Error Format

``` json
{
  "error": {
    "code": "INVALID_IOC",
    "message": "The supplied IOC could not be validated."
  }
}
```

## API Rules

1.  Never expose API keys.
2.  Do not return provider secrets.
3.  Normalize provider-specific fields before returning them.
4.  Keep the response stable so frontend and backend can work in
    parallel.
5.  AI-generated text must be clearly separated from deterministic
    evidence.
