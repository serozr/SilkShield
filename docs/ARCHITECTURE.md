# SilkShield Architecture

## 1. High-Level Architecture

``` text
                    USER
                     |
                     v
              SILKSHIELD UI
                     |
                     v
                FastAPI API
                     |
        +------------+-------------+
        |            |             |
        v            v             v
   IOC Parser   Threat Intel   Feature Engine
                    |             |
                    |             v
                    |        ML Risk Model
                    |             |
                    +------+------+
                           |
                           v
                    Decision Engine
                           |
                    +------+------+
                    |             |
                    v             v
              AI Security     MITRE Mapping
                Analyst
                    |
                    v
             Explainable Result
                    |
                    v
               UI / Report
```

## 2. Components

### Frontend

Responsible for:

-   IOC input
-   analysis status
-   threat score
-   classification
-   evidence
-   AI explanation
-   recommendation
-   related indicators

### API

FastAPI is the integration layer.

Responsibilities:

-   validate requests
-   route analysis jobs
-   combine intelligence and ML results
-   invoke AI analysis
-   return one normalized response

### IOC Parser

Detects the IOC type:

-   URL
-   domain
-   IPv4/IPv6
-   SHA256/SHA1/MD5

### Threat Intelligence Layer

Normalizes external intelligence into a common internal format.

Initial provider:

-   VirusTotal

Possible later providers:

-   AbuseIPDB
-   WHOIS/domain metadata
-   DNS intelligence
-   MITRE ATT&CK

### ML Engine

Consumes normalized numerical/categorical features and produces a risk
probability.

Initial model:

-   XGBoost

### AI Analyst

Consumes structured evidence, not raw untrusted text alone.

Produces:

-   explanation
-   threat classification
-   confidence narrative
-   recommended response
-   relevant ATT&CK techniques where supported

### Decision Engine

Combines deterministic signals and model output into the final security
decision.

### LinuxONE Runtime

The application backend and ML/AI components should be deployed or
demonstrated on IBM LinuxONE where technically feasible.

## 3. Design Principle

The system should remain useful if the AI layer is unavailable.

Therefore:

``` text
Threat Intelligence + ML = deterministic core
AI = explanation and analyst assistance
```

AI must not be the only source of the threat score.
