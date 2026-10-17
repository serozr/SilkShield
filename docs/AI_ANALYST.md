# SilkShield AI Security Analyst

## Purpose

The AI layer converts structured security evidence into an
analyst-friendly explanation and recommendation.

## Important Architecture Rule

Do not ask the LLM to independently decide whether an IOC is malicious
without evidence.

Instead:

``` text
External Intelligence
        +
ML Result
        +
Structured Features
        ↓
    AI Analyst
        ↓
Explanation + Recommendation
```

## Input Example

``` json
{
  "risk_score": 93,
  "classification": "PHISHING",
  "confidence": 0.96,
  "evidence": [
    "17/94 engines detected the IOC",
    "Domain age is 6 days",
    "Suspicious infrastructure",
    "Credential-harvesting URL characteristics"
  ]
}
```

## Expected Output

``` json
{
  "summary": "High-risk credential phishing indicator.",
  "reasoning": [
    "Multiple independent detections support the risk assessment.",
    "The infrastructure is recently registered.",
    "The URL contains characteristics associated with credential harvesting."
  ],
  "recommendation": "BLOCK",
  "mitre": ["T1566.002"]
}
```

## Granite

If IBM Granite is available in the environment, use it as the preferred
generative AI layer.

If the model cannot be deployed in time, implement an abstraction:

``` text
AIProvider
├── GraniteProvider
└── DemoFallbackProvider
```

This keeps the architecture honest and prevents the whole demo from
depending on one deployment path.

## Prompt Rules

The system prompt should instruct the model to:

1.  Use only supplied evidence.
2.  Distinguish evidence from inference.
3.  Avoid inventing detections.
4.  Avoid claiming certainty.
5.  Recommend defensive actions only.
6.  Return structured output.
7.  Mention missing evidence when relevant.

## RAG

Potential knowledge sources:

-   MITRE ATT&CK
-   defensive security guidance
-   relevant public threat intelligence documentation

RAG should be used to ground explanations and ATT&CK references.

## AI Safety

The analyst should never execute code, download malware, or provide
offensive instructions as part of the analysis workflow.
