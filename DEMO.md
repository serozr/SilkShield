# SilkShield Demo Plan

## Demo Goal

Show a complete real-time security decision from IOC input to AI
recommendation.

## Demo Flow

### 1. Introduce the problem

Security analysts receive fragmented threat intelligence and must
manually interpret it.

### 2. Enter IOC

Use a prepared safe demonstration IOC or known test fixture.

Do not use an unknown real-world target without authorization.

### 3. Analyze

Show:

``` text
IOC
 ↓
Threat Intelligence
 ↓
ML
 ↓
AI
```

### 4. Show Result

Highlight:

-   risk score
-   classification
-   evidence
-   AI explanation
-   recommended action

### 5. Explain Difference

Suggested wording:

> "Traditional threat intelligence tells an analyst what was detected.
> SilkShield turns those signals into an explainable security decision."

### 6. Show IBM LinuxONE

Display the backend/runtime evidence showing the prototype running on
IBM LinuxONE.

### 7. Optional Threat Graph

Show relationships between:

``` text
File → Domain → IP → Infrastructure
```

## Demo Safety

Use prepared, authorized, non-destructive test data.

Do not execute malware during the demo.

Do not scan systems that the team does not own or have permission to
test.

## Failure Plan

If live external intelligence fails:

1.  Explain that the provider is unavailable.
2.  Switch to clearly labelled cached/demo intelligence.
3.  Continue the ML + AI analysis.

Never pretend cached data is live.
