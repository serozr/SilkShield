# SilkShield Team Tasks

## Team Lead --- Integration

Owner: Team lead

Tasks:

-   architecture
-   repository
-   API contract
-   backend integration
-   LinuxONE deployment
-   merge team contributions
-   final demo
-   technical pitch

Priority:

**P0 --- highest**

## Dataset / ML

Tasks:

-   find suitable labelled dataset
-   clean data
-   feature engineering
-   train XGBoost
-   evaluate model
-   export model
-   document limitations

Deliverables:

``` text
ml/train.py
ml/predict.py
ml/model/
ml/features.md
ml/evaluation.md
```

## AI / Granite

Tasks:

-   Granite integration if available
-   analyst prompt
-   structured output
-   RAG prototype
-   fallback provider

Deliverables:

``` text
ai/analyst.py
ai/prompts.py
ai/rag.py
```

## Threat Intelligence

Tasks:

-   VirusTotal adapter
-   IOC parser
-   response normalization
-   caching
-   demo fixtures

Deliverables:

``` text
intelligence/virustotal.py
intelligence/ioc.py
intelligence/normalize.py
```

## Frontend

Tasks:

-   dashboard
-   IOC input
-   threat score
-   evidence
-   AI explanation
-   recommendation

Frontend may use mocked API responses until the backend contract is
stable.

## Presentation / Pitch

Tasks:

-   problem
-   solution
-   novelty
-   architecture
-   AI/ML
-   IBM LinuxONE
-   demo
-   impact
-   future roadmap

## Integration Rules

-   Work from the shared API contract.
-   Use feature branches.
-   Keep secrets out of Git.
-   Do not rewrite another teammate's module without coordination.
-   Every contribution must be runnable or documented.

## Priority Order

``` text
P0: End-to-end MVP
P1: Real intelligence integration
P1: ML scoring
P1: AI explanation
P1: LinuxONE deployment
P2: polished UI
P2: threat graph
P2: RAG
P3: extra integrations
```
