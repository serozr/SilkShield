# SilkShield ML Pipeline

## Goal

Predict the probability that an IOC represents a security threat and
convert that probability into a risk score.

## Initial Model

**XGBoost classifier**

Why:

-   fast to train
-   suitable for tabular data
-   handles mixed feature types after preprocessing
-   easy to benchmark
-   explainable enough for a datathon prototype

## Candidate Features

### Threat Intelligence

-   detection count
-   total engines
-   detection ratio
-   malicious votes
-   suspicious votes
-   reputation score
-   number of related indicators

### Domain / URL

-   domain age
-   URL length
-   number of subdomains
-   presence of IP address in URL
-   suspicious keyword indicators
-   HTTPS presence
-   redirect count where available

### Infrastructure

-   ASN reputation
-   country/region where available
-   DNS record count
-   related malicious infrastructure

## Target

Binary target:

``` text
0 = benign
1 = malicious
```

Optional multiclass target:

``` text
benign
phishing
malware
command_and_control
suspicious
```

## Risk Score

The model probability can be converted to:

``` text
risk_score = probability * 100
```

Risk bands:

``` text
0–24   LOW
25–49  MEDIUM
50–74  HIGH
75–100 CRITICAL
```

These thresholds are initial product defaults and should be tuned using
validation results.

## Evaluation

At minimum report:

-   accuracy
-   precision
-   recall
-   F1
-   ROC-AUC if binary probabilities are available
-   confusion matrix

For cybersecurity, pay particular attention to recall for malicious
samples and false positives.

## Required Output

The ML teammate should provide:

``` text
ml/
├── train.py
├── predict.py
├── model/
├── features.md
├── evaluation.md
└── requirements.txt
```

## Important

Do not claim that the model is production-grade. Clearly state the
dataset, split, limitations and evaluation results.
