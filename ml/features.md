# SilkShield ML Feature Engineering

This document outlines the feature set engineered for the SilkShield XGBoost risk scoring engine.

## Overview

The model takes 18 numerical features extracted from raw IOC metadata and threat intelligence telemetry to output a calibrated threat probability (0.0 to 1.0) and associated risk score (0 to 100).

## Feature Matrix

| # | Feature Name | Type | Description | Source |
|---|--------------|------|-------------|--------|
| 1 | `detection_count` | int | Number of security engines flagging the IOC as malicious | VT / TI Engines |
| 2 | `total_engines` | int | Total number of scanning engines evaluated | VT / TI Engines |
| 3 | `detection_ratio` | float | `detection_count / total_engines` (normalized signal) | Derived |
| 4 | `reputation` | int | Community reputation score (typically -100 to +100) | TI Metadata |
| 5 | `related_count` | int | Count of associated indicators (subdomains, IPs, dropped hashes) | Graph / TI |
| 6 | `malicious_votes` | int | Direct malicious community votes | Community Telemetry |
| 7 | `suspicious_votes` | int | Community suspicion votes | Community Telemetry |
| 8 | `domain_length` | int | Character length of the target domain | Lexical Analysis |
| 9 | `subdomain_count` | int | Number of dot-separated subdomains | Lexical Analysis |
| 10 | `has_ip_in_name` | binary | 1 if domain or host looks like an IPv4 address, else 0 | Lexical Analysis |
| 11 | `suspicious_keywords`| int | Count of phishing/credential keywords present (e.g. login, verify, crypto) | Lexical Analysis |
| 12 | `url_length` | int | Length of full URL if IOC is a URL, else 0 | Lexical Analysis |
| 13 | `has_https` | binary | 1 if URL protocol is HTTPS, else 0 | Lexical Analysis |
| 14 | `path_depth` | int | Directory nesting depth in URL path | Lexical Analysis |
| 15 | `has_query` | binary | 1 if query parameters exist in URL, else 0 | Lexical Analysis |
| 16 | `asn_reputation` | int | Reputation proxy score of autonomous system / hosting provider | Network Telemetry |
| 17 | `dns_record_count` | int | Count of resolved DNS records (low or zero can be suspicious) | Network Telemetry |
| 18 | `domain_age_days` | int | Days since domain registration (newly registered domains are higher risk) | WHOIS / Metadata |

## Feature Extraction Pipeline

1. **Parser**: `intelligence.ioc.detect_ioc_type` identifies whether the target is an IP, domain, URL, or hash.
2. **Extraction**: `ml.features.extract_features` calculates lexical and behavioral signals combined with raw threat telemetry.
3. **Vectorization**: `ml.features.features_to_array` packs the values into an ordered float matrix matching `FEATURE_NAMES`.
4. **Inference**: Fed into `XGBClassifier.predict_proba()` to compute probability of maliciousness.
