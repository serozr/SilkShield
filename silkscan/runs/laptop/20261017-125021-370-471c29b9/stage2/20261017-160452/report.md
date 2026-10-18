# Stage 2: threat category and family · `20261017-125021-370-471c29b9/stage2/20261017-160452`

Taxonomy v1, precision target 0.8. Labels are AV consensus (ClarAVy).

| Split | Malware | With category | With family |
|---|---|---|---|
| test | 60,000 | 9,480 | 47,271 |
| train | 66,199 | 29,250 | 53,214 |
| validation | 40,000 | 7,207 | 29,453 |

## Categories (test, labelled malware)

| Category | Impact | Train positives | Status | Threshold | Test AP | Test precision | Test recall |
|---|---|---|---|---|---|---|---|
| backdoor | high | 816 | enabled | 0.957 | 0.675 | 79.2% | 38.8% |
| coinminer | medium | 8,860 | enabled | 0.500 | 0.983 | 98.7% | 92.5% |
| downloader | medium | 1,264 | enabled | 0.990 | 0.518 | 81.5% | 12.5% |
| infector | medium | 13,848 | enabled | 0.500 | 0.999 | 99.9% | 98.3% |
| pua | low | 1,257 | enabled | 0.500 | 0.841 | 80.7% | 69.2% |
| ransomware | high | 244 | enabled | 0.877 | 0.386 | 71.1% | 27.1% |
| stealer | high | 3,279 | enabled | 0.500 | 0.921 | 85.7% | 84.1% |

## Family

25 families + other; confidence threshold 0.272.

Test: coverage 30.8%, precision of emitted families 72.4%, top-1 accuracy on known families 45.3%, other/unseen families 50.9%.

## End to end (test files the detector flags)

57,172 flagged files (malicious 56,556, benign 616; zones {'malicious': 51095, 'suspicious': 6077}). Category assigned to 58.3% of flagged malware, family to 31.8%; 228 false positives also get a category. Category precision on labelled flagged malware: 94.3%.
