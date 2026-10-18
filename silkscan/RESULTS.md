# Results

## Summary

SilkScan flags malicious Windows executables (Win64 EXE/DLL) without running them, decides at an operational
false-alarm budget, names the threat type, and serves verdicts over an HTTP/SSE API. Main results on the held-out
test months (Sep–Dec 2024):

| Malware recall | False-positive rate | ROC-AUC | Recall incl. review zone* | File scan (x86_64 laptop) |
|---|---|---|---|---|
| **85.1 %** | **0.085 %** | **0.998** | **93.9 %** | **~85 ms** per file |

\* validation; the review zone sends 6 % of all files to an analyst.

Pipeline: upload → PE-format gate, SHA-256 deny/allow lists, YARA (decide before any parsing) → static features
(thrember, isolated process) → LightGBM with separate EXE/DLL thresholds and a review zone → threat category and family
→ verdict with priority, action and reasons.

## Protocol

- **Data:** EMBER2024, Win64 only. Each record appears twice in the weekly files; we keep one copy.
- **Splits:**
  - train: 132k files (deterministic 30 % sample of the training weeks);
  - validation: the last 8 training weeks (80k, of which 40k benign);
  - test: Sep–Dec 2024 (120k);
  - challenge: 814 evasive samples.
- **No hash overlap between splits:** 0 shared SHA-256 among the full training weeks (440k), validation, test and
  challenge. The manifest stops with an error if any file appears in two splits.
- **Thresholds:** every threshold is chosen on validation. Test and challenge are only reported.
- **Uncertainty:** 95 % bootstrap intervals in brackets.
- **Model-only metrics:** detection metrics are model-only. Hash lists and YARA are not involved.
- **Model:** LightGBM (EMBER2024 benchmark settings: 500 rounds, learning rate 0.1, 64 leaves, `is_unbalance`,
  seed 0; no hyperparameter search) on 2618 features (EMBER v3 + `section_summary` + `import_semantics`). Training takes
  about 160 s on an x86_64 laptop.
- **Scores:** model scores, not probabilities.

## Detection (test)

Target FPR 0.1 %. Separate EXE/DLL thresholds.

| | Benign / malicious | ROC-AUC | Recall | FPR |
|---|---|---|---|---|
| **All** | 59,993 / 60,000 | **0.998** | **85.1 %** [84.8, 85.3] | **0.085 %** [0.060, 0.110] |
| EXE | 15,535 / 56,777 | 0.996 | 85.7 % | 0.109 % [0.064, 0.161] |
| DLL | 44,458 / 3,223 | 0.992 | 74.8 % | 0.076 % |

Recall at 1 % FPR: 96.9 %.

**Precision depends on how common malware is.** On the balanced test set precision is 99.9 % (51 false alarms out of
60k benign files). In deployment malware is rarer. At the same recall and FPR:

| Malware share | Precision | Alarms per 100k files (false) |
|---|---|---|
| 50 % (test set) | 99.9 % | 42,579 (42) |
| 10 % | 99.1 % | 8,584 (76) |
| 1 % | 91 % | 935 (84) |
| 0.1 % | 50 % | 170 (85) |

The false-alarm count stays near 85 per 100k files. This is why decisions come with a priority and a review zone,
rather than a single yes/no.

**Why separate EXE/DLL thresholds.** With one threshold the overall FPR looked fine (0.075 %), but only because 74 % of
benign files are DLLs:
- EXE false alarms ran at 0.27 %, 2.7× the target;
- half of the malicious DLLs were missed.

| Test | Single threshold | EXE/DLL thresholds |
|---|---|---|
| EXE FPR | 0.27 % | **0.11 %** |
| DLL recall | 52 % | **75 %** |
| Overall recall | 87.8 % | 85.1 % |

**Three-zone decision (validation).**
- At 0.1 % FPR, 82.9 % of malware is flagged automatically.
- With the suspicious zone, 93.9 % is flagged.
- The review queue holds 6 % of files and receives 0.9 % of benign files.

**Over time (test months, recall / FPR).** No downward trend over four months. FPR varies between 0.05 % and 0.12 %.

| Sep | Oct | Nov | Dec |
|---|---|---|---|
| 82.2 % / 0.09 % | 82.4 % / 0.10 % | 88.1 % / 0.05 % | 86.1 % / 0.12 % |

**Challenge (evasive samples).**
- **Automatic:** 5.0 % flagged.
- **With the review zone:** 31.6 % flagged (EXE 26 %, DLL 50 %).
- **Score distribution:** median score 0.665. Only 3.6 % reach the EXE threshold.
- **Against test benign files:** ROC-AUC 0.932, recall at 1 % FPR 47.8 %.
- **Why they are missed:** explanations show these samples lack the usual static signs (writable+executable
  sections, unusual headers, missing signatures). Static features alone do not catch them.

## Ablation

5 variants × 3 seeds, with a single threshold at 0.1 % FPR. This is a different operating point from the EXE/DLL
thresholds above, so its recall is higher (88 % vs 85 %).

| Feature groups | Columns | Test AUC | Test recall |
|---|---|---|---|
| EMBER v3 | 2568 | 0.9979 | 88.8 % ± 0.2 |
| EMBER v3 + import_semantics | 2592 | 0.9980 | 88.8 % ± 0.2 |
| EMBER v3 + section_summary | 2594 | 0.9979 | 88.7 % ± 0.4 |
| all three | 2618 | 0.9980 | 88.2 % ± 0.5 |
| **section_summary + import_semantics only** | **50** | **0.9942** | **76.5 % ± 1.5** |

- **No measurable gain from our two groups.** Differences are within 2 standard deviations. The groups stay in the
  model because they make explanations readable.
- **50 readable columns alone reach AUC 0.994.** This makes a small, more readily interpretable model.
  `section_summary.frac_write_execute` (share of writable+executable sections) ranks 4th of all 2618 features.
- **Removing "shortcut" columns does not change the model.** Removed: DLL flag, exports, signatures, security
  directory. AUC and the EXE/DLL imbalance stayed the same: the model rebuilds the information from other columns.
  The imbalance comes from the data mix, so we handled it with thresholds.
- **capa capabilities:** no measurable gain (AUC 0.9981 vs 0.9980). Not used.

## Threat type (stage 2)

- **Model:** one binary model per category. Each threshold meets 0.8 precision on validation, with a floor of 0.5.
- **Labels:** AV consensus (ClarAVy). Only 16 % of test malware has a category label.
- **Measured on:** the 9,480 test malware files that have a category label.

| Category | Impact | Test positives | Precision | Recall |
|---|---|---|---|---|
| infector | medium | 4,277 | 99.9 % | 98.3 % |
| coinminer | medium | 1,265 | 98.7 % | 92.5 % |
| stealer | high | 1,512 | 85.7 % | 84.1 % |
| pua | low | 1,160 | 80.7 % | 69.2 % |
| backdoor | high | 667 | 79.2 % | 38.8 % |
| downloader | medium | 702 | 81.5 % | 12.5 % |
| ransomware | high | 199 | 71.1 % | 27.1 % |

- **End to end:** 94.3 % category precision. Measured on test malware that the detector flagged, that has a
  category label and that received a category. A file counts as correct when every assigned category is among its labels.
- **Coverage:** 58 % of flagged malware gets a category, 32 % a family. Family names are correct 72 % of the time.
- **Why the 0.5 floor:** without it, coinminer precision fell from 80 % on validation to 57 % on test as category
  frequencies shifted. With the floor it is 98.7 %.

## Service

- **Checks before the model:** hash lists, YARA and the PE-format gate decide before parsing. Known training malware
  is flagged P1 in about 1 ms.
- **API = core:** 2,000 test records gave 0 differences between the HTTP API and the core `scan()`. Every verdict
  reached the SSE stream in order.
- **Throughput (x86_64 laptop, 2 workers):**
  - file upload: about 85 ms per file, 28 files/s;
  - feature records: 520 records/s, or 104/s with explanations.

## IBM Z

- **Portability:** rehearsed under `linux/s390x` QEMU emulation (big-endian). The x86_64-trained model gives the same
  verdicts on 320 records (score difference 0.0), and all tests pass.
- **Not yet measured:** performance on real IBM Z hardware, NNPA and Snap ML.

## Engineering findings

| Finding | Effect | Fix |
|---|---|---|
| scikit-learn feature hashing depends on byte order | On big-endian machines 1643 of 2618 columns move; 58 of 320 verdicts change | byte-swap before hashing |
| oscrypto 1.3.0 cannot parse OpenSSL 3.0.13 | Feature extractor fails to import on Ubuntu 24.04 | pin upstream fix |
| capa fields sit in only one of the two copies of each record | Reading first copies only: "capa present" in 77 % of benign vs 0 % of malicious training files, a label leak | merge copies; capa not used |
| Single detection threshold | EXE FPR 2.7× target, DLL recall 52 % | EXE/DLL thresholds |
| Category threshold at the precision edge | coinminer precision 57 % on test | 0.5 threshold floor |

## Limitations

- Trained on 30 % of the training data. Full-data training on IBM Z is the next step.
- Evasive malware: 5 % flagged automatically, 32 % with review.
- Low recall for rare high-impact categories (ransomware 27 % on 199 files, backdoor 39 %).
- The EXE threshold rests on about 12 allowed false alarms in validation, which is narrow. Its test interval
  [0.064, 0.161] % includes the target.
- Only AMD64 files are scored. Other machine types (e.g. 32-bit x86) go to review.
