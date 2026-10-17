# silkscan

Static malware detection for Windows PE files (Win64), trained on EMBER2024 with LightGBM. Runs on x86_64 and IBM Z (s390x).

A scan runs in this order:

1. **Pre-checks.** File format gate, SHA-256 deny/allow lists and YARA.
2. **Parsing.** Static PE parsing, only if no pre-check already decided.
3. **Detection model.** Three-zone decision: `malicious` / `suspicious` / `clean`.
4. **Threat type.** Threat category and family for flagged files.

Files are never executed.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[ember]'          # core + official EMBER v3 feature extractor
pip install -e '.[checks,api]'     # optional: YARA, HTTP API
pip install -e '.[snapml]'         # optional, IBM Z: Snap ML / NNPA backends
```

Python ≥ 3.10.

## Train

```bash
export EMBER2024_DIR=/data/ember2024        # thrember.download_dataset(EMBER2024_DIR, file_type="Win64")
silkscan manifest -c configs/win64.yaml       # splits + temporal validation
silkscan features -c configs/win64.yaml       # cached features
silkscan train    -c configs/win64.yaml       # -> runs/<run>/
RUN=runs/<run>
silkscan threshold --run $RUN --policy auto        # separate EXE/DLL thresholds
silkscan threshold --run $RUN --review-fpr 0.01    # suspicious zone
silkscan train-type --run $RUN                     # threat category + family -> $RUN/stage2/<id>/
silkscan hashlist -c configs/win64.yaml --splits train validation --out work/win64/hashes/known_malicious.npy
silkscan evaluate --run $RUN                       # test + challenge report
```

All thresholds are selected on the validation split. Outputs are model scores, not probabilities.
Results of the current model, ablation and threat typing: [RESULTS.md](RESULTS.md).

## Evaluate on other data

```bash
python scripts/pe_to_jsonl.py --malicious mal/ --benign clean/ --out mine.jsonl   # static parsing only
silkscan evaluate --run $RUN --jsonl mine.jsonl --name mine                          # no EMBER data needed
```

Records must be in the EMBER2024 feature format (v3). Other datasets need their raw PE files to be converted this way.

## Move a model to another machine

Copy the run directory, the hash list and `configs/serving.yaml`. Then check that the scores match:

```bash
python scripts/check_parity.py --serving configs/serving.yaml --records parity/records.jsonl --write parity/expected.jsonl   # source
python scripts/check_parity.py --serving configs/serving.yaml --records parity/records.jsonl --expected parity/expected.jsonl  # target
```

## Serve

The repository includes the served model (`runs/laptop/20261017-125021-370-471c29b9`), its known-malicious hash list and the parity records, so `configs/serving.yaml` works right after cloning. To serve another model, edit `configs/serving.yaml`. Set `run` and `stage2` to your trained model, and point `hash_list.deny` to your hash list.

**CLI:**

```bash
silkscan predict --serving configs/serving.yaml --pe file.exe [--explain 5]
silkscan predict --serving configs/serving.yaml --jsonl records.jsonl
```

**HTTP API:**

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"   # generate a key; store it outside the repo
export SILKSCAN_API_KEYS=<key>                               # several keys: comma-separated (e.g. one per client)
python -m silkscan.api --config configs/api.yaml
```

The service refuses to start without a key (unless `auth_required: false`). Keys are never read from files in
the repository. Give each client (e.g. the SilkShield backend) its own key and send it as `Authorization: Bearer <key>`;
to rotate, start with both the old and new key, update the client, then remove the old key. For a service, keep the
variable in an environment file readable only by the service user (e.g. systemd `EnvironmentFile=`).

| Endpoint | Purpose |
|---|---|
| `POST /v1/scan` | file as multipart `file` or `application/octet-stream`; `?async=true`, `?explain=K` |
| `POST /v1/scan/features` | EMBER raw-feature record (JSON) or batch (NDJSON) |
| `GET /v1/jobs/{id}`, `GET /v1/verdicts/{sha256}` | async results, cached verdicts |
| `GET /v1/events` | verdict stream (SSE; `Last-Event-ID`, `?min_priority=P2`) |
| `GET /v1/model`, `GET /v1/health`, `GET /metrics` | model info, readiness, Prometheus metrics |

Send `Authorization: Bearer <key>` with every request except `GET /v1/health`. The service listens on `127.0.0.1:8090` (change in `configs/api.yaml` or with `--host`/`--port`). Full contract for UI and other clients: [API.md](API.md).

**Verdict fields:**

| Field | Meaning |
|---|---|
| `decision` | `malicious` / `suspicious` / `clean` / `inconclusive` / `error` |
| `priority` | `P1`–`P4` |
| `action` | `quarantine_and_alert` / `quarantine_and_review` / `review` / `allow` |
| `reasons` | why the decision was made |
| `score`, `threshold`, `model_decision` | model output and the threshold applied |
| `classification` | threat categories and family |
| `checks` | results of each check |
| `feature_status` | extraction status per feature group |
| `timing_ms` | time per stage |

A file that could not be analysed is never reported as `clean`.

## Extend

- **YARA rules:** `rules/yara/*.yar`. Rule meta `severity`, `tags` and `effect` are read.
- **Hash lists:** `rules/hashes/{deny,allow}.txt` (one SHA-256 per line), or `.npy` lists from `silkscan hashlist`.
- **Custom checks:** subclass `silkscan.checks.Check` and register it in `silkscan/checks/__init__.py` (see `examples/custom_check.py`).
- **Feature groups:** subclass `silkscan.features.base.FeatureExtractor`, register it in `silkscan/features/groups/__init__.py`, and enable it in the config (see `examples/custom_extractor.py`).

## IBM Z

```bash
sudo apt install python3-venv python3-dev python3-numpy python3-scipy python3-sklearn python3-yaml \
    python3-yara cmake g++ make git                       # Ubuntu; other distributions: same python3-* packages
scripts/z_setup.sh --system-packages --api --yara --snapml   # checks arch/NNPA, installs, runs tests
python scripts/fetch_ember2024.py --out /data/ember2024  # or copy the extracted files from another machine
export EMBER2024_DIR=/data/ember2024
scripts/train_all.sh                                      # full pipeline -> configs/serving.s390x.yaml
python -m silkscan.api --config configs/api.yaml            # set serving: configs/serving.s390x.yaml first
```

- **Dependencies:** PyPI has no s390x wheels for numpy, scipy, scikit-learn, LightGBM or yara-python. `--system-packages` uses the distribution's packages, so only LightGBM is compiled (needs `cmake`, `g++`, `make`). On s390x, `z_setup.sh` installs only the parts of `thrember` that its feature extractor needs.
- **Rehearsal on x86_64:** `scripts/docker_s390x.sh` builds the same install for `linux/s390x` under QEMU, runs the tests and checks parity with the trained model (see the script header for the one-time QEMU setup). Emulation is slow and has no NNPA.
- **Memory:** full Win64 training needs about 10 GB of RAM. With less, set `data.train_fraction` below 1.0.
- **Snap ML backends:** `train_all.sh` uses `snapml-nnpa` when NNPA (z16 or later) and Snap ML are available, after selecting a separate validation threshold for it.
- **Byte order:** arrays on disk are little-endian on every platform, so caches and models move between x86_64 and s390x unchanged. scikit-learn's feature hashing (used by thrember for imports, exports, sections and the Rich header) depends on byte order; on big-endian machines `silkscan.features.hashing` makes it hash like x86, so a model trained on either platform sees the same columns.
- **Data path:** run directories store `${EMBER2024_DIR}` rather than a machine-specific path. Serving does not need the data.

## Test

```bash
pip install -e '.[dev,api,checks]'
pytest -q
```
