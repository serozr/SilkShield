# silkscan HTTP API (v1)

Contract for clients such as a web UI. Start the service with `python -m silkscan.api --config configs/api.yaml`
(default `127.0.0.1:8090`; override with `--host`/`--port`). All bodies are JSON unless stated otherwise.

## Connecting a UI

- **Auth:** every request needs `Authorization: Bearer <key>` (keys come from `SILKSCAN_API_KEYS` on the server),
  except `GET /v1/health` (`health_auth_required: false` in `configs/api.yaml`).
  Do not ship the key to the browser: put the UI's own backend (or a reverse proxy) in front and let it add the header.
- **CORS:** the API sends no CORS headers. Serve the UI from the same origin as that backend/proxy.
- **SSE:** the browser `EventSource` cannot send `Authorization`. Either proxy `/v1/events` through the backend
  (which adds the header) or read the stream with `fetch()` (example below).

Typical UI flow:

1. Upload → `POST /v1/scan`. A `200` carries the verdict. A `202` means it is still running: poll
   `GET /v1/jobs/{job_id}` or wait for its event on the stream.
2. Live list → `GET /v1/events` (one event per finished scan, from any client).
3. Detail page → `GET /v1/verdicts/{sha256}` (add `?explain=K` on the upload to get feature explanations).
4. Header/status bar → `GET /v1/health`, `GET /v1/model`.

## Endpoints

| Method | Path | Request | Success |
|---|---|---|---|
| POST | `/v1/scan` | `multipart/form-data` with exactly one part named `file`, **or** raw bytes as `application/octet-stream` (+ optional `X-Filename`) | `200` verdict, or `202 {"job_id"}` + `Location` |
| POST | `/v1/scan/features` | one EMBER2024 raw-feature record (`application/json`) or many (`application/x-ndjson`, one per line) | `200` verdict, or an array of verdicts for NDJSON |
| GET | `/v1/jobs/{job_id}` | | `200 {"job_id", "status", "verdict"?, "error"?}` |
| GET | `/v1/verdicts/{sha256}` | | `200` latest verdict for this file under the active model |
| GET | `/v1/events` | header `Last-Event-ID` (optional), `?min_priority=P1..P4` | `text/event-stream` |
| GET | `/v1/model` | | model and check versions, thresholds |
| GET | `/v1/health` | | `200 {"status":"ok", "workers", "queue_depth", ...}` or `503` when degraded |
| GET | `/metrics` | | Prometheus text |

Query parameters for both scan endpoints:

| Parameter | Default | Meaning |
|---|---|---|
| `async` | `false` | `true`: return `202` at once instead of waiting up to `sync_timeout_s` (5 s) |
| `explain` | `0` | number of top features to explain (adds `explanation`; slower) |
| `source` | `""` | free label (e.g. `ui`), echoed in events |

Job `status`: `queued` → `running` → `done` (with `verdict`) or `failed` (with `error`).
Identical submissions are deduplicated: a repeat returns the stored verdict with header `X-SilkScan-Cache: hit`.

## Verdict

```jsonc
{
  "schema_version": "1",
  "id": "0026ced5…",                 // SHA-256 of the file
  "decision": "malicious",            // malicious | suspicious | clean | inconclusive | error
  "priority": "P2",                   // P1 (most urgent) … P4
  "action": "quarantine_and_review",  // see table below
  "reasons": ["model: malicious"],    // human-readable, show as a list
  "model_decision": "malicious",      // model alone; "skipped" when a check decided first
  "score": 0.99999,                   // model score 0–1 (not a probability); null if the model did not run
  "threshold": 0.99929,               // score >= threshold -> malicious
  "review_threshold": 0.97900,        // score >= review_threshold -> suspicious
  "file_kind": "exe",                 // exe | dll | null
  "classification": {                 // null unless malicious/suspicious
    "categories": [{"name": "infector", "score": 1.0, "impact": "medium"}],
    "family": {"name": "expiro", "confidence": 0.999}  // or null
  },
  "tags": ["family:expiro", "infector"],
  "checks": [{"check": "yara", "outcome": "hit", "severity": "high", "effect": "force_malicious",
              "tags": [], "evidence": ["EICAR_Test_File"], "message": null, "elapsed_ms": 0.2}],
  "feature_status": {"ember_v3": "OK", "section_summary": "OK", "import_semantics": "OK"},
  "explanation": {                    // only with ?explain=K
    "unit": "log-odds contribution",
    "by_group": {"ember_v3": 10.1, "section_summary": 2.6},
    "top_features": [{"feature": "section_summary.frac_write_execute",
                      "meaning": "section_summary.frac_write_execute", "contribution": 2.34}]
  },
  "model": {"run": "…", "backend": "lightgbm", "threshold_policy": "per_group"},
  "timing_ms": {"pre_checks": 0.3, "parse": 64.8, "post_checks": 0.0, "model": 10.8}
}
```

Ignore unknown fields; new ones may be added within schema version 1.

| Priority | When | `action` | Suggested UI |
|---|---|---|---|
| P1 | malicious and forced by a check, a high/critical rule hit, or a high-impact type (ransomware, backdoor, stealer, …) | `quarantine_and_alert` | red, alert |
| P2 | malicious (model), or suspicious with a high-impact type | `quarantine_and_review` | red |
| P3 | suspicious, inconclusive (incomplete analysis) or error | `review` | amber |
| P4 | clean | `allow` | green |

A file that could not be analysed is never `clean`.

## Events (`/v1/events`)

```
id: 42
event: verdict
data: {"id":"<sha256>","decision":"malicious","priority":"P1","score":null,"reasons":[…],"source":"ui","filename":"a.exe","at":"2026-10-17T15:04:05+00:00"}

: heartbeat
```

- Event IDs increase by one. Reconnect with `Last-Event-ID: <last id>` to receive what you missed.
- `event: reset` means that cursor is too old: reload the list, then continue.
- `?min_priority=P2` delivers P1 and P2 only.
- A client that reads too slowly is disconnected; reconnect with `Last-Event-ID`.
- Fetch the full verdict with `GET /v1/verdicts/{id}` when needed.

## Errors

Body: `{"error": "<message>"}` (for feature records: `{"error": {"line": 3, "message": "…"}}`).
Every response carries `X-Request-ID`; log it for support.

| Status | Meaning | Client action |
|---|---|---|
| 400 | bad `Content-Length` | fix request |
| 401 | missing/wrong key | check key |
| 404 | unknown job / no verdict for this hash | |
| 413 | file larger than `max_file_mb` (100 MB) | reject in UI before upload |
| 415 | wrong `Content-Type` | |
| 422 | invalid parameter, multipart or feature record | show message |
| 429 | rate limit (600/min per key) | wait `Retry-After` seconds |
| 503 | queue full or service not ready (`Retry-After`), or scan worker failed | retry later |
| 500 | internal error | report `X-Request-ID` |

## Examples

```bash
curl -H "Authorization: Bearer $KEY" -F file=@sample.exe "http://localhost:8090/v1/scan?source=ui&explain=5"
curl -H "Authorization: Bearer $KEY" --data-binary @sample.exe -H "Content-Type: application/octet-stream" \
     -H "X-Filename: sample.exe" "http://localhost:8090/v1/scan?async=true"
curl -N -H "Authorization: Bearer $KEY" "http://localhost:8090/v1/events?min_priority=P2"
```

```js
// Upload and wait for the verdict (via the UI backend, which adds the Authorization header).
async function scan(file) {
  const form = new FormData();
  form.append("file", file);
  let r = await fetch("/v1/scan?source=ui", { method: "POST", body: form });
  if (r.status === 200) return r.json();
  if (r.status !== 202) throw new Error((await r.json()).error);
  const { job_id } = await r.json();
  for (;;) {
    await new Promise((ok) => setTimeout(ok, 500));
    const job = await (await fetch(`/v1/jobs/${job_id}`)).json();
    if (job.status === "done") return job.verdict;
    if (job.status === "failed") throw new Error(job.error);
  }
}

// Live feed without EventSource (works with an Authorization header).
async function follow(onVerdict, lastId) {
  const headers = lastId ? { "Last-Event-ID": String(lastId) } : {};
  const r = await fetch("/v1/events", { headers });
  const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return follow(onVerdict, lastId);           // reconnect and resume
    buf += value;
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i); buf = buf.slice(i + 2);
      const id = block.match(/^id: (\d+)/m), data = block.match(/^data: (.*)$/m);
      if (/^event: verdict/m.test(block) && data) { lastId = id && +id[1]; onVerdict(JSON.parse(data[1])); }
    }
  }
}
```
