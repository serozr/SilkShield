# SilkShield

## AI-Powered Real-Time Threat Decision Engine

SilkShield is a cybersecurity platform that transforms raw threat
intelligence into explainable security decisions using machine learning
and generative AI.

### Datathon Track

**Theme 1 --- Real-Time AI for Critical Decisions**

Core pipeline:

``` text
IOC
 ↓
Threat Intelligence
 ↓
Feature Extraction
 ↓
ML Risk Scoring
 ↓
AI Security Analysis
 ↓
Explainable Decision
 ↓
Recommended Response
```

### Core Product Idea

SilkShield is inspired by the threat-intelligence workflow of platforms
such as VirusTotal, but its goal is not to clone VirusTotal.

**VirusTotal-style systems aggregate detections. SilkShield turns those
signals into an explainable security decision.**

### MVP Inputs

-   URL
-   Domain
-   IP address
-   File hash

### MVP Outputs

-   Threat score: 0--100
-   Risk level
-   Threat classification
-   Confidence
-   Evidence
-   AI explanation
-   Recommended action
-   Optional MITRE ATT&CK mapping

### Proposed Stack

-   Python
-   FastAPI
-   XGBoost
-   IBM Granite / compatible GenAI layer
-   RAG knowledge base
-   VirusTotal API
-   Streamlit or React frontend
-   IBM LinuxONE / s390x deployment

### Run SilkShield locally

Python 3.10 or newer is recommended. From the repository root, create an
environment, install the requirements, and copy the example configuration:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
test -f .env || cp .env.example .env
```

The default `AI_PROVIDER=demo` needs no model server or AI credentials. Start
the API bound to loopback:

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another terminal, check the service and submit a benign example domain:

```bash
curl -sS http://127.0.0.1:8000/health
curl -sS -X POST http://127.0.0.1:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"ioc":"google.com","type":"domain"}'
```

The API may use live VirusTotal data when `VIRUSTOTAL_API_KEY` is configured;
otherwise it may use a clearly labelled demo fixture or local fallback. Check
`metadata.intelligence_source` in the response before interpreting evidence.
The local Granite setup is optional; see
[docs/LOCAL_LLM_SETUP.md](docs/LOCAL_LLM_SETUP.md).

### Open the dashboard

The FastAPI service serves the dashboard and its static assets; no separate
frontend build or server is required. Open `http://127.0.0.1:8000/` on the
machine running the API.

For the loopback-only LinuxONE deployment, create a Local SSH tunnel in PuTTY:
under **Connection → SSH → Tunnels**, set **Source port** to `8000`,
**Destination** to `127.0.0.1:8000`, select **Local**, click **Add**, then
connect to the VM. Open `http://127.0.0.1:8000/` in the workstation browser.
If local port `8000` is already in use, choose source port `18000` and open
`http://127.0.0.1:18000/`; keep the destination at `127.0.0.1:8000`.

The **Quick test** chips use the same `/analyze` pipeline. The response labels
show whether intelligence is live, cached, a demo fixture, or a local fallback;
never present fixture or cached data as live intelligence.

The deployment script and Docker Compose expose the API only on loopback.
For remote administration, use an SSH tunnel instead of exposing port 8000
publicly (for example, `ssh -L 8000:127.0.0.1:8000 user@server`). The API does
not provide authentication; do not bind it to a public interface without a
separately configured access-control layer.

### Run the local Granite LLM (no paid API)

A local `llama.cpp` server can be used by setting `AI_PROVIDER=local`,
`LOCAL_LLM_API_URL=http://127.0.0.1:8080/v1/chat/completions`, and
`LOCAL_LLM_MODEL_ID=local-granite` in `.env`. Keep the local model server
running while using the SilkShield API. See
[docs/LOCAL_LLM_SETUP.md](docs/LOCAL_LLM_SETUP.md).

### Run tests

```bash
python -m unittest discover -s tests -v
```

### Decision guardrails

The LLM provides an evidence-grounded explanation; the final action is validated against the risk score (`0–24`: `ALLOW`, `25–49`: `MONITOR`, `50–100`: `BLOCK`). MITRE ATT&CK techniques and mitigations are sourced from the local retrieval layer, not accepted directly from model-generated claims. Low-risk and benign IOCs do not receive inferred techniques by default.

### IBM Granite / watsonx.ai setup

See [docs/WATSONX_SETUP.md](docs/WATSONX_SETUP.md) for credentials, environment configuration, and a safe connectivity test. The demo provider remains the default until live Granite access is configured.

### Important MVP Principle

The first milestone is a complete vertical slice:

``` text
IOC → intelligence → features → model → AI explanation → dashboard
```

Do not build secondary features until this path works end-to-end.

### Judging Alignment

The competition judging material emphasizes:

1.  Community value and theme alignment
2.  Novelty and idea originality
3.  Technical design, IBM Z/LinuxONE and AI/ML
4.  Execution and delivery

SilkShield should explicitly demonstrate all four.
