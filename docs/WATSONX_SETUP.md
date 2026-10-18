# Connect SilkShield to IBM Granite through watsonx.ai

This guide connects the existing `GraniteProvider` in SilkShield to IBM watsonx.ai Runtime. The default provider remains `demo` until you explicitly configure live access.

## 1. Get the IBM credentials

In your IBM Cloud / watsonx.ai account:

1. Create or open a watsonx.ai project.
2. Ensure a watsonx.ai Runtime service is available and associated with the project.
3. Create an IBM Cloud API key permitted to call the Runtime service.
4. Open the project's **Developer access** page and copy the regional API base URL and project ID.
5. Confirm that the model `ibm/granite-4-h-small` is available in your region, and review the pricing/plan before sending requests.

Do not send the API key in chat, commit it, or paste it into a shell command. Type it into the server's ignored `.env` file.

## 2. Configure LinuxONE

From the project directory:

```bash
cd ~/SilkShield
source .venv/bin/activate
nano .env
```

Set these values. Use the exact regional URL and project ID from Developer access:

```dotenv
AI_PROVIDER=granite
GRANITE_API_URL=https://us-south.ml.cloud.ibm.com
GRANITE_API_KEY=PASTE_YOUR_KEY_IN_NANO_ONLY
WATSONX_PROJECT_ID=PASTE_YOUR_PROJECT_ID
GRANITE_MODEL_ID=ibm/granite-4-h-small
```

Replace the URL if your project is in another region. Keep the existing `VIRUSTOTAL_API_KEY` entry if you already configured it. Save and exit Nano with **Ctrl+O**, Enter, then **Ctrl+X**.

The repository ignores `.env`; never force-add it to Git.

## 3. Check configuration without printing secrets

```bash
python - <<'PY'
from app.config import settings
print("AI_PROVIDER:", settings.ai_provider)
print("GRANITE_API_URL configured:", bool(settings.granite_api_url))
print("GRANITE_API_KEY configured:", bool(settings.granite_api_key))
print("WATSONX_PROJECT_ID configured:", bool(settings.watsonx_project_id))
print("GRANITE_MODEL_ID:", settings.granite_model_id)
PY
```

All three `configured` checks should be `True`; no key/token is printed.

## 4. Run the Granite smoke test

```bash
python -m scripts.test_granite
```

Success prints `provider: granite` plus the summary from a small test call. The script never prints the API key or IAM token.

Common failures:
- **HTTP 401:** API key or IAM authentication issue.
- **HTTP 403:** service/project permissions or model access issue.
- **HTTP 404:** wrong regional URL, project configuration, or unavailable model.
- **Network error:** outbound HTTPS or regional endpoint connectivity problem.

## 5. Restart SilkShield and test the full pipeline

After the smoke test passes, restart the existing Uvicorn process so it reloads `.env`. In the Uvicorn terminal press **Ctrl+C**, then run:

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

From a second SSH session, test:

```bash
curl -s -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"ioc":"7b5bda1922a562be4cf5fc9203a83ed94323c462dc0e22fd8af440a0423079e6","type":"hash"}'
```

In the response, check `metadata.ai_provider` equals `granite`. If the API call fails, SilkShield reports an AI error rather than silently claiming the deterministic fallback was a live LLM.

The hash in this example is a synthetic repository demo fixture input, not a real malware sample. For an honest demo, make sure the returned `intelligence_source` says `virustotal_live` before claiming the threat intelligence is live.
