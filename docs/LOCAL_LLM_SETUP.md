# Local Granite LLM on IBM LinuxONE

SilkShield can use the Granite model running locally through `llama.cpp`. No cloud AI API key is needed. The local inference server must remain running on the same LinuxONE VM.

## 1. Keep two terminals open

**Terminal A — local model server:** leave the running command alive. It should say:

```text
model loaded
listening on http://127.0.0.1:8080
```

Keep it bound to `127.0.0.1`; do not expose the model server to the public network.

**Terminal B — SilkShield app:** update the repository and activate its venv:

```bash
cd ~/SilkShield
git pull --ff-only
source .venv/bin/activate
```

## 2. Configure SilkShield

Edit the existing ignored `.env` file:

```bash
nano .env
```

Set or add:

```dotenv
AI_PROVIDER=local
LOCAL_LLM_API_URL=http://127.0.0.1:8080/v1/chat/completions
LOCAL_LLM_MODEL_ID=local-granite
```

Leave other entries such as `VIRUSTOTAL_API_KEY` unchanged. Save with **Ctrl+O**, Enter, then **Ctrl+X**. The local model server accepts the client-side model label `local-granite`; llama.cpp returns its real model name in the response.

## 3. Restart SilkShield API

In the terminal running Uvicorn, press **Ctrl+C**, then restart:

```bash
cd ~/SilkShield
source .venv/bin/activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

This reloads `.env`. Do not stop the separate llama.cpp server.

## 4. Run an end-to-end IOC analysis

From the second SSH terminal:

```bash
curl -sS --max-time 150 -X POST http://127.0.0.1:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"ioc":"google.com","type":"domain"}'
```

Confirm the response metadata contains:

```json
"ai_provider": "local_granite"
```

That metadata value proves the app selected the local LLM provider. The response's `intelligence_source` separately identifies whether threat intelligence came from a live service, a fixture, cache, or local fallback.

## Troubleshooting

- **Connection refused to port 8080:** the llama.cpp server is not running; check Terminal A.
- **Provider remains `demo_fallback`:** confirm `AI_PROVIDER=local` in `.env` and restart Uvicorn.
- **Slow request or invalid JSON:** the small 1B model is running on CPU; output quality and formatting are limited. The provider returns a safe `MONITOR` recommendation when the response is not valid JSON.
- **Do not expose port 8080 publicly.** Keep the service bound to loopback, especially because the test server currently has no API key.
