from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from starlette.testclient import TestClient

from silkscan.api.app import create_app
from silkscan.api.config import APIConfig
from silkscan.api.uploads import read_body
from silkscan.checks import create_checks
from silkscan.config import load_serving_config
from silkscan.data.records import split_record
from silkscan.inference.bundle import ModelBundle
from silkscan.inference.predict import Submission, scan

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def post_file(client, data, **kwargs):
    return client.post("/v1/scan", content=data, headers={"Content-Type": "application/octet-stream"}, **kwargs)


def completed(client, response):
    if response.status_code == 200:
        return response.json()
    assert response.status_code == 202, response.text
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        status = client.get("/v1/jobs/" + response.json()["job_id"]).json()
        assert status["status"] != "failed", status
        if status["status"] == "done":
            return status["verdict"]
        time.sleep(0.01)
    pytest.fail("Scan did not finish")


def without_timings(verdict):
    result = copy.deepcopy(verdict)
    result.pop("timing_ms")
    for check in result["checks"]:
        check.pop("elapsed_ms")
    return result


def test_model_health_and_auth(api_client, trained_run):
    assert api_client.get("/v1/health").json()["workers"] == 2
    assert api_client.get("/v1/health", headers={"Authorization": ""}).status_code == 401
    assert api_client.get("/v1/health", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert api_client.get("/v1/health", headers={"Authorization": "Bearer second-key"}).status_code == 200
    metadata = api_client.get("/v1/model").json()
    assert metadata["schema_fingerprint"] == ModelBundle(trained_run[0]).schema.fingerprint()
    assert metadata["backend"] == "lightgbm" and metadata["verdict_schema_version"] == "1"
    assert metadata["runtime"]["byteorder"] in ("little", "big")
    assert api_client.get("/v1/jobs/missing").status_code == 404
    assert api_client.get("/v1/verdicts/missing").status_code == 404


def test_real_pe_and_eicar_short_circuit(api_client, pe_bytes):
    response = post_file(api_client, pe_bytes)
    assert response.status_code == 200, response.text
    verdict = response.json()
    assert verdict["schema_version"] == "1"
    assert verdict["decision"] in {"clean", "malicious", "inconclusive"}
    assert verdict["timing_ms"]["parse"] > 0
    pytest.importorskip("yara")
    eicar = post_file(api_client, pe_bytes + EICAR)
    assert eicar.status_code == 200
    v = eicar.json()
    assert (v["decision"], v["priority"], v["model_decision"]) == ("malicious", "P1", "skipped")
    assert v["timing_ms"]["parse"] == v["timing_ms"]["model"] == 0
    cached = post_file(api_client, pe_bytes + EICAR)
    assert cached.headers["X-SilkScan-Cache"] == "hit" and cached.json() == v
    assert api_client.get("/v1/verdicts/" + v["id"]).json() == v


def test_core_parity_all_demo_test_rows(api_client, api_setup, trained_run):
    _, serving_path, rows = api_setup
    serving = load_serving_config(serving_path)
    bundle = ModelBundle(trained_run[0])
    expected = scan(bundle, bundle.backend(), [Submission(record=split_record(r)) for r in rows],
                    create_checks(serving.checks), explain_top=0)
    response = api_client.post("/v1/scan/features", content="\n".join(json.dumps(r) for r in rows),
                               headers={"Content-Type": "application/x-ndjson"})
    assert response.status_code == 200, response.text
    assert len(response.json()) == len(rows)
    for actual, reference in zip(response.json(), expected):
        assert without_timings(actual) == without_timings(reference)
    cached = api_client.post("/v1/scan/features", json=rows[0])
    assert cached.headers["X-SilkScan-Cache"] == "hit"
    assert cached.json() == response.json()[0]
    if any(c.name == "yara" for c in create_checks(serving.checks)):
        assert next(c for c in cached.json()["checks"] if c["check"] == "yara")["outcome"] == "skipped"


def test_ndjson_order_and_whole_body_validation(api_client, api_setup):
    rows = list(reversed(api_setup[2][:3]))
    response = api_client.post("/v1/scan/features", content="\n".join(json.dumps(r) for r in rows),
                               headers={"Content-Type": "application/x-ndjson"})
    assert response.status_code == 200
    assert [v["id"] for v in response.json()] == [r["sha256"] for r in rows]
    bad = api_client.post("/v1/scan/features", content=json.dumps(rows[0]) + "\n{}",
                          headers={"Content-Type": "application/x-ndjson"})
    assert bad.status_code == 422 and bad.json()["error"]["line"] == 2
    for obj in ([], {}, {"sha256": "bad"}, {"sha256": "a" * 64}):
        assert api_client.post("/v1/scan/features", json=obj).status_code == 422
    assert api_client.post("/v1/scan/features", content='{"sha256":"synthetic:nan","x":NaN}',
                           headers={"Content-Type": "application/json"}).status_code == 422


def test_feature_input_cannot_poison_file_cache(api_client, api_setup):
    pytest.importorskip("yara")
    data = b"feature-cache-test" + EICAR
    raw = {**api_setup[2][0], "sha256": hashlib.sha256(data).hexdigest()}
    features = api_client.post("/v1/scan/features", json=raw).json()
    assert features["model_decision"] != "skipped"
    response = post_file(api_client, data)
    assert response.headers.get("X-SilkScan-Cache") != "hit"
    assert response.json()["model_decision"] == "skipped"
    assert response.json()["decision"] == "malicious"


def test_feature_content_and_explanation_separate_cache(api_client, api_setup):
    row = {**api_setup[2][2], "sha256": "synthetic:cache-content"}
    first = api_client.post("/v1/scan/features", json=row)
    assert first.status_code == 200
    row["label"] = 1 - row["label"]
    second = api_client.post("/v1/scan/features", json=row)
    assert second.headers.get("X-SilkScan-Cache") != "hit"
    assert first.json()["score"] == second.json()["score"]
    explained = api_client.post("/v1/scan/features?explain=3", json=row)
    assert explained.status_code == 200 and "explanation" in explained.json()
    assert explained.json()["score"] == second.json()["score"]


def test_multipart_and_filename_sanitization(api_client):
    pytest.importorskip("yara")
    response = api_client.post("/v1/scan?source=portal", files={"file": ("../test.exe", EICAR)})
    assert response.status_code == 200 and response.json()["decision"] == "malicious"
    service = api_client.app.state.service
    row = service.store.get_by_sha(response.json()["id"], service.namespace)
    assert row["filename"] == "../test.exe" and row["source"] == "portal"
    assert row["verdict"] == response.json() and "api_ms" in row
    assert "raw" not in row and "data" not in row
    assert api_client.post("/v1/scan", files={"wrong": ("a.exe", b"x")}).status_code == 422
    assert api_client.post("/v1/scan", files=[("file", ("a", b"x")), ("file", ("b", b"x"))]).status_code == 422


def test_size_limit_before_receive_and_chunked_limit(api_client):
    class Request:
        headers = {"content-length": "101"}
        async def stream(self):
            pytest.fail("Body must not be consumed")
            yield b""
    from starlette.exceptions import HTTPException
    with pytest.raises(HTTPException) as exc:
        asyncio.run(read_body(Request(), 100))
    assert exc.value.status_code == 413
    response = api_client.post("/v1/scan", content=b"small", headers={"Content-Type": "application/octet-stream",
                              "Content-Length": str(1024 * 1024 + 1)})
    assert response.status_code == 413
    class Chunked:
        headers = {}
        async def stream(self):
            yield b"x" * 60
            yield b"x" * 60
    with pytest.raises(HTTPException) as exc:
        asyncio.run(read_body(Chunked(), 100))
    assert exc.value.status_code == 413


def test_async_deduplication_and_single_event(api_client):
    pytest.importorskip("yara")
    data = b"deduplication" + EICAR
    before = len(api_client.app.state.service.store.latest_events(10000))
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda _: post_file(api_client, data, params={"async": "true"}), range(8)))
    ids = {r.json()["job_id"] for r in responses if r.status_code == 202}
    assert len(ids) == 1
    verdicts = [completed(api_client, r) for r in responses]
    assert all(v == verdicts[0] for v in verdicts)
    assert len(api_client.app.state.service.store.latest_events(10000)) == before + 1


def test_parse_timeout_handoff_and_recovery(api_setup, tmp_path):
    config = APIConfig(serving=str(api_setup[1]), workers=1, auth_required=False,
                       store_url=f"sqlite:///{tmp_path / 'timeout.db'}", sync_timeout_s=0,
                       parse_timeout_s=0.001, batch_window_ms=0)
    with TestClient(create_app(config)) as client:
        response = post_file(client, b"not-a-PE")
        assert response.status_code == 202
        verdict = completed(client, response)
        assert verdict["decision"] == "error" and verdict["priority"] == "P3"
        assert any("TimeoutError" in r for r in verdict["reasons"])
        assert client.get("/v1/health").status_code == 200
        if any(c["name"] == "yara" for c in __import__("yaml").safe_load(api_setup[1].read_text())["checks"]):
            assert completed(client, post_file(client, EICAR))["decision"] == "malicious"


def test_rate_limit_and_public_health(api_setup, tmp_path, monkeypatch):
    monkeypatch.setenv("SILKSCAN_API_KEYS", "secret")
    config = APIConfig(serving=str(api_setup[1]), workers=1, rate_limit_per_min=2,
                       health_auth_required=False, store_url=f"sqlite:///{tmp_path / 'limit.db'}")
    with TestClient(create_app(config)) as client:
        assert client.get("/v1/health").status_code == 200
        assert client.get("/v1/model").status_code == 401
        headers = {"Authorization": "Bearer secret"}
        assert client.get("/v1/model", headers=headers).status_code == 200
        assert client.get("/v1/model", headers=headers).status_code == 200
        limited = client.get("/v1/model", headers=headers)
        assert limited.status_code == 429 and "Retry-After" in limited.headers


def test_bad_parameters_and_metrics(api_client):
    for query in ("explain=-1", "explain=no", "async=maybe"):
        assert post_file(api_client, b"x", params=query).status_code == 422
    assert api_client.get("/v1/events?min_priority=P0").status_code == 422
    assert api_client.get("/v1/events", headers={"Last-Event-ID": "bad"}).status_code == 422
    assert api_client.post("/v1/scan", json={}).status_code == 415
    response = api_client.get("/metrics")
    assert response.status_code == 200 and "silkscan_queue_depth" in response.text
    assert "silkscan_stage_ms_bucket" in response.text


def test_invalid_general_and_nonfinite_json_are_422(api_client):
    for value in ('{"sha256":"synthetic:bad","general":[1]}',
                  '{"sha256":"synthetic:bad","general":{"size":1e999}}'):
        response = api_client.post("/v1/scan/features", content=value,
                                   headers={"Content-Type": "application/json"})
        assert response.status_code == 422 and response.json()["error"]["line"] == 1
