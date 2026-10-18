from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
from dataclasses import replace

import pytest
import yaml
from starlette.testclient import TestClient

from silkscan.api.app import create_app
from silkscan.api.config import APIConfig, load_api_config
from silkscan.api.isolation import ParserProcess
from silkscan.api.security import SecurityMiddleware
from silkscan.api.service import QueueFullError
from silkscan.api.store import SQLiteVerdictStore
from silkscan.api.uploads import clean_text
from silkscan.errors import ConfigError


@pytest.mark.parametrize("raw", [
    {"typo": 1}, {"workers": 0}, {"workers": True}, {"auth_required": "false"},
    {"parse_timeout_s": float("nan")}, {"parse_timeout_s": 0}, {"subscriber": {"typo": 1}},
    {"subscriber": {"enabled": True}}, {"store_url": "postgres://localhost/db"},
    {"max_pending_mb": -1}, {"serving": 42}, {"subscriber": {"reconnect_max_s": 0}},
])
def test_strict_configuration(tmp_path, raw):
    path = tmp_path / "api.yaml"
    path.write_text(yaml.safe_dump(raw))
    with pytest.raises(ConfigError):
        load_api_config(path)


def test_auth_requires_environment_secret(monkeypatch):
    monkeypatch.delenv("SILKSCAN_API_KEYS", raising=False)
    with pytest.raises(RuntimeError, match="SILKSCAN_API_KEYS"):
        SecurityMiddleware(None, APIConfig())
    assert clean_text("a\x00b\n\r\t.exe") == "ab.exe"
    assert len(clean_text("x" * 500)) == 255


def test_parser_timeout_kills_and_replaces_child():
    parser = ParserProcess(timeout_s=0.05)
    # A child that reports ready and then never answers.
    parser.command = [sys.executable, "-c", "import sys, time; sys.stdout.write('R'); sys.stdout.flush(); time.sleep(30)"]
    parser.start()
    first = parser._proc
    with pytest.raises(TimeoutError):
        parser(b"data")
    assert first.poll() is not None
    assert parser._proc is not None and parser._proc is not first
    parser.close()


def _address_space_limit_enforced() -> bool:
    code = ("import resource as r; r.setrlimit(r.RLIMIT_AS, (64 << 20, 64 << 20));"
            "print(r.getrlimit(r.RLIMIT_AS)[0] == 64 << 20)")
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip() == "True"


@pytest.mark.skipif(not _address_space_limit_enforced(), reason="RLIMIT_AS is not enforced here (e.g. QEMU user emulation)")
def test_parser_memory_limit_failure():
    parser = ParserProcess(timeout_s=5, memory_mb=16)
    with pytest.raises(RuntimeError, match="memory limit"):
        parser(b"not a PE")
    parser.close()


def test_parser_process_is_reused_and_recycled():
    parser = ParserProcess(timeout_s=30, recycle_after=2)
    assert parser(b"first").id == hashlib.sha256(b"first").hexdigest()
    first = parser._proc
    parser(b"second")
    assert first.poll() is not None and parser._proc is not first
    second = parser._proc
    assert parser(b"third").id == hashlib.sha256(b"third").hexdigest()
    assert parser._proc is second and second.poll() is None
    parser.close()


def test_store_coordinator_lock_and_restart_recovery(tmp_path):
    url = f"sqlite:///{tmp_path / 'store.db'}"
    store = SQLiteVerdictStore(url)
    store.create_job("interrupted")
    with pytest.raises(RuntimeError, match="coordinator"):
        SQLiteVerdictStore(url)
    store.close()
    store = SQLiteVerdictStore(url)
    assert store.get_job("interrupted")["status"] == "failed"
    store.close()


def test_persistent_cache_event_ids_and_setting_invalidation(api_setup, tmp_path):
    root, serving, rows = api_setup
    config = APIConfig(serving=str(serving), workers=1, auth_required=False, batch_window_ms=0,
                       store_url=f"sqlite:///{tmp_path / 'cache.db'}")
    record = {**rows[0], "sha256": "synthetic:persistent"}
    with TestClient(create_app(config)) as client:
        original = client.post("/v1/scan/features", json=record).json()
        first_id = client.app.state.service.hub.buffer[-1]["event_id"]
    with TestClient(create_app(config)) as client:
        response = client.post("/v1/scan/features", json=record)
        assert response.headers["X-SilkScan-Cache"] == "hit" and response.json() == original
        client.post("/v1/scan/features", json={**record, "sha256": "synthetic:persistent-2"})
        assert client.app.state.service.hub.buffer[-1]["event_id"] > first_id
    alternate = tmp_path / "audit.yaml"
    raw = yaml.safe_load(serving.read_text())
    raw["short_circuit"] = False
    alternate.write_text(yaml.safe_dump(raw))
    with TestClient(create_app(replace(config, serving=str(alternate)))) as client:
        assert client.get("/v1/verdicts/" + record["sha256"]).status_code == 404
        response = client.post("/v1/scan/features", json=record)
        assert response.status_code == 200 and response.headers.get("X-SilkScan-Cache") is None
        assert response.json()["score"] == original["score"]


def test_queue_backpressure(api_client):
    async def scenario():
        service = api_client.app.state.service
        old = service.pending_bytes
        service.pending_bytes = service.config.max_pending_mb * 1024 * 1024
        try:
            with pytest.raises(QueueFullError):
                await service.submit({"data": b"capacity-test", "explain": 0})
        finally:
            service.pending_bytes = old
    api_client.portal.call(scenario)


def test_worker_failure_marks_job_failed_and_recovers(api_client, api_setup, monkeypatch):
    async def scenario():
        service = api_client.app.state.service
        originals = [w.scan for w in service.workers]
        def failure(payloads):
            raise RuntimeError("do not log raw input here")
        for worker in service.workers:
            monkeypatch.setattr(worker, "scan", failure)
        try:
            result = await service.submit({"raw": {**api_setup[2][0], "sha256": "synthetic:worker-failed"},
                                           "explain": 0})
            await asyncio.wait_for(result["job"].future, 5)
            job = service.store.get_job(result["job"].job_id)
            assert job["status"] == "failed" and "raw input" not in job["error"]
        finally:
            for worker, original in zip(service.workers, originals):
                monkeypatch.setattr(worker, "scan", original)
        result = await service.submit({"raw": {**api_setup[2][0], "sha256": "synthetic:worker-recovered"},
                                       "explain": 0})
        assert (await service.result(result["job"]))["score"] is not None
    api_client.portal.call(scenario)


def test_invalid_model_refuses_startup(tmp_path):
    serving = tmp_path / "serving.yaml"
    serving.write_text(yaml.safe_dump({"run": str(tmp_path / "missing")}))
    config = APIConfig(serving=str(serving), workers=1, auth_required=False,
                       store_url=f"sqlite:///{tmp_path / 'startup.db'}")
    app = create_app(config)
    with pytest.raises(RuntimeError, match="initialization"):
        with TestClient(app):
            pass
    assert not any(worker.alive for worker in app.state.service.workers)
