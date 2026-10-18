from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from silkscan.api.events import EventHub
from silkscan.api.config import SubscriberConfig
from silkscan.api.subscriber import RejectedEvent, Subscriber, blob_parts, read_local_blob, sse_messages

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def event(n, priority="P2"):
    return {"event_id": n, "data": {"id": str(n), "priority": priority}}


def test_event_replay_reset_priority_heartbeat_and_slow_client():
    async def scenario():
        hub = EventHub(capacity=2, client_capacity=1, heartbeat_s=0.001)
        for i in range(1, 4):
            hub.publish(event(i))
        listener, replay, reset = hub.subscribe(0)
        assert reset and [e["event_id"] for e in replay] == [2, 3]
        stream = hub.stream(listener, replay, reset)
        assert "event: reset" in await anext(stream)
        assert "id: 2" in await anext(stream)
        assert "id: 3" in await anext(stream)
        assert await anext(stream) == ": heartbeat\n\n"
        hub.publish(event(4))
        hub.publish(event(5))
        assert listener.closed.is_set() and listener not in hub.listeners
        await stream.aclose()
        listener, replay, reset = hub.subscribe(4, "P1")
        assert not replay and not reset
        hub.publish(event(6, "P4"))
        assert listener.queue.empty()
        hub.publish(event(7, "P1"))
        assert listener.queue.get_nowait()["event_id"] == 7
        hub.close()
    asyncio.run(scenario())


def test_actual_sse_route_live_and_reconnect(api_client, api_setup):
    async def scenario():
        app = api_client.app
        received, heartbeat, verdict_seen = [], asyncio.Event(), asyncio.Event()
        disconnect = asyncio.Event()
        async def receive():
            await disconnect.wait()
            return {"type": "http.disconnect"}
        async def send(message):
            if message["type"] == "http.response.body":
                body = message.get("body", b"").decode()
                received.append(body)
                if ": heartbeat" in body:
                    heartbeat.set()
                if "event: verdict" in body:
                    verdict_seen.set()
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
                 "http_version": "1.1", "method": "GET", "scheme": "http", "path": "/v1/events",
                 "raw_path": b"/v1/events", "query_string": b"", "root_path": "",
                 "headers": [(b"authorization", b"Bearer test-secret")],
                 "client": ("test", 1), "server": ("test", 80)}
        task = asyncio.create_task(app(scope, receive, send))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test",
                                    headers={"Authorization": "Bearer test-secret"}) as client:
            await asyncio.wait_for(heartbeat.wait(), 3)
            for n in range(2):
                row = {**api_setup[2][0], "sha256": f"synthetic:sse:{n}"}
                verdict_seen.clear()
                response = await client.post("/v1/scan/features", json=row)
                assert response.status_code == 200
                await asyncio.wait_for(verdict_seen.wait(), 3)
        disconnect.set()
        await asyncio.wait_for(task, 3)
        live = [s for s in received if "event: verdict" in s]
        assert len(live) == 2
        first_id = int(live[0].splitlines()[0].split(": ")[1])
        received.clear()
        verdict_seen.clear()
        disconnect.clear()
        scope["headers"].append((b"last-event-id", str(first_id).encode()))
        task = asyncio.create_task(app(scope, receive, send))
        await asyncio.wait_for(verdict_seen.wait(), 3)
        disconnect.set()
        await asyncio.wait_for(task, 3)
        assert any(live[1] == s for s in received)
        assert not app.state.service.hub.listeners
    api_client.portal.call(scenario)


@pytest.mark.parametrize("ref", ["../secret", "/etc/passwd", "a/../../x", "%2e%2e/secret",
                                      "https://evil.example/x", "//evil.example/x", "x%252f..", "a\\b",
                                      "store://quarantine/../../x", "x?url=http://localhost"])
def test_blob_reference_confinement(ref):
    with pytest.raises(RejectedEvent):
        blob_parts(ref)


def test_local_symlink_and_size_rejected(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    secret = tmp_path / "secret"
    secret.write_bytes(b"secret")
    (base / "link").symlink_to(secret)
    with pytest.raises(OSError):
        read_local_blob(base, ["link"], 100)
    (base / "large").write_bytes(b"x" * 101)
    with pytest.raises(RejectedEvent):
        read_local_blob(base, ["large"], 100)
    assert blob_parts("store://quarantine/sample") == ["quarantine", "sample"]


def test_subscriber_fake_upstream_hash_validation_and_reconnect(api_client, tmp_path):
    pytest.importorskip("yara")
    data = b"upstream-event" + EICAR
    (tmp_path / "sample").write_bytes(data)
    good = {"event_id": "one", "sha256": hashlib.sha256(data).hexdigest(), "blob_ref": "sample",
            "filename": "upstream.exe", "source": "test-upstream"}
    async def scenario():
        calls = []
        reconnected = asyncio.Event()
        service = api_client.app.state.service
        config = SubscriberConfig(enabled=True, url="https://upstream.test/events", blob_base=str(tmp_path),
                                  reconnect_max_s=1)
        async def upstream(request):
            calls.append(request)
            if len(calls) > 1:
                reconnected.set()
                await asyncio.Event().wait()
            body = "id: one\ndata: " + json.dumps(good) + "\n\n"
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body)
        async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as client:
            subscriber = Subscriber(config, service, client)
            task = asyncio.create_task(subscriber.run())
            try:
                await asyncio.wait_for(reconnected.wait(), 5)
                assert calls[1].headers["Last-Event-ID"] == "one"
                row = service.store.get_by_sha(good["sha256"], service.namespace)
                assert row and row["verdict"]["decision"] == "malicious"
                assert any(e["data"]["id"] == good["sha256"] for e in service.hub.buffer)
                with pytest.raises(RejectedEvent, match="SHA-256"):
                    await subscriber.handle({**good, "sha256": "0" * 64}, client)
                with pytest.raises(RejectedEvent):
                    await subscriber.handle({**good, "blob_ref": "../sample"}, client)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
    api_client.portal.call(scenario)


def test_subscriber_http_base_rejects_redirect_and_oversize():
    class Service:
        info = {"max_bytes": 4}
    async def scenario():
        seen = []
        async def remote(request):
            seen.append(str(request.url))
            if request.url.path.endswith("redirect"):
                return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})
            return httpx.Response(200, content=b"12345")
        subscriber = Subscriber(SubscriberConfig(blob_base="https://allowed.test/files"), Service())
        async with httpx.AsyncClient(transport=httpx.MockTransport(remote)) as client:
            for name in ("redirect", "big"):
                with pytest.raises(RejectedEvent):
                    await subscriber.fetch_blob(name, client)
        assert seen == ["https://allowed.test/files/redirect", "https://allowed.test/files/big"]
    asyncio.run(scenario())


def test_sse_event_size_limit_and_fragmented_lines():
    class Bytes(httpx.AsyncByteStream):
        async def __aiter__(self):
            for part in (b"id: x\r", b"\ndata: {", b'}\r\n\r\n'):
                yield part
    async def scenario():
        response = httpx.Response(200, stream=Bytes())
        assert [item async for item in sse_messages(response, 100)] == [("x", "{}")]
        with pytest.raises(RejectedEvent):
            response = httpx.Response(200, stream=Bytes())
            [item async for item in sse_messages(response, 5)]
    asyncio.run(scenario())
