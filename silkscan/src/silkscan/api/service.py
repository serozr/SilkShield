"""One coordinator owns the bounded queue, cache, deduplication and event order."""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone

from silkscan.api.events import EventHub
from silkscan.api.observability import Metrics, log_event
from silkscan.api.store import SQLiteVerdictStore
from silkscan.api.worker import Worker, fingerprint


class QueueFullError(Exception):
    pass


class ScanFailedError(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Job:
    job_id: str
    key: str
    sha256: str
    payload: dict
    source: str
    received_at: str
    request_id: str
    submitted: float
    future: asyncio.Future
    payload_bytes: int


class ScanService:
    def __init__(self, config, store=None):
        self.config = config
        self.store = store
        self.workers = [Worker(config) for _ in range(config.workers)]
        self.queue = asyncio.Queue(config.queue_size)
        self.pending = {}
        self.pending_bytes = 0
        self.submit_lock = asyncio.Lock()
        self.complete_lock = asyncio.Lock()
        self.hub = EventHub(config.events_buffer, config.events_client_queue, config.heartbeat_s)
        self.metrics = Metrics()
        self.tasks = []
        self.ready = False
        self.stopping = False

    async def start(self):
        try:
            self.store = self.store or await asyncio.to_thread(SQLiteVerdictStore, self.config.store_url)
            results = await asyncio.gather(*(asyncio.to_thread(w.start) for w in self.workers),
                                           return_exceptions=True)
            for result in results:
                if isinstance(result, BaseException):
                    raise result
            first = results[0]
            if any(r["namespace"] != first["namespace"] for r in results):
                raise RuntimeError("Workers loaded different model/check versions; use immutable artifacts")
            self.info = first
            self.namespace = first["namespace"]
            self.hub.buffer.extend(await asyncio.to_thread(self.store.latest_events, self.config.events_buffer))
            self.ready = True
            self.tasks = [asyncio.create_task(self._consume(w)) for w in self.workers]
        except BaseException:
            await self.close()
            raise

    async def close(self):
        self.ready = False
        self.stopping = True
        self.hub.close()
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await asyncio.gather(*(asyncio.to_thread(w.close) for w in self.workers))
        if self.store is not None:
            for job in list(self.pending.values()):
                await asyncio.to_thread(self.store.update_job, job.job_id, "failed", "Service stopped")
                if not job.future.done():
                    job.future.set_result({"error": "Service stopped"})
            self.pending.clear()
            await asyncio.to_thread(self.store.close)

    def health(self):
        alive = sum(w.alive for w in self.workers)
        ok = self.ready and alive == self.config.workers and all(not t.done() for t in self.tasks)
        return {"status": "ok" if ok else "degraded", "model_loaded": ok, "checks_loaded": ok,
                "queue_depth": self.queue.qsize(), "workers": alive}

    async def submit(self, payload, source="", request_id="", received_at=None):
        if self.health()["status"] != "ok":
            raise QueueFullError("Service is not ready")
        if "raw" in payload:
            sha = payload["raw"]["sha256"]
            content = {"kind": "features", "raw": payload["raw"]}
            payload_bytes = await asyncio.to_thread(lambda: len(json.dumps(payload["raw"]).encode()))
        else:
            sha = await asyncio.to_thread(lambda: hashlib.sha256(payload["data"]).hexdigest())
            content = {"kind": "file", "sha256": sha}
            payload_bytes = len(payload["data"])
        # Filename is available to custom checks; never reuse their verdict across filenames.
        key = await asyncio.to_thread(fingerprint, {**content, "explain": payload["explain"],
                                                    "filename": payload.get("filename")})
        async with self.submit_lock:
            cached = await asyncio.to_thread(self.store.get_by_sha, sha, self.namespace, key)
            if cached:
                self.metrics.cache_hits += 1
                return {"cached": cached["verdict"], "job_id": cached["job_id"]}
            if key in self.pending:
                return {"job": self.pending[key]}
            if self.queue.full() or self.pending_bytes + payload_bytes > self.config.max_pending_mb * 1024 * 1024:
                raise QueueFullError("Scan queue is full; retry later")
            job = Job(uuid.uuid4().hex, key, sha, payload, source, received_at or utc_now(),
                      request_id or uuid.uuid4().hex, time.perf_counter(), asyncio.get_running_loop().create_future(), payload_bytes)
            await asyncio.to_thread(self.store.create_job, job.job_id)
            self.pending[key] = job
            self.pending_bytes += payload_bytes
            self.queue.put_nowait(job)
            return {"job": job}

    async def result(self, job):
        result = await asyncio.shield(job.future)
        if "error" in result:
            raise ScanFailedError(result["error"])
        return result["verdict"]

    async def _finish(self, job, verdict, scan_ms):
        elapsed = (time.perf_counter() - job.submitted) * 1000
        api_ms = max(0.0, elapsed - scan_ms)
        record = {"verdict": verdict, "sha256": job.sha256, "received_at": job.received_at,
                  "source": job.source, "filename": job.payload.get("filename"), "job_id": job.job_id,
                  "model.run": self.info["metadata"]["run"], "namespace": self.namespace,
                  "cache_key": job.key, "api_ms": round(api_ms, 3)}
        event = {key: verdict[key] for key in ("id", "decision", "priority", "score", "reasons")}
        event.update(source=job.source, filename=job.payload.get("filename"), at=utc_now())
        # Serialize DB commit + fanout so SSE IDs cannot arrive out of order across workers.
        async with self.complete_lock:
            published = await asyncio.to_thread(self.store.put, record, event)
            self.hub.publish(published)
        self.metrics.observe(verdict, api_ms)
        log_event("verdict", request_id=job.request_id, sha256=job.sha256,
                  decision=verdict["decision"], priority=verdict["priority"],
                  timing_ms=verdict["timing_ms"], api_ms=round(api_ms, 3))
        job.future.set_result({"verdict": verdict})

    async def _consume(self, worker):
        while True:
            jobs = [await self.queue.get()]
            try:
                if self.config.batch_window_ms:
                    await asyncio.sleep(self.config.batch_window_ms / 1000)
                while len(jobs) < 64:
                    try:
                        jobs.append(self.queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                groups = defaultdict(list)
                for job in jobs:
                    groups[job.payload["explain"]].append(job)
                for group in groups.values():
                    try:
                        for job in group:
                            await asyncio.to_thread(self.store.update_job, job.job_id, "running")
                        response = await asyncio.to_thread(worker.scan, [j.payload for j in group])
                        verdicts = response["verdicts"]
                        if len(verdicts) != len(group):
                            raise RuntimeError("Worker returned an unexpected result count")
                        for job, verdict in zip(group, verdicts):
                            await self._finish(job, verdict, response["scan_ms"])
                    except Exception as exc:
                        self.metrics.failures += len(group)
                        for job in group:
                            if job.future.done():
                                continue
                            error = f"Scan worker failed ({type(exc).__name__})"
                            await asyncio.to_thread(self.store.update_job, job.job_id, "failed", error)
                            job.future.set_result({"error": error})
                            log_event("job_failed", request_id=job.request_id, sha256=job.sha256,
                                      error=type(exc).__name__)
                        if not worker.alive and not self.stopping:
                            try:
                                await asyncio.to_thread(worker.close)
                                info = await asyncio.to_thread(worker.start)
                                if info["namespace"] != self.namespace:
                                    raise RuntimeError("Worker artifact versions changed")
                            except Exception:
                                self.ready = False
                    finally:
                        for job in group:
                            if job.future.done():
                                self.pending.pop(job.key, None)
                                self.pending_bytes -= job.payload_bytes
            finally:
                for job in jobs:
                    self.queue.task_done()
