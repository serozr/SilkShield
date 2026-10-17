"""Version 1 HTTP API. Verdicts are returned exactly as produced by scan()."""
from __future__ import annotations

import asyncio
import json
import math
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, PlainTextResponse, StreamingResponse
from starlette.routing import Route

from silkscan.api.config import APIConfig, load_api_config
from silkscan.api.security import SecurityMiddleware
from silkscan.api.observability import log_event
from silkscan.api.service import QueueFullError, ScanFailedError, ScanService, utc_now
from silkscan.api.subscriber import Subscriber
from silkscan.api.uploads import clean_text, multipart_file, read_body


def explain_value(request):
    try:
        explain = int(request.query_params.get("explain", request.app.state.service.info["explain_top"]))
        if explain < 0:
            raise ValueError
        return explain
    except ValueError:
        raise HTTPException(422, "explain must be a nonnegative integer") from None


def asynchronous(request):
    value = request.query_params.get("async", "false").lower()
    if value not in ("true", "false", "1", "0"):
        raise HTTPException(422, "async must be a boolean")
    return value in ("true", "1")


async def scan_file(request):
    service = request.app.state.service
    explain, async_mode = explain_value(request), asynchronous(request)
    received_at = utc_now()
    body = await read_body(request, service.info["max_bytes"])
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type == "multipart/form-data":
        body, filename = await asyncio.to_thread(multipart_file, body, request.headers["content-type"])
    elif media_type == "application/octet-stream":
        filename = clean_text(request.headers.get("x-filename", ""))
    else:
        raise HTTPException(415, "Expected multipart/form-data or application/octet-stream")
    result = await service.submit({"data": body, "filename": filename, "explain": explain},
                                  clean_text(request.query_params.get("source", "")),
                                  request.state.request_id, received_at)
    if "cached" in result:
        return JSONResponse(result["cached"], headers={"X-SilkScan-Cache": "hit"})
    job = result["job"]
    if not async_mode:
        try:
            verdict = await asyncio.wait_for(service.result(job), service.config.sync_timeout_s)
            return JSONResponse(verdict)
        except asyncio.TimeoutError:
            pass
    return JSONResponse({"job_id": job.job_id}, 202, headers={"Location": f"/v1/jobs/{job.job_id}"})


def parse_features(body, ndjson, max_batch):
    from silkscan.data.records import split_record
    from silkscan.features.groups.ember_v3 import RAW_FIELDS

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(422, {"line": 1, "message": "Expected UTF-8"}) from None
    lines = list(enumerate(text.splitlines(), 1)) if ndjson else [(1, text)]
    records = []
    for line_no, line in lines:
        if ndjson and not line.strip():
            continue
        if len(records) >= max_batch:
            raise HTTPException(422, {"line": line_no, "message": "max_batch exceeded"})
        try:
            def invalid_constant(value):
                raise ValueError("Nonfinite JSON number")
            def finite_float(value):
                result = float(value)
                if not math.isfinite(result):
                    raise ValueError("Nonfinite JSON number")
                return result
            obj = json.loads(line, parse_constant=invalid_constant, parse_float=finite_float)
            if not isinstance(obj, dict):
                raise ValueError("Expected an object")
            split_record(obj)
            # CheckContext reads general before invoking guarded feature extractors.
            if obj.get("general") is not None and not isinstance(obj["general"], dict):
                raise ValueError("general must be an object")
            if not set(obj).intersection((*RAW_FIELDS, "caps", "ttps", "mbc")):
                raise ValueError("No raw features")
        except Exception:
            raise HTTPException(422, {"line": line_no, "message": "Invalid EMBER feature record"}) from None
        records.append(obj)
    if not records:
        raise HTTPException(422, {"line": 1, "message": "No feature records"})
    return records


async def scan_features(request):
    service = request.app.state.service
    explain = explain_value(request)
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type not in ("application/json", "application/x-ndjson"):
        raise HTTPException(415, "Expected application/json or application/x-ndjson")
    ndjson = media_type == "application/x-ndjson"
    body = await read_body(request, service.info["max_bytes"])
    records = await asyncio.to_thread(parse_features, body, ndjson, service.config.max_batch)
    source = clean_text(request.query_params.get("source", ""))
    submitted = []
    for record in records:
        submitted.append(await service.submit({"raw": record, "explain": explain}, source,
                                              request.state.request_id))
    results = await asyncio.gather(*(service.result(r["job"]) if "job" in r else _cached(r["cached"])
                                     for r in submitted))
    headers = {"X-SilkScan-Cache": "hit"} if all("cached" in r for r in submitted) else {}
    return JSONResponse(results if ndjson else results[0], headers=headers)


async def _cached(verdict):
    return verdict


async def get_job(request):
    service = request.app.state.service
    job = await asyncio.to_thread(service.store.get_job, request.path_params["job_id"])
    if job is None:
        raise HTTPException(404, "Unknown job")
    return JSONResponse(job)


async def get_verdict(request):
    service = request.app.state.service
    row = await asyncio.to_thread(service.store.get_by_sha, request.path_params["sha256"], service.namespace)
    if row is None:
        raise HTTPException(404, "No verdict for the active model and checks")
    return JSONResponse(row["verdict"])


async def model(request):
    return JSONResponse(request.app.state.service.info["metadata"])


async def health(request):
    result = request.app.state.service.health()
    return JSONResponse(result, 200 if result["status"] == "ok" else 503)


async def metrics(request):
    service = request.app.state.service
    return PlainTextResponse(service.metrics.render(service.queue.qsize()),
                             media_type="text/plain; version=0.0.4")


class EventResponse(StreamingResponse):
    """Cancel even a blocked socket send when a subscriber's bounded queue fills."""
    def __init__(self, hub, listener, replay, reset):
        self.hub, self.listener = hub, listener
        super().__init__(hub.stream(listener, replay, reset), media_type="text/event-stream",
                         headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    async def __call__(self, scope, receive, send):
        response = asyncio.create_task(super().__call__(scope, receive, send))
        closed = asyncio.create_task(self.listener.closed.wait())
        try:
            done, _ = await asyncio.wait((response, closed), return_when=asyncio.FIRST_COMPLETED)
            if response in done:
                await response
        finally:
            response.cancel()
            closed.cancel()
            await asyncio.gather(response, closed, return_exceptions=True)
            self.hub.listeners.discard(self.listener)
            await self.body_iterator.aclose()


async def events(request):
    priority = request.query_params.get("min_priority")
    if priority is not None and priority not in ("P1", "P2", "P3", "P4"):
        raise HTTPException(422, "min_priority must be P1, P2, P3 or P4")
    last = request.headers.get("last-event-id")
    try:
        last = int(last) if last is not None else None
        if last is not None and last < 0:
            raise ValueError
    except ValueError:
        raise HTTPException(422, "Last-Event-ID must be a nonnegative integer") from None
    hub = request.app.state.service.hub
    return EventResponse(hub, *hub.subscribe(last, priority))


async def http_error(request, exc):
    return JSONResponse({"error": exc.detail}, exc.status_code, headers=exc.headers)


async def queue_error(request, exc):
    return JSONResponse({"error": str(exc)}, 503, headers={"Retry-After": "1"})


async def worker_error(request, exc):
    return JSONResponse({"error": str(exc)}, 503)


async def server_error(request, exc):
    log_event("request_failed", request_id=getattr(request.state, "request_id", ""),
              error=type(exc).__name__)
    return JSONResponse({"error": "Internal service error"}, 500)


def create_app(config: APIConfig | str = "configs/api.yaml", *, store=None):
    config = load_api_config(config) if isinstance(config, str) else config.validate()
    service = ScanService(config, store)

    @asynccontextmanager
    async def lifespan(app):
        await service.start()
        subscriber_task = None
        if config.subscriber.enabled:
            subscriber_task = asyncio.create_task(Subscriber(config.subscriber, service).run())
        try:
            yield
        finally:
            if subscriber_task:
                subscriber_task.cancel()
                await asyncio.gather(subscriber_task, return_exceptions=True)
            await service.close()

    routes = [Route("/v1/scan", scan_file, methods=["POST"]),
              Route("/v1/scan/features", scan_features, methods=["POST"]),
              Route("/v1/jobs/{job_id}", get_job), Route("/v1/verdicts/{sha256}", get_verdict),
              Route("/v1/events", events), Route("/v1/model", model), Route("/v1/health", health),
              Route("/metrics", metrics)]
    app = Starlette(routes=routes, lifespan=lifespan,
                    middleware=[Middleware(SecurityMiddleware, config=config)],
                    exception_handlers={HTTPException: http_error, QueueFullError: queue_error,
                                        ScanFailedError: worker_error, Exception: server_error})
    app.state.service = service
    return app
