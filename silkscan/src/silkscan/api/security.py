"""Authentication, per-client rate limits and request IDs without body logging."""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import uuid
from collections import OrderedDict

from starlette.datastructures import Headers
from starlette.responses import JSONResponse

from silkscan.api.observability import log_event


class SecurityMiddleware:
    def __init__(self, app, config):
        self.app = app
        self.config = config
        self.keys = tuple(k.strip().encode() for k in os.getenv("SILKSCAN_API_KEYS", "").split(",") if k.strip())
        if config.auth_required and not self.keys:
            raise RuntimeError("SILKSCAN_API_KEYS must contain at least one key when auth_required is true")
        self.clients = OrderedDict()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = uuid.uuid4().hex
        scope.setdefault("state", {})["request_id"] = request_id
        headers = Headers(scope=scope)
        authorization = headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        supplied = token.encode() if scheme.lower() == "bearer" else b""
        matched = False
        for key in self.keys:
            matched |= hmac.compare_digest(supplied, key)
        public_health = scope["path"] == "/v1/health" and not self.config.health_auth_required
        if self.config.auth_required and not public_health and not matched:
            await JSONResponse({"error": "Unauthorized"}, 401,
                               headers={"WWW-Authenticate": "Bearer", "X-Request-ID": request_id})(scope, receive, send)
            return
        client = hashlib.sha256(supplied).hexdigest() if matched else (scope.get("client") or ("unknown",))[0]
        now = time.monotonic()
        # A bounded idle cache avoids unbounded state for arbitrary client addresses.
        while self.clients and next(iter(self.clients.values()))[0] <= now - 60:
            self.clients.popitem(last=False)
        start, count = self.clients.pop(client, (now, 0))
        if now - start >= 60:
            start, count = now, 0
        self.clients[client] = (start, count + 1)
        if len(self.clients) > 10000:
            self.clients.popitem(last=False)
        if count >= self.config.rate_limit_per_min:
            await JSONResponse({"error": "Rate limit exceeded"}, 429,
                               headers={"Retry-After": str(max(1, int(60 - (now - start)))),
                                        "X-Request-ID": request_id})(scope, receive, send)
            return
        begun = time.perf_counter()

        async def response_send(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", []).append((b"x-request-id", request_id.encode()))
                log_event("request", request_id=request_id, status=message["status"],
                          duration_ms=round(1000 * (time.perf_counter() - begun), 3))
            await send(message)

        await self.app(scope, receive, response_send)
