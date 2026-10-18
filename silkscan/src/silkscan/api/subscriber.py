"""Upstream SSE subscriber with bounded downloads and confined blob references."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

import httpx

from silkscan.api.observability import log_event
from silkscan.api.service import QueueFullError
from silkscan.api.uploads import clean_text


class RejectedEvent(ValueError):
    pass


def blob_parts(reference):
    if not isinstance(reference, str) or len(reference) > 4096:
        raise RejectedEvent("Invalid blob reference")
    parsed = urlsplit(reference)
    if parsed.scheme == "store":
        reference = parsed.netloc + parsed.path
    elif parsed.scheme or parsed.netloc:
        raise RejectedEvent("Arbitrary URLs are forbidden")
    if parsed.query or parsed.fragment:
        raise RejectedEvent("Query and fragment are forbidden")
    reference = unquote(reference)
    if (reference.startswith("/") or any(c in reference for c in ("\\", "\x00", "%", ":"))
            or any(ord(c) < 32 for c in reference)):
        raise RejectedEvent("Invalid blob reference")
    parts = reference.split("/")
    if not parts or any(p in ("", ".", "..") for p in parts):
        raise RejectedEvent("Blob reference escapes its base")
    return parts


def read_local_blob(base, parts, limit):
    # Walk by directory descriptors and reject symlinks, including intermediate components.
    directory = os.open(Path(base).resolve(), os.O_RDONLY | os.O_DIRECTORY)
    file_fd = None
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise RejectedEvent("Blob is not a regular file within the size limit")
        with os.fdopen(file_fd, "rb") as stream:
            file_fd = None
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise RejectedEvent("Blob exceeds size limit")
        return data
    finally:
        os.close(directory)
        if file_fd is not None:
            os.close(file_fd)


async def sse_messages(response, max_bytes):
    buffer = bytearray()
    data = []
    event_id = None
    event_bytes = 0
    async for chunk in response.aiter_bytes():
        # Split a network chunk incrementally; never retain an unbounded SSE line/event.
        for fragment in chunk.splitlines(keepends=True):
            buffer.extend(fragment)
            if len(buffer) + event_bytes > max_bytes:
                raise RejectedEvent("Upstream event exceeds size limit")
            if not buffer.endswith(b"\n"):
                continue
            line = bytes(buffer).rstrip(b"\r\n").decode("utf-8")
            buffer.clear()
            if not line:
                if data:
                    yield event_id, "\n".join(data)
                data, event_id, event_bytes = [], None, 0
            elif line.startswith(":"):
                continue
            else:
                key, _, value = line.partition(":")
                value = value.removeprefix(" ")
                event_bytes += len(line.encode())
                if key == "data":
                    data.append(value)
                elif key == "id" and "\x00" not in value:
                    event_id = value


class Subscriber:
    def __init__(self, config, service, client=None):
        self.config = config
        self.service = service
        self.client = client
        self.last_id = None

    async def fetch_blob(self, reference, client):
        parts = blob_parts(reference)
        base = self.config.blob_base
        limit = self.service.info["max_bytes"]
        if urlsplit(base).scheme in ("http", "https"):
            parsed = urlsplit(base)
            if parsed.username or parsed.query or parsed.fragment:
                raise RejectedEvent("Invalid configured HTTP blob base")
            url = base.rstrip("/") + "/" + "/".join(quote(p, safe="") for p in parts)
            async with client.stream("GET", url, follow_redirects=False,
                                     headers={"Accept-Encoding": "identity"}) as response:
                if response.is_redirect:
                    raise RejectedEvent("Blob redirects are forbidden")
                response.raise_for_status()
                declared = response.headers.get("content-length")
                if declared is not None and int(declared) > limit:
                    raise RejectedEvent("Blob exceeds size limit")
                result = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(result) + len(chunk) > limit:
                        raise RejectedEvent("Blob exceeds size limit")
                    result.extend(chunk)
                return bytes(result)
        if urlsplit(base).scheme:
            raise RejectedEvent("Unsupported configured blob base")
        return await asyncio.to_thread(read_local_blob, base, parts, limit)

    async def handle(self, event, client):
        if not isinstance(event, dict):
            raise RejectedEvent("Expected an object")
        sha = event.get("sha256")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise RejectedEvent("Invalid SHA-256")
        try:
            data = await self.fetch_blob(event.get("blob_ref"), client)
        except (OSError, ValueError) as exc:
            raise RejectedEvent(f"Blob rejected ({type(exc).__name__})") from None
        actual = await asyncio.to_thread(lambda: hashlib.sha256(data).hexdigest())
        if actual != sha:
            raise RejectedEvent("SHA-256 mismatch")
        payload = {"data": data, "filename": clean_text(event.get("filename")),
                   "explain": self.service.info["explain_top"]}
        while True:
            try:
                return await self.service.submit(payload, source=clean_text(event.get("source")))
            except QueueFullError:
                await asyncio.sleep(0.25)

    async def run(self):
        owns_client = self.client is None
        client = self.client or httpx.AsyncClient(trust_env=False, follow_redirects=False,
                                                 timeout=httpx.Timeout(30, read=45))
        delay = 1
        try:
            while True:
                headers = {"Accept": "text/event-stream"}
                if self.last_id is not None:
                    headers["Last-Event-ID"] = self.last_id
                token = os.getenv(self.config.token_env, "")
                if token:
                    headers["Authorization"] = "Bearer " + token
                try:
                    async with client.stream("GET", self.config.url, headers=headers,
                                             follow_redirects=False) as response:
                        response.raise_for_status()
                        if response.headers.get("content-type", "").split(";")[0] != "text/event-stream":
                            raise RejectedEvent("Upstream response must be text/event-stream")
                        async for event_id, data in sse_messages(response, self.config.max_event_bytes):
                            try:
                                await self.handle(json.loads(data), client)
                            except (RejectedEvent, json.JSONDecodeError) as exc:
                                log_event("subscriber_rejected", error=type(exc).__name__)
                            if event_id is not None:
                                self.last_id = event_id
                            delay = 1
                except (httpx.HTTPError, ValueError, OSError) as exc:
                    log_event("subscriber_reconnect", error=type(exc).__name__)
                await asyncio.sleep(delay)
                delay = min(self.config.reconnect_max_s, delay * 2)
        finally:
            if owns_client:
                await client.aclose()
