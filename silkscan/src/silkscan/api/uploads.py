"""Bounded, memory-only uploads: multipart never spills samples to /tmp."""
from __future__ import annotations

import unicodedata

from python_multipart import MultipartParser
from python_multipart.multipart import parse_options_header
from starlette.exceptions import HTTPException


def clean_text(value, limit=255):
    if not isinstance(value, str):
        return ""
    return "".join(c for c in value if not unicodedata.category(c).startswith("C"))[:limit]


async def read_body(request, limit):
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            size = int(declared)
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length") from None
        if size < 0:
            raise HTTPException(400, "Invalid Content-Length")
        if size > limit:
            raise HTTPException(413, "Request exceeds max_file_mb")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > limit:
            raise HTTPException(413, "Request exceeds max_file_mb")
        data.extend(chunk)
    return bytes(data)


def multipart_file(body, content_type):
    _, options = parse_options_header(content_type)
    boundary = options.get(b"boundary")
    if not boundary or len(boundary) > 200:
        raise HTTPException(422, "Invalid multipart boundary")
    data = bytearray()
    header_name, header_value = bytearray(), bytearray()
    headers = {}
    state = {"parts": 0, "filename": None, "complete": False}

    def begin():
        state["parts"] += 1
        if state["parts"] > 1:
            raise HTTPException(422, "Expected exactly one file part named file")

    def field(buf, start, end):
        header_name.extend(buf[start:end])
        if len(header_name) > 1024:
            raise HTTPException(422, "Multipart header too large")

    def value(buf, start, end):
        header_value.extend(buf[start:end])
        if len(header_value) > 8192:
            raise HTTPException(422, "Multipart header too large")

    def header_end():
        if len(headers) > 16:
            raise HTTPException(422, "Too many multipart headers")
        headers[bytes(header_name).lower()] = bytes(header_value)
        header_name.clear()
        header_value.clear()

    def headers_done():
        _, params = parse_options_header(headers.get(b"content-disposition", b""))
        if params.get(b"name") != b"file" or b"filename" not in params:
            raise HTTPException(422, "Expected a file part named file")
        state["filename"] = clean_text(params[b"filename"].decode("utf-8", errors="replace"))

    callbacks = {"on_part_begin": begin, "on_header_field": field, "on_header_value": value,
                 "on_header_end": header_end, "on_headers_finished": headers_done,
                 "on_part_data": lambda buf, start, end: data.extend(buf[start:end]),
                 "on_end": lambda: state.update(complete=True)}
    try:
        parser = MultipartParser(boundary, callbacks)
        parser.write(body)
        parser.finalize()
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(422, "Malformed multipart body") from None
    if not state["complete"] or state["filename"] is None:
        raise HTTPException(422, "Incomplete multipart upload")
    return bytes(data), state["filename"]
