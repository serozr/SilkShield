"""VirusTotal Adapter — handles all communication with the VirusTotal v3 API."""

from __future__ import annotations

import base64

import httpx

from app.config import settings

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    """Async client for the VirusTotal public API v3."""

    def __init__(self) -> None:
        self.api_key = settings.virustotal_api_key
        self._headers = {"x-apikey": self.api_key}

    # --- availability ---
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    # --- lookup helpers ---
    async def _get(self, path: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{VT_BASE}{path}",
                headers=self._headers,
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()

    async def lookup_domain(self, domain: str) -> dict:
        return await self._get(f"/domains/{domain}")

    async def lookup_ip(self, ip: str) -> dict:
        return await self._get(f"/ip_addresses/{ip}")

    async def lookup_url(self, url: str) -> dict:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._get(f"/urls/{url_id}")

    async def lookup_hash(self, file_hash: str) -> dict:
        return await self._get(f"/files/{file_hash}")

    # --- dispatcher ---
    async def lookup(self, ioc: str, ioc_type: str) -> dict:
        """Route to the correct lookup method based on IOC type."""
        dispatch = {
            "domain": self.lookup_domain,
            "ip": self.lookup_ip,
            "url": self.lookup_url,
            "hash": self.lookup_hash,
        }
        handler = dispatch.get(ioc_type)
        if handler is None:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        return await handler(ioc)
