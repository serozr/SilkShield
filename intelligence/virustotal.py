"""VirusTotal Adapter — handles all communication with the VirusTotal v3 API.

Features:
- Structured exception hierarchy (VTNotFoundError, VTRateLimitError, VTAuthError, VTNetworkError)
- Automatic URL identifier encoding (base64url per VT v3 spec)
- Connection verification and CLI healthcheck tool
- Safe handling of rate limits and missing keys
"""

from __future__ import annotations

import base64
import time
from typing import Any, Dict, Optional

import httpx

from app.config import settings

VT_BASE = "https://www.virustotal.com/api/v3"


# ─── Exception Hierarchy ────────────────────────────────────── #

class VTError(Exception):
    """Base exception for all VirusTotal operations."""
    pass


class VTAuthError(VTError):
    """Raised on HTTP 401 or 403 (invalid, missing, or forbidden API key)."""
    pass


class VTRateLimitError(VTError):
    """Raised on HTTP 429 (quota or 4 req/min limit exceeded)."""
    pass


class VTNotFoundError(VTError):
    """Raised on HTTP 404 (indicator not found in VirusTotal database)."""
    pass


class VTNetworkError(VTError):
    """Raised on connection timeout or network transport errors."""
    pass


# ─── Client ─────────────────────────────────────────────────── #

class VirusTotalClient:
    """Async client for the VirusTotal public API v3."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.api_key = (api_key if api_key is not None else settings.virustotal_api_key).strip()
        self._headers = {"x-apikey": self.api_key} if self.api_key else {}

    # --- availability ---
    @property
    def is_configured(self) -> bool:
        """Return True if an API key is present."""
        return bool(self.api_key)

    # --- lookup helpers ---
    async def _get(self, path: str) -> dict:
        if not self.is_configured:
            raise VTAuthError("VirusTotal API key is not configured in .env")

        url = f"{VT_BASE}{path}"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=self._headers)
                if resp.status_code == 404:
                    raise VTNotFoundError(f"Indicator not found on VirusTotal: {path}")
                if resp.status_code == 429:
                    raise VTRateLimitError(
                        "VirusTotal API rate limit or daily quota reached (free tier: 4 req/min)."
                    )
                if resp.status_code in (401, 403):
                    raise VTAuthError(
                        f"VirusTotal authentication failed (HTTP {resp.status_code}). Check VIRUSTOTAL_API_KEY in .env."
                    )
                resp.raise_for_status()
                return resp.json()
        except (VTNotFoundError, VTRateLimitError, VTAuthError):
            raise
        except httpx.TimeoutException as e:
            raise VTNetworkError(f"VirusTotal connection timed out: {e}") from e
        except httpx.RequestError as e:
            raise VTNetworkError(f"VirusTotal network error: {e}") from e

    async def lookup_domain(self, domain: str) -> dict:
        return await self._get(f"/domains/{domain.strip().lower()}")

    async def lookup_ip(self, ip: str) -> dict:
        return await self._get(f"/ip_addresses/{ip.strip()}")

    async def lookup_url(self, url: str) -> dict:
        url_clean = url.strip()
        url_id = base64.urlsafe_b64encode(url_clean.encode()).decode().rstrip("=")
        return await self._get(f"/urls/{url_id}")

    async def lookup_hash(self, file_hash: str) -> dict:
        return await self._get(f"/files/{file_hash.strip().lower()}")

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

    # --- connection verification ---
    async def test_connection(self) -> Dict[str, Any]:
        """Test API key validity and network connectivity with a benign canary IOC."""
        if not self.is_configured:
            return {
                "ok": False,
                "status": "missing_key",
                "message": "VIRUSTOTAL_API_KEY is not set. Add your key to .env to enable live intelligence.",
            }

        start = time.perf_counter()
        try:
            # Canary query to a known public resolver
            data = await self.lookup_ip("8.8.8.8")
            elapsed = round((time.perf_counter() - start) * 1000, 1)
            attrs = data.get("data", {}).get("attributes", {})
            as_owner = attrs.get("as_owner", "Google LLC")
            return {
                "ok": True,
                "status": "connected",
                "latency_ms": elapsed,
                "message": f"Successfully connected to VirusTotal API v3 ({elapsed}ms latency, canary validated).",
                "canary_owner": as_owner,
            }
        except VTAuthError as e:
            return {
                "ok": False,
                "status": "invalid_key",
                "message": str(e),
            }
        except VTRateLimitError as e:
            return {
                "ok": False,
                "status": "rate_limited",
                "message": str(e),
            }
        except VTNetworkError as e:
            return {
                "ok": False,
                "status": "network_error",
                "message": str(e),
            }
        except Exception as e:
            return {
                "ok": False,
                "status": "error",
                "message": f"Unexpected error: {e}",
            }


# ─── CLI Healthcheck & Diagnostic Tool ──────────────────────── #

if __name__ == "__main__":
    import asyncio

    async def _cli():
        print("=" * 60)
        print("  SilkShield -- VirusTotal API Healthcheck & Diagnostics")
        print("=" * 60)

        client = VirusTotalClient()
        if not client.is_configured:
            print("\n[!] Status: VIRUSTOTAL_API_KEY is NOT configured.")
            print("\nHow to configure your API key:")
            print("  1. Open or create the .env file in the project root.")
            print("  2. Add: VIRUSTOTAL_API_KEY=your_virustotal_api_key_here")
            print("  3. Save the file and re-run this tool:")
            print("     python -m intelligence.virustotal")
            print("=" * 60)
            return

        masked = client.api_key[:4] + "..." + client.api_key[-4:] if len(client.api_key) > 8 else "***"
        print(f"\n[*] Configured API key: {masked}")
        print("[*] Testing live connectivity with canary query (8.8.8.8)...")

        result = await client.test_connection()
        if result["ok"]:
            print(f"\n[+] Success! {result['message']}")
            print(f"    Latency: {result.get('latency_ms')} ms")
            print("    Live VirusTotal intelligence is active and ready.")
        else:
            print(f"\n[-] Failed! [{result['status'].upper()}]")
            print(f"    {result['message']}")

        print("=" * 60)

    asyncio.run(_cli())
