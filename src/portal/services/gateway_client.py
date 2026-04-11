"""Async HTTP client for the gateway admin API.

The portal authenticates to the gateway using a service account JWT
configured via GATEWAY_SERVICE_JWT. All calls MUST use HTTPS in production;
the REQUIRE_HTTPS startup validator enforces this.
"""

import structlog
from httpx import AsyncClient, HTTPError

from portal.config import settings

logger = structlog.get_logger(__name__)


class GatewayClient:
    """Thin wrapper around httpx for gateway admin API calls."""

    def __init__(self, http_client: AsyncClient) -> None:
        self._http = http_client
        self._base = settings.gateway_admin_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {settings.gateway_service_jwt}",
            "Content-Type": "application/json",
        }

    async def _get(self, path: str) -> dict | list | None:
        url = f"{self._base}{path}"
        try:
            resp = await self._http.get(url, headers=self._headers)
            resp.raise_for_status()
            return resp.json()
        except HTTPError as exc:
            logger.warning("gateway_client.get.error", path=path, error=str(exc))
            return None

    async def _post(self, path: str, data: dict) -> dict | None:
        url = f"{self._base}{path}"
        try:
            resp = await self._http.post(url, json=data, headers=self._headers)
            resp.raise_for_status()
            return resp.json()
        except HTTPError as exc:
            logger.warning("gateway_client.post.error", path=path, error=str(exc))
            return None

    async def _put(self, path: str, data: dict) -> dict | None:
        url = f"{self._base}{path}"
        try:
            resp = await self._http.put(url, json=data, headers=self._headers)
            resp.raise_for_status()
            return resp.json()
        except HTTPError as exc:
            logger.warning("gateway_client.put.error", path=path, error=str(exc))
            return None

    async def _delete(self, path: str) -> bool:
        url = f"{self._base}{path}"
        try:
            resp = await self._http.delete(url, headers=self._headers)
            resp.raise_for_status()
            return True
        except HTTPError as exc:
            logger.warning("gateway_client.delete.error", path=path, error=str(exc))
            return False

    # ── Vendor catalog ─────────────────────────────────────────────────

    async def list_vendors(self) -> list:
        result = await self._get("/admin/vendors")
        if result is None:
            return []
        # Gateway returns list directly or wrapped in {"vendors": [...]}
        if isinstance(result, list):
            return result
        return result.get("vendors", [])

    async def get_vendor(self, vendor_id: str) -> dict | None:
        return await self._get(f"/admin/vendors/{vendor_id}")

    async def get_vendor_quota(self, vendor_id: str) -> dict | None:
        return await self._get(f"/admin/vendors/{vendor_id}/quota")

    async def create_vendor(self, data: dict) -> dict | None:
        return await self._post("/admin/vendors", data)

    async def update_vendor(self, vendor_id: str, data: dict) -> dict | None:
        return await self._put(f"/admin/vendors/{vendor_id}", data)

    async def deactivate_vendor(self, vendor_id: str) -> bool:
        return await self._delete(f"/admin/vendors/{vendor_id}")

    async def flush_vendor_cache(self, vendor_id: str) -> bool:
        return await self._delete(f"/admin/vendors/{vendor_id}/cache")
