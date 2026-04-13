"""Vendor catalog routes — proxied from the gateway admin API.

All authenticated users can browse the catalog (read-only).
Admin users can create, update, and deactivate vendors via the same
proxy (write calls are forwarded to the gateway admin API).
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from portal.auth.dependencies import get_current_user, require_admin
from portal.db.models import User
from portal.db.session import get_db
from portal.services.audit import log_action
from portal.services.gateway_client import GatewayClient
from portal.sse import is_datastar_request, merge_fragments, merge_signals

router = APIRouter(tags=["vendors"])
templates = Jinja2Templates(directory="src/portal/templates")


def _get_gateway_client(request: Request) -> GatewayClient:
    return GatewayClient(request.app.state.http_client)


def _normalize_vendor_payload(data: dict) -> dict:
    """Accept API payloads and Datastar signal payloads.

    Only non-empty fields are included so callers can do partial updates
    (e.g. reactivate-only) without overwriting unrelated fields.
    """
    out: dict = {}
    name = data.get("name") or data.get("vendorName")
    if name:
        out["name"] = name
    slug = data.get("slug") or data.get("vendorSlug")
    if slug:
        out["slug"] = slug
    base_url = data.get("base_url") or data.get("baseUrl") or data.get("vendorBaseUrl")
    if base_url:
        out["base_url"] = base_url
    auth_type = data.get("auth_type") or data.get("authType") or data.get("vendorAuthType")
    if auth_type:
        out["auth_type"] = auth_type
    # is_active passthrough for reactivation
    is_active = data.get("is_active") if "is_active" in data else data.get("isActive")
    if is_active is not None:
        out["is_active"] = is_active
    return out


# ── Pages ──────────────────────────────────────────────────────────────────


@router.get("/vendors")
async def vendors_page(
    request: Request,
    user: User = Depends(get_current_user),
):
    gw = _get_gateway_client(request)
    vendors = await gw.list_vendors()
    if vendors is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="gateway_error",
        )
    ctx = {"request": request, "user": user, "vendors": vendors}
    if is_datastar_request(request):
        html = templates.get_template("fragments/vendor_list.html").render(ctx)
        return merge_fragments(f'<div id="vendor-list">{html}</div>')
    return templates.TemplateResponse(request=request, name="vendors.html", context=ctx)


@router.get("/admin/vendors")
async def admin_vendors_page(
    request: Request,
    admin: User = Depends(require_admin),
):
    gw = _get_gateway_client(request)
    vendors = await gw.list_vendors()
    if vendors is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="gateway_error",
        )
    ctx = {"request": request, "user": admin, "vendors": vendors}
    if is_datastar_request(request):
        html = templates.get_template("fragments/admin_vendor_list.html").render(ctx)
        return merge_fragments(f'<div id="vendor-admin-list">{html}</div>')
    return templates.TemplateResponse(request=request, name="admin_vendors.html", context=ctx)


@router.get("/vendors/{vendor_id}")
async def vendor_detail_page(
    vendor_id: str,
    request: Request,
    user: User = Depends(get_current_user),
):
    gw = _get_gateway_client(request)
    vendor = await gw.get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="vendor_not_found")
    quota = await gw.get_vendor_quota(vendor_id)
    ctx = {
        "request": request,
        "user": user,
        "vendor": vendor,
        "quota": quota or {},
    }
    return templates.TemplateResponse(request=request, name="vendor_detail.html", context=ctx)


# ── API (proxy) ────────────────────────────────────────────────────────────


@router.get("/api/vendors")
async def list_vendors_api(
    request: Request,
    user: User = Depends(get_current_user),
) -> list:
    gw = _get_gateway_client(request)
    vendors = await gw.list_vendors()
    if vendors is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="gateway_error",
        )
    return vendors


@router.get("/api/vendors/{vendor_id}")
async def get_vendor_api(
    vendor_id: str,
    request: Request,
    user: User = Depends(get_current_user),
) -> dict:
    gw = _get_gateway_client(request)
    vendor = await gw.get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="vendor_not_found")
    return vendor


@router.post("/api/vendors", status_code=201)
async def create_vendor_api(
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    data = _normalize_vendor_payload(await request.json())
    gw = _get_gateway_client(request)
    result = await gw.create_vendor(data)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="gateway_error",
        )
    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=admin.id,
        action="vendor.created",
        resource_type="vendor",
        resource_id=str(result.get("id", "unknown")),
        details=data,
        ip_address=ip,
    )
    await db.commit()

    if is_datastar_request(request):
        vendors = await gw.list_vendors()
        ctx = {"request": request, "user": admin, "vendors": vendors}
        html = templates.get_template("fragments/admin_vendor_list.html").render(ctx)
        return merge_fragments(f'<div id="vendor-admin-list">{html}</div>')

    return result


@router.put("/api/vendors/{vendor_id}")
async def update_vendor_api(
    vendor_id: str,
    request: Request,
    view: str = "",
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    data = _normalize_vendor_payload(await request.json())
    gw = _get_gateway_client(request)
    result = await gw.update_vendor(vendor_id, data)
    if result is None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="gateway_error")
    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=admin.id,
        action="vendor.updated",
        resource_type="vendor",
        resource_id=vendor_id,
        details=data,
        ip_address=ip,
    )
    await db.commit()

    if is_datastar_request(request):
        if view == "admin":
            vendors = await gw.list_vendors()
            ctx = {"request": request, "user": admin, "vendors": vendors}
            html = templates.get_template("fragments/admin_vendor_list.html").render(ctx)
            return merge_fragments(f'<div id="vendor-admin-list">{html}</div>')
        return merge_signals({"redirect": f"/vendors/{vendor_id}"})

    return result


@router.put("/api/vendors/{vendor_id}/activate")
async def activate_vendor_api(
    vendor_id: str,
    request: Request,
    view: str = "",
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Reactivate a vendor. Returns admin fragment when view=admin (Datastar), else JSON."""
    gw = _get_gateway_client(request)
    result = await gw.update_vendor(vendor_id, {"is_active": True})
    if result is None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="gateway_error")
    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=admin.id,
        action="vendor.reactivated",
        resource_type="vendor",
        resource_id=vendor_id,
        ip_address=ip,
    )
    await db.commit()
    if is_datastar_request(request) and view == "admin":
        vendors = await gw.list_vendors()
        ctx = {"request": request, "user": admin, "vendors": vendors}
        html = templates.get_template("fragments/admin_vendor_list.html").render(ctx)
        return merge_fragments(f'<div id="vendor-admin-list">{html}</div>')
    return result


@router.delete("/api/vendors/{vendor_id}")
async def deactivate_vendor_api(
    vendor_id: str,
    request: Request,
    view: str = "",
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    gw = _get_gateway_client(request)
    ok = await gw.deactivate_vendor(vendor_id)
    if not ok:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="gateway_error")
    ip = request.client.host if request.client else None
    await log_action(
        db,
        user_id=admin.id,
        action="vendor.deactivated",
        resource_type="vendor",
        resource_id=vendor_id,
        ip_address=ip,
    )
    await db.commit()
    if is_datastar_request(request):
        if view == "admin":
            vendors = await gw.list_vendors()
            ctx = {"request": request, "user": admin, "vendors": vendors}
            html = templates.get_template("fragments/admin_vendor_list.html").render(ctx)
            return merge_fragments(f'<div id="vendor-admin-list">{html}</div>')
        return merge_signals({"redirect": "/vendors"})
    return {"status": "ok"}
