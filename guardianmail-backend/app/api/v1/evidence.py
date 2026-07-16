"""Evidence pack download endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from app.core.security import require_user
from app.services.evidence.pack import build

router = APIRouter(prefix="/evidence", tags=["evidence"])


@router.get("/{threat_id}/download")
async def download(
    threat_id: str,
    user=Depends(require_user),
    fmt: str = Query(default="zip", pattern="^(zip|json|pdf|csv)$"),
    include_body: bool = Query(default=False),
):
    try:
        pack = await build(user["sub"], threat_id, include_body=include_body)
    except ValueError as e:
        raise HTTPException(404, str(e))
    disp = f'attachment; filename="guardianmail-evidence-{pack["pack_id"]}.{fmt}"'
    headers = {"content-disposition": disp, "x-pack-id": pack["pack_id"], "x-pack-sha256": pack["sha256"]}
    if fmt == "json":
        return Response(pack["json"], media_type="application/json", headers=headers)
    if fmt == "pdf":
        return Response(pack["pdf"], media_type="application/pdf", headers=headers)
    if fmt == "csv":
        return Response(pack["csv"], media_type="text/csv", headers=headers)
    return Response(pack["zip"], media_type="application/zip", headers=headers)
