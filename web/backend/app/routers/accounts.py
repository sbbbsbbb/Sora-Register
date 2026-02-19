from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from app.routers.auth import get_current_user
from app.database import get_db, init_db
import csv
import io

router = APIRouter(prefix="/api/accounts", tags=["accounts"])


@router.get("")
def list_accounts(
    username: str = Depends(get_current_user),
    status: str = Query(None),
    has_sora: bool = Query(None),
    has_plus: bool = Query(None),
    phone_bound: bool = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
):
    init_db()
    with get_db() as conn:
        c = conn.cursor()
        where = []
        params = []
        if status:
            where.append("status = ?")
            params.append(status)
        if has_sora is not None:
            where.append("has_sora = ?")
            params.append(1 if has_sora else 0)
        if has_plus is not None:
            where.append("has_plus = ?")
            params.append(1 if has_plus else 0)
        if phone_bound is not None:
            where.append("phone_bound = ?")
            params.append(1 if phone_bound else 0)
        where_sql = " AND ".join(where) if where else "1=1"
        c.execute(
            f"SELECT COUNT(*) FROM accounts WHERE {where_sql}",
            params
        )
        total = c.fetchone()[0]
        offset = (page - 1) * page_size
        c.execute(
            f"""SELECT id, email, password, status, registered_at,
                   has_sora, has_plus, phone_bound, proxy, refresh_token, access_token, created_at
            FROM accounts WHERE {where_sql}
            ORDER BY id DESC LIMIT ? OFFSET ?""",
            params + [page_size, offset]
        )
        rows = c.fetchall()
    items = []
    for r in rows:
        items.append({
            "id": r[0],
            "email": r[1],
            "password": r[2],
            "status": r[3],
            "registered_at": r[4],
            "has_sora": bool(r[5]),
            "has_plus": bool(r[6]),
            "phone_bound": bool(r[7]),
            "proxy": r[8],
            "refresh_token": (r[9] or "")[:20] + "..." if r[9] else "",
            "access_token": (r[10] or "")[:20] + "..." if r[10] else "",
            "created_at": r[11],
        })
    return {"total": total, "page": page, "page_size": page_size, "items": items}


@router.get("/export")
def export_accounts(
    username: str = Depends(get_current_user),
    status: str = Query(None),
    has_sora: bool = Query(None),
    has_plus: bool = Query(None),
):
    init_db()
    with get_db() as conn:
        c = conn.cursor()
        where = []
        params = []
        if status:
            where.append("status = ?")
            params.append(status)
        if has_sora is not None:
            where.append("has_sora = ?")
            params.append(1 if has_sora else 0)
        if has_plus is not None:
            where.append("has_plus = ?")
            params.append(1 if has_plus else 0)
        where_sql = " AND ".join(where) if where else "1=1"
        c.execute(
            f"""SELECT email, password, status, registered_at, has_sora, has_plus, phone_bound, proxy, refresh_token, access_token
            FROM accounts WHERE {where_sql} ORDER BY id DESC""",
            params
        )
        rows = c.fetchall()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["email", "password", "status", "registered_at", "has_sora", "has_plus", "phone_bound", "proxy", "refresh_token", "access_token"])
    for r in rows:
        writer.writerow([
            r[0], r[1], r[2], r[3],
            "Y" if r[4] else "N", "Y" if r[5] else "N", "Y" if r[6] else "N",
            r[7] or "", r[8] or "", r[9] or ""
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=accounts.csv"}
    )
