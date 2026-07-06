"""PDF / CSV / XLSX report generation from Mongo aggregates."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone

from jinja2 import Template
from openpyxl import Workbook

from app.database.mongodb import get_db


_HTML = Template("""
<!doctype html><html><head><meta charset="utf-8">
<title>GuardianMail security report</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;padding:32px;color:#111}
h1{margin:0 0 4px;font-size:24px} .sub{color:#666;margin-bottom:24px}
table{width:100%;border-collapse:collapse;margin-top:16px}
th,td{text-align:left;padding:8px;border-bottom:1px solid #eee;font-size:12px}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px}
.safe{background:#e6f7ec;color:#137a3d} .susp{background:#fff5e0;color:#8a5a00}
.phish{background:#ffe4e4;color:#9a1b1b} .fraud{background:#f2e2ff;color:#5a1b8a}
</style></head><body>
<h1>{{ user.get('email','') }}</h1>
<div class="sub">GuardianMail report · {{ generated_at }}</div>
<div><b>Scanned:</b> {{ counts.total }} · <b>Threats:</b> {{ counts.threats }} · <b>Protection score:</b> {{ counts.score }}/100</div>
<h3>Recent verdicts</h3>
<table><thead><tr><th>When</th><th>Sender</th><th>Subject</th><th>Verdict</th><th>Risk</th></tr></thead><tbody>
{% for r in rows %}
<tr>
  <td>{{ r.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
  <td>{{ r.sender }}</td><td>{{ r.subject }}</td>
  <td><span class="pill {{ r.verdict }}">{{ r.verdict }}</span></td>
  <td>{{ r.risk_score }}</td>
</tr>
{% endfor %}
</tbody></table></body></html>
""")


async def _gather(user_id: str, days: int = 30) -> dict:
    db = get_db()
    since = datetime.now(timezone.utc) - timedelta(days=days)
    user = await db.users.find_one({"_id": user_id}) or {}
    rows = [r async for r in db.threats.find(
        {"user_id": user_id, "created_at": {"$gte": since}},
        sort=[("created_at", -1)], limit=500,
    )]
    total = len(rows)
    threats = sum(1 for r in rows if r.get("verdict") != "safe")
    return {
        "user": user, "rows": rows,
        "counts": {"total": total, "threats": threats,
                   "score": max(0, 100 - int((threats / max(total, 1)) * 70))},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


async def generate_pdf(user_id: str) -> bytes:
    from weasyprint import HTML  # heavy import — keep local
    ctx = await _gather(user_id)
    return HTML(string=_HTML.render(**ctx)).write_pdf()


async def generate_csv(user_id: str) -> bytes:
    ctx = await _gather(user_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["created_at", "sender", "subject", "verdict", "risk_score", "attack_category"])
    for r in ctx["rows"]:
        w.writerow([r.get("created_at"), r.get("sender"), r.get("subject"),
                    r.get("verdict"), r.get("risk_score"), r.get("attack_category")])
    return buf.getvalue().encode()


async def generate_xlsx(user_id: str) -> bytes:
    ctx = await _gather(user_id)
    wb = Workbook(); ws = wb.active; ws.title = "Threats"
    ws.append(["Created", "Sender", "Subject", "Verdict", "Risk", "Category"])
    for r in ctx["rows"]:
        ws.append([r.get("created_at"), r.get("sender"), r.get("subject"),
                   r.get("verdict"), r.get("risk_score"), r.get("attack_category")])
    out = io.BytesIO(); wb.save(out); return out.getvalue()


async def generate(user_id: str, fmt: str) -> tuple[bytes, str]:
    fmt = fmt.lower()
    if fmt == "csv":
        return await generate_csv(user_id), "text/csv"
    if fmt in ("xlsx", "excel"):
        return await generate_xlsx(user_id), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return await generate_pdf(user_id), "application/pdf"
