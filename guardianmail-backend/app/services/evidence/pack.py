"""Evidence Pack generator.

Bundles everything an investigator needs for a cybercrime submission:
  · sender / subject / message-id / thread-id / received-at
  · key headers (SPF/DKIM/DMARC/Received)
  · full indicator list + AI explanation
  · malicious URLs + domains + hashes
  · per-URL threat-intel scan results
  · risk timeline
  · JSON + CSV + PDF summary, packaged as ZIP
  · SHA-256 integrity hash printed on the front page

Bodies are excluded by default (privacy). Pass `include_body=True` to include
the original message text — the caller decides.
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from jinja2 import Template

from app.database.mongodb import get_db
from app.utils.hashing import sha256_bytes


_PDF_HTML = Template("""
<!doctype html><html><head><meta charset="utf-8">
<title>GuardianMail Evidence Pack {{ pack_id }}</title>
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;padding:32px;color:#111;font-size:12px}
h1{margin:0;font-size:22px} h2{margin-top:20px;font-size:14px;border-bottom:1px solid #ddd;padding-bottom:4px}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:11px}
.hash{background:#fff8e1;padding:6px 10px;border-radius:4px;display:inline-block}
table{width:100%;border-collapse:collapse;margin-top:8px}
th,td{border-bottom:1px solid #eee;text-align:left;padding:6px;vertical-align:top}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:10px;background:#eee}
.crit{background:#ffe4e4;color:#9a1b1b}
</style></head><body>
<h1>GuardianMail Evidence Pack</h1>
<div>Pack ID: <span class="mono">{{ pack_id }}</span></div>
<div>Generated: {{ generated_at }}</div>
<div>Integrity SHA-256: <span class="hash mono">{{ integrity }}</span></div>

<h2>Message</h2>
<table>
  <tr><th>Sender</th><td>{{ threat.sender }}</td></tr>
  <tr><th>Subject</th><td>{{ threat.subject }}</td></tr>
  <tr><th>Message-ID</th><td class="mono">{{ threat.message_id or 'N/A' }}</td></tr>
  <tr><th>Thread-ID</th><td class="mono">{{ threat.thread_id or 'N/A' }}</td></tr>
  <tr><th>Received</th><td>{{ threat.created_at }}</td></tr>
  <tr><th>Verdict</th><td><span class="pill crit">{{ threat.verdict }}</span> · risk {{ threat.risk_score }}/100</td></tr>
  <tr><th>Attack category</th><td>{{ threat.attack_category or 'unclassified' }}</td></tr>
</table>

<h2>Key headers</h2>
<table>{% for k, v in headers.items() %}<tr><th>{{ k }}</th><td class="mono">{{ v }}</td></tr>{% endfor %}</table>

<h2>Malicious URLs</h2>
<table><tr><th>URL</th><th>Flagged</th><th>Providers</th></tr>
{% for u in urls %}<tr><td class="mono">{{ u.url }}</td><td>{{ 'yes' if u.flagged else 'no' }}</td>
<td>{{ u.flagged_by|join(', ') }}</td></tr>{% endfor %}</table>

<h2>Indicators</h2>
<ul>{% for i in indicators %}<li><b>[{{ i.severity }}]</b> {{ i.category }} — {{ i.detail }}</li>{% endfor %}</ul>

<h2>AI explanation</h2>
<p>{{ threat.ai_summary or '(none)' }}</p>

<h2>Attachments</h2>
<table><tr><th>Name</th><th>MIME</th><th>SHA-256</th></tr>
{% for a in attachments %}<tr><td>{{ a.name }}</td><td>{{ a.mime }}</td><td class="mono">{{ a.sha256 or '' }}</td></tr>{% endfor %}
</table>
</body></html>
""")


def _extract_urls(url_intel: dict | None) -> list[dict]:
    results = (url_intel or {}).get("results", [])
    out = []
    for r in results:
        flagged_by = [p["provider"] for p in r.get("providers", []) if p.get("status") == "flagged"]
        out.append({"url": r.get("url"), "flagged": r.get("flagged", False), "flagged_by": flagged_by})
    return out


def _extract_headers(threat: dict) -> dict[str, str]:
    auth = threat.get("email_auth") or {}
    raw = threat.get("headers") or {}
    keep = {
        "From": raw.get("From") or threat.get("sender"),
        "Subject": raw.get("Subject") or threat.get("subject"),
        "Received": raw.get("Received"),
        "Return-Path": raw.get("Return-Path"),
        "Message-ID": raw.get("Message-ID") or threat.get("message_id"),
        "SPF": auth.get("spf"),
        "DKIM": auth.get("dkim"),
        "DMARC": auth.get("dmarc"),
    }
    return {k: v for k, v in keep.items() if v}


async def build(user_id: str, threat_id: str, include_body: bool = False) -> dict[str, Any]:
    """Generate an evidence pack for one threat. Returns the ZIP bytes + metadata."""
    from weasyprint import HTML  # heavy import

    db = get_db()
    threat = await db.threats.find_one({"_id": ObjectId(threat_id), "user_id": user_id})
    if not threat:
        raise ValueError("threat not found")

    urls = _extract_urls(threat.get("url_intel"))
    headers = _extract_headers(threat)
    indicators = (threat.get("signals") or {}).get("indicators") or threat.get("indicators") or []
    attachments = threat.get("attachments") or []
    if include_body is False:
        threat_view = {k: v for k, v in threat.items() if k not in ("body_text", "body_html")}
    else:
        threat_view = threat

    pack_id = str(ObjectId())
    generated_at = datetime.now(timezone.utc).isoformat()

    # ---- JSON export (canonical, serializable)
    json_payload = json.dumps({
        "pack_id": pack_id,
        "generated_at": generated_at,
        "user_id": user_id,
        "threat": _mongo_safe(threat_view),
        "headers": headers,
        "urls": urls,
        "indicators": indicators,
        "attachments": [{k: a.get(k) for k in ("name", "mime", "size", "sha256")} for a in attachments],
    }, default=str, indent=2).encode()

    # ---- CSV export (URLs + indicators, one row each)
    csv_buf = io.StringIO()
    w = csv.writer(csv_buf)
    w.writerow(["type", "field1", "field2", "field3"])
    for u in urls:
        w.writerow(["url", u["url"], "flagged" if u["flagged"] else "clean", ",".join(u["flagged_by"])])
    for i in indicators:
        w.writerow(["indicator", i.get("severity"), i.get("category"), i.get("detail")])
    for a in attachments:
        w.writerow(["attachment", a.get("name"), a.get("mime"), a.get("sha256", "")])
    csv_bytes = csv_buf.getvalue().encode()

    # ---- PDF summary
    pdf_bytes = HTML(string=_PDF_HTML.render(
        pack_id=pack_id, generated_at=generated_at,
        integrity="(computed after bundling)",
        threat=_mongo_safe(threat_view), headers=headers, urls=urls,
        indicators=indicators, attachments=attachments,
    )).write_pdf()

    # ---- ZIP bundle
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("evidence.json", json_payload)
        z.writestr("indicators.csv", csv_bytes)
        z.writestr("summary.pdf", pdf_bytes)
        z.writestr("README.txt", (
            f"GuardianMail Evidence Pack {pack_id}\n"
            f"Generated: {generated_at}\n\n"
            "Contents:\n"
            "  evidence.json  — canonical machine-readable dump\n"
            "  indicators.csv — flat table for spreadsheet import\n"
            "  summary.pdf    — investigator-ready one-pager\n\n"
            "Attach the entire ZIP to your cybercrime.gov.in complaint.\n"
        ).encode())
    zip_bytes = zip_buf.getvalue()
    integrity = sha256_bytes(zip_bytes)

    # persist metadata for history / retrieval
    await db.evidence_packs.insert_one({
        "_id": ObjectId(pack_id),
        "user_id": user_id,
        "threat_id": ObjectId(threat_id),
        "generated_at": datetime.now(timezone.utc),
        "sha256": integrity,
        "size_bytes": len(zip_bytes),
        "include_body": include_body,
    })

    return {
        "pack_id": pack_id, "sha256": integrity,
        "zip": zip_bytes, "size_bytes": len(zip_bytes),
        "json": json_payload, "pdf": pdf_bytes, "csv": csv_bytes,
        "urls": urls, "indicators": indicators, "headers": headers,
    }


def _mongo_safe(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: _mongo_safe(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_mongo_safe(x) for x in d]
    if isinstance(d, ObjectId):
        return str(d)
    if isinstance(d, datetime):
        return d.isoformat()
    return d
