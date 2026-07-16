"""Unit tests for Module 9 — Complaint & Evidence platform.

These tests exercise the pure/deterministic paths (integrity envelopes,
template registry rendering, exporters). Repository-bound tests are
covered by integration suites.
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timezone

import pytest

from app.services.complaints.template_registry import (
    COMPLAINT_CATEGORIES, COMPLAINT_DESTINATIONS, _DEFAULT_CATALOGUE,
    ComplaintTemplate,
)
from app.services.evidence import exporters
from app.services.evidence.integrity import (
    canonical_json, integrity_envelope, sha256_hex, verify_envelope,
)


def _sample_bundle() -> dict:
    manifest = {
        "summary": {"verdict": "phishing", "risk_score": 87,
                    "confidence": 92, "sender": "attacker@example.com"},
        "message": {"sender": "attacker@example.com",
                    "subject": "Verify your account", "message_id": "<abc@ex>"},
        "authentication": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
        "indicators": [
            {"severity": "high", "category": "url", "detail": "known phishing host"},
        ],
        "urls": [
            {"url": "http://bad.example/login", "flagged": True,
             "flagged_by": ["gsb", "phishtank"]},
        ],
        "attachments": [],
        "ai_report": {"summary": "AI marked this phishing.", "verdict": "phishing",
                       "confidence": 92, "recommendations": ["Do not click."]},
        "timeline": [
            {"at": datetime.now(timezone.utc).isoformat(), "event": "ingested"},
        ],
    }
    envelope = integrity_envelope("507f1f77bcf86cd799439011", manifest)
    return {
        "manifest": manifest,
        "summary": manifest["summary"],
        "message": manifest["message"],
        "authentication": manifest["authentication"],
        "indicators": manifest["indicators"],
        "urls": manifest["urls"],
        "attachments": [],
        "timeline": manifest["timeline"],
        "ai_report": manifest["ai_report"],
        "chain_of_custody": [
            {"at": datetime.now(timezone.utc).isoformat(),
             "event": "pack_generated", "actor": "user-1"}
        ],
        "integrity": envelope,
    }


# --------------------------------------------------------------------------- #
# Integrity                                                                   #
# --------------------------------------------------------------------------- #
def test_canonical_json_is_deterministic():
    a = {"b": 2, "a": 1, "n": [1, 2, 3]}
    b = {"n": [1, 2, 3], "a": 1, "b": 2}
    assert canonical_json(a) == canonical_json(b)


def test_integrity_envelope_verifies():
    manifest = {"summary": {"verdict": "phishing"}, "urls": []}
    env = integrity_envelope("pack-1", manifest)
    ok, reason = verify_envelope(env)
    assert ok, reason


def test_integrity_envelope_detects_tamper():
    manifest = {"summary": {"verdict": "phishing"}, "urls": []}
    env = integrity_envelope("pack-1", manifest)
    env["manifest"]["summary"]["verdict"] = "safe"
    ok, reason = verify_envelope(env)
    assert not ok
    assert "sha256" in reason


def test_sha256_hex_matches_stdlib():
    import hashlib
    assert sha256_hex(b"abc") == hashlib.sha256(b"abc").hexdigest()


# --------------------------------------------------------------------------- #
# Templates                                                                   #
# --------------------------------------------------------------------------- #
def test_catalogue_covers_all_destinations_and_categories():
    seen_destinations = {k[0] for k in _DEFAULT_CATALOGUE}
    seen_categories = {k[1] for k in _DEFAULT_CATALOGUE}
    assert seen_destinations == set(COMPLAINT_DESTINATIONS)
    assert seen_categories == set(COMPLAINT_CATEGORIES)


def test_template_renders_with_full_context():
    tpl: ComplaintTemplate = _DEFAULT_CATALOGUE[
        ("cybercrime_gov_in", "phishing", "en", 1)
    ]
    ctx = {
        "victim_name": "Jane", "victim_email": "jane@example.com",
        "victim_phone": "+91-99999", "category_label": "Phishing",
        "sender": "attacker@ex", "subject_line": "Verify",
        "message_id": "<a@b>", "received_at": "2025-01-01T00:00:00Z",
        "verdict": "phishing", "risk_score": 90, "confidence": 88,
        "attack_category": "credential_theft",
        "spf": "fail", "dkim": "none", "dmarc": "fail",
        "indicators": ["[high] url — bad"], "urls": ["http://bad/"],
        "ai_summary": "AI says phishing.",
        "recommended_action": "Block sender",
        "evidence_id": "abc", "evidence_hash": "deadbeef",
        "evidence_generated_at": "2025-01-01T00:00:01Z",
        "chain_of_custody_id": "abc",
    }
    out = tpl.render(ctx)
    assert "GuardianMail" in out["subject"]
    assert "Phishing" in out["body"]
    assert "deadbeef" in out["body"]
    assert "http://bad/" in out["body"]


# --------------------------------------------------------------------------- #
# Exporters                                                                   #
# --------------------------------------------------------------------------- #
def test_json_export_matches_canonical():
    bundle = _sample_bundle()
    data = exporters.to_json(bundle)
    parsed = json.loads(data)
    assert parsed["integrity"]["pack_id"] == "507f1f77bcf86cd799439011"
    assert parsed["manifest"]["summary"]["verdict"] == "phishing"


def test_csv_export_contains_indicator_row():
    bundle = _sample_bundle()
    csv_data = exporters.to_csv(bundle).decode()
    assert "known phishing host" in csv_data
    assert "http://bad.example/login" in csv_data


def test_zip_bundle_contains_all_artefacts():
    bundle = _sample_bundle()
    data = exporters.to_zip(bundle)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
    pack_id = bundle["integrity"]["pack_id"]
    assert f"{pack_id}/manifest.json" in names
    assert f"{pack_id}/indicators.csv" in names
    assert f"{pack_id}/INTEGRITY.txt" in names


@pytest.mark.parametrize("fmt", ["json", "csv", "zip"])
def test_render_dispatcher(fmt):
    data, mime = exporters.render(_sample_bundle(), fmt)
    assert data and mime


def test_render_rejects_unknown_format():
    with pytest.raises(ValueError):
        exporters.render(_sample_bundle(), "xml")
