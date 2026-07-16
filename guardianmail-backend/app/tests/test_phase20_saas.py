"""Phase 20 — SaaS unit tests (framework-independent).

Uses stdlib `unittest`; the module's `__test__` hooks let the surrounding
pytest suite pick them up automatically without extra config.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from app.services.saas import (
    BillingService, LicenseService, OrganizationService, QuotaService,
    RBACService, SubscriptionService, TenantService, UsageService,
    WorkspaceService,
)
from app.services.saas.plans import get_plan
from app.services.saas.tenant_service import TenantContext
from app.services.saas.retention_service import cutoff, normalize_retention


class TestTenantIsolation(unittest.TestCase):
    def setUp(self):
        self.svc = TenantService()

    def test_tenant_ids_are_unique(self):
        self.assertNotEqual(self.svc.new_tenant_id(), self.svc.new_tenant_id())

    def test_build_tenant_defaults(self):
        t = self.svc.build_tenant(name="Acme Inc")
        self.assertEqual(t["slug"], "acme-inc")
        self.assertEqual(t["plan"], "free")
        self.assertIn("password_policy", t["settings"])

    def test_cross_tenant_rejected(self):
        ctx = TenantContext(tenant_id="A", organization_id=None,
                            workspace_id=None, user_id="u")
        with self.assertRaises(PermissionError):
            TenantService.ensure_same_tenant(ctx, "B")

    def test_scope_query_injects_tenant(self):
        ctx = TenantContext(tenant_id="tnt_1", organization_id=None,
                            workspace_id=None, user_id="u")
        self.assertEqual(TenantService.scope_query(ctx, {"x": 1})["tenant_id"], "tnt_1")

    def test_invalid_isolation_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.build_tenant(name="Acme", isolation="bogus")


class TestOrganization(unittest.TestCase):
    def setUp(self):
        self.svc = OrganizationService()

    def test_domain_allow_list(self):
        org = self.svc.build_organization(
            tenant_id="t", name="Acme", owner_user_id="u")
        org["settings"]["allowed_email_domains"] = ["acme.com"]
        self.assertTrue(self.svc.domain_allowed(org, "user@acme.com"))
        self.assertFalse(self.svc.domain_allowed(org, "user@evil.com"))

    def test_invalid_org_type_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.build_organization(
                tenant_id="t", name="Acme", owner_user_id="u", org_type="bad")

    def test_member_suspend_and_remove(self):
        m = self.svc.build_member(
            organization_id="o", tenant_id="t",
            user_id="u1", email="a@b.com", roles=("employee",))
        self.svc.suspend(m, reason="policy")
        self.assertEqual(m["status"], "suspended")
        self.svc.remove(m)
        self.assertEqual(m["status"], "removed")


class TestWorkspace(unittest.TestCase):
    def test_workspace_membership(self):
        svc = WorkspaceService()
        w = svc.build_workspace(tenant_id="t", organization_id="o",
                                name="Team A", owner_user_id="u1")
        svc.add_members(w, ["u2", "u3"])
        self.assertTrue(svc.user_in_workspace(w, "u2"))
        svc.remove_member(w, "u2")
        self.assertFalse(svc.user_in_workspace(w, "u2"))


class TestRBAC(unittest.TestCase):
    def test_builtin_role_permissions(self):
        r = RBACService()
        self.assertTrue(r.has_permission(["administrator"], "user.manage"))
        self.assertFalse(r.has_permission(["guest"], "admin.manage"))
        self.assertTrue(r.has_permission(["soc_analyst"], "soc.manage"))

    def test_unknown_permission_denied(self):
        r = RBACService()
        self.assertFalse(r.has_permission(["owner"], "does.not.exist"))

    def test_custom_role_registration(self):
        r = RBACService()
        r.register_custom_role("auditor", ["threat.read", "analytics.read"])
        self.assertTrue(r.has_permission(["auditor"], "threat.read"))
        with self.assertRaises(ValueError):
            r.register_custom_role("owner", ["threat.read"])


class TestSubscription(unittest.TestCase):
    def test_build_and_active(self):
        svc = SubscriptionService()
        sub = svc.build(tenant_id="t", plan="professional",
                        billing_cycle="annual", seats=10)
        self.assertEqual(sub["plan"], "professional")
        self.assertTrue(svc.is_active(sub))
        self.assertTrue(svc.feature_enabled(sub, "analytics"))

    def test_expired_period(self):
        svc = SubscriptionService()
        sub = svc.build(tenant_id="t", plan="starter")
        sub["current_period_end"] = datetime.now(timezone.utc) - timedelta(days=1)
        self.assertFalse(svc.is_active(sub))

    def test_change_plan(self):
        svc = SubscriptionService()
        sub = svc.build(tenant_id="t", plan="free")
        svc.change_plan(sub, "business")
        self.assertEqual(sub["plan"], "business")


class TestUsageAndQuota(unittest.TestCase):
    def test_quota_blocks_on_daily_cap(self):
        usage = UsageService()
        quota = QuotaService(usage)
        limits = get_plan("free")   # daily_scans=25
        for _ in range(25):
            self.assertTrue(quota.consume("t", "threat_scans", limits).allowed)
        self.assertFalse(quota.check("t", "threat_scans", limits).allowed)

    def test_unlimited_plan_never_blocks(self):
        usage = UsageService()
        quota = QuotaService(usage)
        limits = get_plan("custom")
        for _ in range(500):
            self.assertTrue(quota.consume("t", "ai_requests", limits).allowed)

    def test_usage_snapshot_shape(self):
        usage = UsageService()
        usage.record("t", "emails_scanned", 3)
        snap = usage.snapshot("t")
        self.assertEqual(snap["daily"]["emails_scanned"], 3)
        self.assertEqual(snap["monthly"]["emails_scanned"], 3)

    def test_unknown_metric_rejected(self):
        usage = UsageService()
        with self.assertRaises(ValueError):
            usage.record("t", "bogus")


class TestLicense(unittest.TestCase):
    def test_assignment_and_seat_cap(self):
        svc = LicenseService()
        lic = svc.build(tenant_id="t", subscription_id="s", seats=2)
        svc.assign_seats(lic, ["u1", "u2"])
        with self.assertRaises(ValueError):
            svc.assign_seats(lic, ["u3"])
        svc.release_seat(lic, "u1")
        svc.assign_seats(lic, ["u3"])
        self.assertEqual(svc.available_seats(lic), 0)

    def test_key_verify_and_revoke(self):
        svc = LicenseService()
        lic = svc.build(tenant_id="t", subscription_id="s", seats=1)
        key = lic["key"]
        self.assertTrue(svc.verify_key(lic, key))
        self.assertFalse(svc.verify_key(lic, "wrong"))
        svc.revoke(lic)
        with self.assertRaises(ValueError):
            svc.activate(lic)


class TestBilling(unittest.TestCase):
    def test_invoice_totals_and_coupon(self):
        svc = BillingService()
        now = datetime.now(timezone.utc)
        inv = svc.build_invoice(
            tenant_id="t", subscription_id="s", plan="professional",
            period_start=now, period_end=now + timedelta(days=30),
            overage={"ai_requests": 100}, coupon_percent=10,
        )
        # base 4900 + 100*3 = 5200; 10% off -> total 4680
        self.assertEqual(inv["subtotal_cents"], 5200)
        self.assertEqual(inv["total_cents"], 4680)
        svc.mark_paid(inv, reference="txn_x")
        self.assertEqual(inv["status"], "paid")
        self.assertEqual(BillingService.total_billed([inv]), 4680)


class TestRetention(unittest.TestCase):
    def test_valid_windows(self):
        for d in (30, 90, 180, 365, -1):
            self.assertEqual(normalize_retention(d), d)
        with self.assertRaises(ValueError):
            normalize_retention(42)

    def test_cutoff_forever(self):
        self.assertIsNone(cutoff(-1))
        self.assertIsNotNone(cutoff(30))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
