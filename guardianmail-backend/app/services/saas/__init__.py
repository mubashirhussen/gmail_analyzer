"""Phase 20 — Enterprise SaaS platform (multi-tenancy, org, billing, quotas).

Additive service package. Domain code from prior modules is not modified;
this package is consumed via explicit imports from the SaaS API router and
Celery workers only.
"""
from app.services.saas.tenant_service import TenantService
from app.services.saas.organization_service import OrganizationService
from app.services.saas.workspace_service import WorkspaceService
from app.services.saas.subscription_service import SubscriptionService
from app.services.saas.billing_service import BillingService
from app.services.saas.usage_service import UsageService
from app.services.saas.quota_service import QuotaService
from app.services.saas.license_service import LicenseService
from app.services.saas.rbac_service import RBACService, PERMISSIONS

__all__ = [
    "TenantService", "OrganizationService", "WorkspaceService",
    "SubscriptionService", "BillingService", "UsageService",
    "QuotaService", "LicenseService", "RBACService", "PERMISSIONS",
]
