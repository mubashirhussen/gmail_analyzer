
# MailGuard — Phase 2 Plan

You picked four heavy slices: **M1 Device Trust + M11 Timeline**, **M3+M4+M6 deeper threat analysis**, **M7 outbound Privacy Guardian**, plus enabling Lovable Cloud + Google OAuth and per-user Gmail. That's still a lot, so I'll ship it in three phases. You approve this plan and I'll start Phase 1 immediately; Phases 2 and 3 are separate turns so each gets proper attention.

## Migration note
The current app uses **local passcode + AES-GCM encrypted localStorage**. Real Device Trust and login history need real accounts, so we move auth to **Lovable Cloud (Supabase)**. The encrypted-history feature stays available as an opt-in "Local vault" toggle in Data & Privacy, but the primary account becomes a Cloud account. Existing local accounts get a one-click "Migrate to Cloud" prompt.

## Phase 1 — Cloud, Auth, Device Trust, Timeline (this turn)
1. Enable Lovable Cloud.
2. Replace `AuthGate` with email/password + Google OAuth (via `lovable.auth.signInWithOAuth`).
3. Move app under `_authenticated/` route; keep `/auth` public.
4. DB tables (with RLS + grants):
   - `profiles` (id, username, email, avatar_url)
   - `devices` (id, user_id, fingerprint_hash, label, os, browser, ip, city, country, last_seen, trusted, current)
   - `sessions` (id, user_id, device_id, refresh_token_hash, expires_at, revoked_at)
   - `security_events` (id, user_id, kind, severity, summary, meta, created_at) — powers M11 timeline
5. Client-side device fingerprint (FingerprintJS-style: UA, screen, tz, canvas hash) → stable hash stored per session.
6. Server fns: `registerDevice`, `listDevices`, `revokeDevice`, `revokeAllOtherDevices`, `reportSuspicious`, `listSecurityEvents`.
7. New pages:
   - **Security → Devices**: trusted devices list, "current" badge, Logout / Remove / Report buttons, "Sign out everywhere else".
   - **Security → Timeline**: chronological feed of events (logins, phishing blocks, device removed, etc.).
8. Every analysis run writes a `security_events` row, so M11 is populated automatically.

## Phase 2 — Deeper threat analysis (M3 + M4 + M6) (next turn)
- Extend `analyzeEmail` server fn to return:
  - `attackCategory` enum: credential_theft, financial_fraud, fake_recruitment, BEC, malware_delivery, qr_phishing, invoice_scam, ceo_fraud, gift_card, crypto_scam, other.
  - `confidence` 0–100.
  - `explanations[]`: structured reasons (sender_age, spf_fail, urgency, shortened_url, credential_request, …) — Gemini-generated but mapped to a fixed enum so the UI can render badges.
  - `links[]` enriched: `domainAgeDays`, `isShortener`, `isIPLiteral`, `homographRisk`, `entropy`, `typosquatOf` (cosine vs top 500 brands list), `tldRisk`. Live lookups (whois/VirusTotal/Safe Browsing) are deferred unless you add API keys — without them we deliver heuristic versions of all of these client/server-side, which is what 95% of student/demo projects ship.
- UI: replace single verdict card with **Threat Confidence dial + Attack Category chip + Explainability list + per-link drill-down table** with severity dots.

## Phase 3 — Outbound Privacy Guardian (M7) (turn after)
- New `/compose` page: "Draft email" textarea.
- Client-side regex + entropy scanner for: Aadhaar (12-digit Verhoeff), PAN (`[A-Z]{5}[0-9]{4}[A-Z]`), passport, Visa/MC/Amex (Luhn), IFSC, IBAN, AWS keys (`AKIA…`), GitHub tokens (`ghp_…`), generic `api[_-]?key` patterns, high-entropy strings, `BEGIN RSA/OPENSSH PRIVATE KEY`.
- Blocking warning modal with one-click "Redact all" (replace with `••••`) before send.
- Optional: also run on every analyzed inbound mail to flag if **you** leaked something in a reply chain.

## Explicitly NOT in scope yet
- Live Gmail OAuth + inbox polling (M2). Needs Google Cloud Console setup by you. I'll wire the UI hooks in Phase 1 so it slots in later, but real polling is its own turn.
- Modules 5, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20. Each is a real feature, not a checkbox. We can sequence them after Phases 1–3 land.
- Browser extension (M17) — separate Chrome extension project, not part of this app.
- VirusTotal / Safe Browsing / HIBP real API calls — need your API keys; without them I'll mark those panels as "Heuristic mode (add API key for live data)".

## Technical notes
- Auth: Supabase email/password + Google via `lovable.auth.signInWithOAuth("google", { redirect_uri: window.location.origin + "/auth" })`. `_authenticated/route.tsx` is the integration-managed gate.
- Device fingerprint stays best-effort (no fingerprintjs-pro). Stored hashed.
- "Sign out everywhere else" = mark all other `sessions` rows `revoked_at = now()`; current bearer is unaffected. On next request from a revoked device, a `requireSupabaseAuth` server fn checks the session row and forces `supabase.auth.signOut()` from the client.
- Timeline events written from server fns via `supabaseAdmin` (audit log integrity).

Reply **approve** to start Phase 1, or tell me what to cut/add.
