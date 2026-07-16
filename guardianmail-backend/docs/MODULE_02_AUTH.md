# GuardianMail AI — Module 2: Authentication & Security

Module 2 implements the enterprise auth stack on the Module 1 foundation.
Nothing in `core/`, `database/`, `middlewares/`, or the router-mount pattern
was changed — only extended.

## 1. Folder Structure (additions to Module 1)

```
guardianmail-backend/app/
├── api/
│   ├── dependencies.py                # Principal + get_principal DI
│   └── v1/
│       ├── auth.py                    # Google OAuth + JWT lifecycle + profile
│       ├── sessions.py                # active session list + per-session revoke
│       ├── devices.py                 # list/rename/trust/remove
│       └── passcode.py                # 6-digit application lock
├── models/
│   ├── user.py                        # + email_verified, status, lockout, passcode
│   ├── session.py                     # + status, revoke_reason, refresh_jti head
│   ├── device.py                      # + trusted/risk/location/device_type
│   ├── refresh_token.py               # NEW — rotation chain w/ reuse detection
│   ├── login_history.py               # NEW — every attempt (success + failure)
│   ├── security_event.py              # NEW — actionable, notifiable events
│   └── audit.py                       # request-scoped mutating actions
├── repositories/
│   ├── users.py
│   ├── sessions.py
│   ├── devices.py
│   ├── refresh_tokens.py
│   └── audit_logs.py                  # AuditLogs + LoginHistory + SecurityEvents
├── schemas/
│   ├── auth.py                        # OAuth DTOs, TokenPair, UserProfile
│   ├── session.py
│   ├── device.py
│   └── passcode.py
├── services/
│   └── auth/
│       ├── redis_keys.py              # ONE keyspace + TTL registry
│       ├── jwt_service.py             # issue/decode/blacklist
│       ├── oauth_service.py           # Google OAuth 2.0 (state + PKCE-ready)
│       ├── session_service.py         # rotation, reuse detection, revoke
│       ├── device_service.py          # register/trust/remove + new-device alert
│       ├── passcode_service.py        # 6-digit lock + retry cap
│       ├── security_service.py       # brute-force / lockout
│       ├── audit_service.py          # audit + login_history + security_events
│       └── auth_service.py           # orchestrator (OAuth→user→device→session)
├── utils/
│   ├── user_agent.py                  # browser/OS/device-type parser
│   ├── geoip.py                       # coarse "City, CC" from IP (fail-open)
│   └── fingerprint.py                 # client_fp + IP prefix + UA family → sha256
└── tests/
    ├── test_jwt.py
    └── test_device_fingerprint.py
```

## 2. Authentication Flow

```
Browser                       API                           Google
   │  POST /auth/google/login  │                              │
   │──────────────────────────►│  build_authorize_url()       │
   │                            │  Redis: oauth:state:{s} = { }│
   │◄── authorize_url ─────────│                              │
   │───── user → Google ──────────────────────────────────────►│
   │◄──── ?code=&state= ──────────────────────────────────────│
   │  POST /auth/google/callback (code, state, X-Device-Fingerprint)
   │──────────────────────────►│  consume_state → exchange_code → userinfo
   │                            │  users.upsert_from_google
   │                            │  device.register_or_touch → new-device event
   │                            │  session.create + jti + refresh (chain head)
   │                            │  audit + login_history + security_event
   │◄── {user, session_id, device_id, access, refresh} ──────│
```

## 3. Google OAuth Flow

- Server-minted `state` (32-byte URL-safe), stored in Redis with 10 min TTL.
- Scopes: `openid email profile https://www.googleapis.com/auth/gmail.readonly`.
- `access_type=offline`, `prompt=select_account`.
- Callback validates state (consume-once), exchanges code, fetches userinfo,
  rejects unverified emails.

## 4. JWT Flow

- **Access token** — HS256, `sub`/`sid`/`did`/`email`/`jti`, TTL 15 min (config).
- **Refresh token** — HS256, `sub`/`sid`/`did`/`jti`, TTL 30 days (60 w/ remember-me).
- **Storage** — refresh token hashed (`sha256`) into `refresh_tokens.token_hash`.
  Raw token is only in the client's hands.
- **Verification** — `jwt_service.verify_access()` decodes + checks Redis blacklist.
- **Revocation** — access blacklisted by `jti` for TTL_S (1 h). Refresh chain
  marked `revoked` on logout, or `reused` on reuse attack.

## 5. Session Flow

```
create()           → new Session + head refresh_jti + access token
refresh()          → validate hash, rotate jti, invalidate old, issue new pair
                     reused/rotated old jti → REVOKE ENTIRE CHAIN + session
touch()            → last_active_at bump on every authenticated request
revoke()           → status=revoked + blacklist access + revoke refresh chain
revoke_all(except) → sign out other sessions
expire_stale()     → periodic sweep: last_active < now-idle_seconds
```

Concurrent-session limit (default 10, per-user configurable) — oldest active
session revoked when a new session would exceed it.

## 6. Device Management Flow

- Fingerprint = `sha256(client_fp | ip_prefix(/16 v4, /64 v6) | ua_family)`.
- Upsert per `(user_id, fingerprint)`.
- First insert → `security_event("device_new", severity="medium")`.
- Trust flag flips risk gating (higher-friction MFA re-prompts in later modules).
- Remove device → soft-delete + `revoke_device_sessions()`.

## 7. Passcode Flow

- 6 digits, hashed with bcrypt via `passlib`.
- Redis counter `pcfail:{user_id}`; 5 failures → hard lock 15 min
  (`passcode_locked_until`) + `security_event("passcode_locked")`.
- `POST /auth/passcode/lock` blacklists the current access jti so the
  client is forced into the lock screen without waiting for TTL.

## 8. Database Collections

| Collection        | Purpose                                    | Key Indexes                              |
|-------------------|--------------------------------------------|------------------------------------------|
| `users`           | Identity + status + passcode               | `email` (unique), `google_sub` (sparse)  |
| `sessions`        | Active/revoked sessions                    | `(user_id,status)`, TTL on `expires_at`  |
| `devices`         | Per-user devices                           | `(user_id,fingerprint)` unique           |
| `refresh_tokens`  | Rotation chain + reuse detection           | `jti` unique, TTL on `expires_at`        |
| `login_history`   | Every attempt (success/failure)            | `(user_id,at desc)`, `(email,at desc)`   |
| `security_events` | Actionable notifiable events               | `(user_id,at desc)`, `(kind,severity)`   |
| `audit_logs`      | Mutating-action trail                      | `(user_id,at)`, `(action,at)`            |

## 9. API Endpoints

```
POST   /api/v1/auth/google/login          → { authorize_url, state }
POST   /api/v1/auth/google/callback       → LoginResponse
POST   /api/v1/auth/refresh               → TokenPair (rotated)
POST   /api/v1/auth/logout                → 200
POST   /api/v1/auth/logout-all            → { revoked: n }
GET    /api/v1/auth/profile   (alias /me) → UserProfile

GET    /api/v1/auth/sessions              → SessionOut[]
DELETE /api/v1/auth/sessions/{id}         → 200

GET    /api/v1/auth/devices               → DeviceOut[]
PATCH  /api/v1/auth/devices/{id}          → rename
PATCH  /api/v1/auth/devices/{id}/trust    → set trusted flag
DELETE /api/v1/auth/devices/{id}          → soft-remove + revoke its sessions

GET    /api/v1/auth/passcode              → PasscodeStatus
POST   /api/v1/auth/passcode              → set
PUT    /api/v1/auth/passcode              → change
POST   /api/v1/auth/passcode/verify       → 200
POST   /api/v1/auth/passcode/lock         → immediate lock (blacklist)
```

Every protected endpoint uses `Depends(get_principal)` → `Principal(user,
user_id, session_id, device_id, access_jti, email)`.

## 10. Service Layer

Single-responsibility services; each exposes a module-level singleton.

| Service            | Owns                                                            |
|--------------------|-----------------------------------------------------------------|
| `JWTService`       | Sign / decode / blacklist. No I/O other than Redis blacklist.   |
| `OAuthService`     | Google OAuth 2.0 authorize URL, state, code exchange, userinfo. |
| `SessionService`   | Session lifecycle + refresh rotation + reuse detection.         |
| `DeviceService`    | Fingerprint + upsert + trust/remove + new-device event.         |
| `PasscodeService`  | Set/change/verify/lock, retry throttling.                       |
| `SecurityService`  | Brute-force / lockout on `email` bucket.                        |
| `AuditService`     | Audit log + login history + security event writes.              |
| `AuthService`      | Orchestrator: consumes the six above; API routes call only it.  |

## 11. Repository Layer

All repos extend `BaseRepository[T]` from Module 1. Domain queries live on
the subclass. Nothing above the service layer touches Mongo.

## 12. Redis Usage

| Key                                   | Purpose                          | TTL     |
|---------------------------------------|----------------------------------|---------|
| `oauth:state:{state}`                 | CSRF nonce + return context      | 10 min  |
| `bl:{access_jti}`                     | Access-token blacklist           | 1 h     |
| `lockout:{email}`                     | Brute-force counter              | 30 min  |
| `pcfail:{user_id}`                    | Passcode retry counter           | 15 min  |
| `rl:{scope}:{key}:{window}`           | Generic rate-limit bucket        | window  |
| `sess:{sid}` (reserved)               | Hot session cache (later)        | 24 h    |

## 13. Security Measures

- HS256 JWT with `sub/sid/did/jti/iat/exp` and per-type check.
- Refresh-token rotation + reuse detection (chain revoke on reuse).
- Access-token blacklist by JTI in Redis; hard lock via `/passcode/lock`.
- Bcrypt password/passcode hashing via passlib.
- AES-GCM (`app/core/encryption.py`) for at-rest secrets.
- Brute-force lockout: 10 fails / 30 min per email.
- Passcode retry cap: 5 fails / 15 min per user.
- CSRF-safe OAuth state (server-minted, consume-once, Redis).
- Timing-safe hash compare in JWT (constant-time via `passlib`/`jose`).
- Security headers + body-size limit + trusted hosts (Module 1).
- Rate limiting via `slowapi` at the app default (`RATE_LIMIT_DEFAULT`).

## 14. Logging Strategy

Every service uses structlog with the request-context bound in Module 1's
`RequestContextMiddleware`. Three write channels:

- **Audit** — `audit_logs` collection, one row per mutating action.
- **Login history** — `login_history` collection, one row per attempt.
- **Security event** — `security_events` collection, notifiable signals.

All three also emit a structlog line so tail-based tooling sees them live.

## 15. Testing Strategy

- `test_jwt.py` — issue/decode/type-mismatch/hash-stability.
- `test_device_fingerprint.py` — UA parsing + fingerprint stability across
  /16 IP drift, sensitivity across network change.
- Integration tests (recommended, added in Module 3 hardening): OAuth
  callback with mocked httpx `respx`, refresh-token rotation, reuse-attack
  chain revoke, session revoke propagation.

## 16. Sequence Diagrams

**Refresh rotation (happy path):**
```
Client            API                RefreshTokensRepo       SessionsRepo
  │ POST /refresh  │                        │                       │
  │───────────────►│ decode(refresh)        │                       │
  │                │ get_by_jti(old)        │                       │
  │                │                        │  → active             │
  │                │ hash match?            │                       │
  │                │ issue new_jti          │                       │
  │                │ create(new)            │                       │
  │                │ mark_rotated(old→new)  │                       │
  │                │ rotate_refresh(sid,new_jti)                    │
  │◄── {access, refresh, expires_in} ──────                         │
```

**Refresh reuse attack:**
```
POST /refresh with rotated jti
  → get_by_jti returns status=rotated
  → mark_reused(jti) + revoke_chain(session_id) + session.revoke("refresh_reuse")
  → security_event("token_reuse", severity="critical")
  → 401 refresh_reuse
```

**Unknown-device sign-in:**
```
callback → upsert (fingerprint miss) → insert device
        → security_event("device_new", severity="medium")
        → LoginResponse includes device_id (client can prompt trust flow)
```

## 17. Best Practices Applied

- Clean layering: route → service → repository → db. No route touches Mongo.
- One responsibility per service; orchestration only in `AuthService`.
- Immutable module singletons; no request-scoped globals.
- All secrets from typed `Settings` (Module 1 guardrails still apply).
- Fail-closed: unverified email rejected; unknown session → 401; hash
  mismatch → 401 tampered; reuse → chain revoke.
- Structured logs auto-bind `request_id`, `user_id`, `device_id`.
- Every mutation writes an audit row; every notifiable signal writes a
  security event.

## 18. Production Deployment Considerations

- **Rotate `SECRET_KEY` + `FERNET_KEY`** via KMS/Secret Manager; keep the
  previous key active for one refresh-TTL window to avoid mass-signout.
- **Refresh token TTL** — 30 days default, 60 days for remember-me. Tighten
  in high-security tenants; enforce concurrent-session limit accordingly.
- **Redis persistence** — RDB + AOF for auth Redis (blacklist + rotation
  state loss = forced signout, not a security break, but disruptive).
- **Mongo TTL indexes** — `sessions.expires_at` and `refresh_tokens.expires_at`
  keep collections bounded automatically.
- **Cookie mode (optional)** — swap `Authorization: Bearer` for `HttpOnly;
  Secure; SameSite=Lax` cookie by adding a cookie adapter to `dependencies.py`;
  contract stays identical.
- **MFA / WebAuthn** — plug additional providers into `AuthService` before
  `session.create()`; the interface is stable.
- **Session sweep** — schedule `session.expire_stale(idle_seconds=1800)` on
  Celery beat (queue `default`) once Module 3 lands.

Module 2 is production-ready. Awaiting approval to proceed to
**Module 3 — Gmail Sync & Metadata Pipeline**.
