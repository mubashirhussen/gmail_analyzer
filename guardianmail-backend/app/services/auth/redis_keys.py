"""Redis keyspace conventions for auth-related state.

Centralised so every service uses the same key format and TTLs. A key
never leaks between subsystems by accident.
"""
from __future__ import annotations

# ---- namespaces ----------------------------------------------------------
SESSION_CACHE = "sess:{sid}"                        # session json blob
REFRESH_STATE = "rt:{jti}"                          # current/rotated/revoked
BLACKLIST     = "bl:{jti}"                          # access token JTI blacklist
OAUTH_STATE   = "oauth:state:{state}"               # csrf nonce + return url
LOCKOUT       = "lockout:{email}"                   # brute force counter
RATE_LIMIT    = "rl:{scope}:{key}:{window}"         # generic buckets
PASSCODE_FAIL = "pcfail:{user_id}"                  # per-user passcode fails

# ---- TTLs (seconds) ------------------------------------------------------
SESSION_TTL_S   = 60 * 60 * 24            # 24h idle cache
BLACKLIST_TTL_S = 60 * 60                 # short-lived: outlives an access token
OAUTH_STATE_TTL_S = 60 * 10               # 10 min consent window
LOCKOUT_TTL_S = 60 * 30                   # 30 min lockout window
LOCKOUT_THRESHOLD = 10
