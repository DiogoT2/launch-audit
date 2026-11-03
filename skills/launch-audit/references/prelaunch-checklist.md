# Pre-launch gate — 20 checks

The minimum before real users and real data touch the app. Each line: the check, a fast way to verify it, and where the details live. Any ❌ on items 1–8 is a launch blocker.

| # | Check | Fast verification | Details |
|---|---|---|---|
| 1 | **Hide API keys** — no secret keys in the client bundle or mobile binary | `scan.py`; search built JS for `sk_live`, `sk-`, `service_role`, `AKIA` | SEC-101 |
| 2 | **Purge git secrets** — none in history; leaked ones rotated | `scan.py --history` or `gitleaks detect` | SEC-103 |
| 3 | **Public DB key only** in the client (anon/publishable) | grep client env vars and config | SEC-307, SEC-101 |
| 4 | **RLS enabled** (or Firebase rules locked) on every table/collection with user data | Supabase security advisor; `scan.py` RLS check; rules not `if true` | SEC-303 |
| 5 | **Server-side auth enforced** on every API route, server action and function | list handlers; each calls a verified-session helper | SEC-201, SEC-601 |
| 6 | **Record access locked** — users can't read/edit others' rows by changing an ID | log in as user B, request user A's IDs | SEC-301, SEC-305 |
| 7 | **Field tampering blocked** — can't set `role`, `price`, `owner_id`, `credits` | send extra fields in update requests | SEC-304 |
| 8 | **Parameterized queries** — no SQL built from strings | grep for interpolated SQL | SEC-402 |
| 9 | **Encrypt sensitive data** at rest and in transit | provider settings; field-level for IDs/tokens | SEC-701 |
| 10 | **Secure session cookies** — HttpOnly, Secure, SameSite | `check_live.py` cookie report | SEC-205 |
| 11 | **Hash passwords** with Argon2id/bcrypt (or provider-managed) | grep hashing code | SEC-202 |
| 12 | **Rate limit login**, sign-up, password reset, OTP | hit login 20× quickly — expect 429/lockout | SEC-203 |
| 13 | **Bot protection** on sign-up/contact/checkout, verified server-side | inspect form + handler | SEC-204 |
| 14 | **Validate all input** server-side with a schema | each handler has validation | SEC-401, SEC-404 |
| 15 | **Escape user content** — no raw HTML rendering of input | grep `dangerouslySetInnerHTML`, `v-html`, `innerHTML` | SEC-403 |
| 16 | **Restrict file uploads** — size, type by content, private storage | inspect upload handler and bucket policy | SEC-407 |
| 17 | **Trim API responses** — no hashes, tokens, other users' data | inspect JSON responses in DevTools | SEC-408 |
| 18 | **Security headers** — CSP, HSTS, nosniff, frame-ancestors, Referrer-Policy | `check_live.py` | SEC-502 |
| 19 | **Force HTTPS** — redirect + HSTS, no mixed content | `check_live.py` | SEC-501 |
| 20 | **Scan dependencies** — no known critical/high vulns | `npm audit` / `pip-audit` / `osv-scanner` | SEC-801, SEC-803 |

## Legal minimum to launch (if any personal data is collected or anything is sold)

| # | Check | Details |
|---|---|---|
| L1 | Privacy policy that matches reality, linked in footer/app/store | LEG-101 |
| L2 | Terms of service, accepted at sign-up/checkout | LEG-102 |
| L3 | Refund policy (if selling) | LEG-103 |
| L4 | Cookie banner with real "Reject all"; no tracking before consent (EU/UK) | LEG-201, LEG-104 |
| L5 | Account/data deletion path (mandatory for app-store apps with accounts) | LEG-302 |
| L6 | Business details and contact visible | LEG-105 |
| L7 | Unsubscribe in every marketing email | LEG-601 |

## Also do in launch week

Backups on and one restore tested (SEC-702) · error tracking + alerts (SEC-1002) · debug mode off (SEC-104) · admin routes behind server-side role checks (SEC-302) · CORS allow-list (SEC-503).
