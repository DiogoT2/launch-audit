# Security checklist

Each item: **what to check → how to find it → how to fix it.** IDs are stable; cite them in the report.

Contents:
1. Secrets & configuration (SEC-1xx)
2. Authentication & sessions (SEC-2xx)
3. Authorization & data access (SEC-3xx)
4. Input, output & injection (SEC-4xx)
5. Transport & browser (SEC-5xx)
6. API hardening & abuse (SEC-6xx)
7. Data protection & recovery (SEC-7xx)
8. Supply chain (SEC-8xx)
9. AI / LLM features (SEC-9xx)
10. Operations & process (SEC-10xx)

---

## 1. Secrets & configuration

### SEC-101 · No secrets in client code or bundles
- **Check:** API keys, service-role keys, private tokens never reach the browser or the mobile binary.
- **Find:** `scan.py` secret patterns; env vars with public prefixes (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `PUBLIC_`) whose names contain SECRET, SERVICE_ROLE, PRIVATE, PASSWORD or TOKEN. On a live site, search the built JS (`/_next/static`, `/assets`) for `sk_live`, `sk-`, `service_role`, `AKIA`.
- **Fix:** move the call server-side (API route, server action, edge function) and keep the key in server-only env vars. Only publishable/anon keys belong in the client, and only when access is enforced elsewhere (RLS, rules, server checks).

### SEC-102 · Environment variables handled correctly
- **Check:** `.env*` files are git-ignored and not tracked; a `.env.example` with placeholder values exists; production values live in the host's secret store; no defaults like `SECRET_KEY = "changeme"` in code.
- **Find:** `git ls-files | grep -i '\.env'`; grep for hard-coded fallbacks `process.env.X || "..."`, `os.getenv("X", "...")`.
- **Fix:** add `.env*` (except `.env.example`) to `.gitignore`, `git rm --cached` tracked env files, rotate anything that was committed, fail fast at boot if a required secret is missing.

### SEC-103 · Git history is clean
- **Check:** no secret was ever committed, even if later deleted.
- **Find:** `scan.py --history`; or `gitleaks detect`, `trufflehog git file://.`.
- **Fix:** rotate first, then `git filter-repo --replace-text` (or BFG), force-push, ask collaborators to re-clone. Enable GitHub secret scanning and push protection.

### SEC-104 · Debug mode off in production
- **Check:** `DEBUG=False` (Django), `APP_DEBUG=false` (Laravel), no Flask `debug=True`, no Werkzeug debugger, no verbose stack traces or `console.log` of tokens in production, production source maps not public unless intended.
- **Find:** grep `DEBUG\s*=\s*True`, `debug=True`, `APP_DEBUG=true`, `productionBrowserSourceMaps: true`, `sourcemap: true` in prod build config.
- **Fix:** drive debug flags from env, default to off; return generic error messages to users and log details server-side.

### SEC-105 · No exposed files or internal dashboards
- **Check:** `/.env`, `/.git/`, backups (`.zip`, `.sql`, `.bak`), `phpinfo`, `.DS_Store`, admin panels (DB admin, Supabase Studio, queues, Grafana, Swagger UI) are not reachable publicly, or are behind auth + network restrictions.
- **Find:** `check_live.py` probes common paths; review hosting config and `public/`/`static/` folders for stray files.
- **Fix:** deploy only the build output; block dotfiles at the server/CDN; put internal tools behind SSO/VPN/IP allow-list; never rely on an "unguessable" URL.

---

## 2. Authentication & sessions

### SEC-201 · Real authentication, enforced on the server
- **Check:** use a proven provider/library (Supabase Auth, Firebase Auth, Auth.js, Clerk, Lucia-style session libs, Django/Rails/Laravel built-ins). Every protected API route, server action and function checks the session **on the server**. Hiding a button or checking in client JS / Next.js middleware alone is not auth.
- **Find:** list all handlers; look for ones that read `userId` from the request body/query instead of the verified session/JWT.
- **Fix:** a single `requireUser()` helper called at the top of every protected handler; derive user ID from the verified token only.

### SEC-202 · Passwords hashed properly
- **Check:** Argon2id (preferred), scrypt or bcrypt (cost ≥ 10). Never MD5/SHA-1/SHA-256 alone, never reversible encryption, never plaintext. Better still: let the auth provider handle passwords.
- **Find:** grep `md5(`, `sha1(`, `sha256(` near "password"; custom `users.password` columns.
- **Fix:** switch to argon2id/bcrypt; rehash on next successful login.

### SEC-203 · Login, sign-up and reset are rate limited
- **Check:** per-IP and per-account limits on login, sign-up, password reset, OTP/magic-link and verification endpoints; lockout or growing delays after repeated failures; reset tokens single-use and short-lived; same response whether or not the account exists.
- **Fix:** provider settings (Supabase/Firebase have them) or middleware such as `express-rate-limit`, `django-ratelimit`, Rails `rack-attack`, Upstash/Redis rate limiter on serverless.

### SEC-204 · Bot protection on public forms
- **Check:** sign-up, contact, comment and checkout forms resist automated abuse.
- **Fix:** invisible challenge (Cloudflare Turnstile, hCaptcha, reCAPTCHA) verified **server-side**, plus a honeypot field and rate limits. Firebase: App Check.

### SEC-205 · Session cookies are secure
- **Check:** session/auth cookies have `HttpOnly`, `Secure`, `SameSite=Lax` (or `Strict`), sensible expiry, `__Host-` prefix where possible; tokens not stored in `localStorage` when an HttpOnly cookie is an option; session rotated on login and invalidated on logout/password change.
- **Find:** `check_live.py` reports Set-Cookie flags; grep `httpOnly: false`, `secure: false`, `localStorage.setItem(.*token`.
- **Fix:** set flags in the session library config; use CSRF tokens or `SameSite` + origin checks for cookie-authenticated state-changing requests.

### SEC-206 · OAuth / social login configured safely
- **Check:** exact redirect-URI allow-list (no wildcards, no open redirects), `state` parameter validated, PKCE for public clients, ID token signature/audience/issuer verified, email from provider treated as verified only if the provider says so, client secret only on the server, minimum scopes.
- **Fix:** use the provider SDK or a maintained library; remove test redirect URIs (localhost, preview URLs) from production apps.

---

## 3. Authorization & data access

### SEC-301 · Users can only reach their own records (no IDOR)
- **Check:** every read/update/delete by ID also filters by owner or tenant: `WHERE id = $1 AND user_id = $session_user`. Changing an ID in a URL or request must not reveal someone else's data.
- **Find:** handlers that fetch by `params.id` without an owner condition; storage buckets with public read for private files; signed URLs with very long expiry.
- **Fix:** scope queries by owner; enforce in the DB too (RLS) so one forgotten check isn't fatal.

### SEC-302 · Admin routes protected
- **Check:** `/admin`, internal APIs and staff-only actions check a server-side role/claim, not a client flag or a hidden route.
- **Fix:** role stored server-side (DB table or custom claim set by the server only); deny by default; log admin actions (SEC-1001).

### SEC-303 · Row Level Security enabled (Supabase/Postgres)
- **Check:** RLS enabled on **every** table in exposed schemas, with explicit policies for select/insert/update/delete. Policies use `auth.uid()`, not client-sent IDs. No `using (true)` on private data. Views and `security definer` functions don't bypass it unintentionally. Storage buckets have policies too.
- **Find:** `scan.py` compares `create table` vs `enable row level security` in migrations; Supabase dashboard security advisor; `select tablename from pg_tables where schemaname='public' and rowsecurity = false;`.
- **Fix:** `alter table x enable row level security;` + policies per operation. Test with the anon key as a logged-out user and as a second user.

### SEC-304 · Field tampering / mass assignment blocked
- **Check:** clients can't set fields they shouldn't: `role`, `is_admin`, `plan`, `credits`, `price`, `owner_id`, `tenant_id`, `email_verified`, `created_at`.
- **Find:** `Model.create(req.body)`, `update(**request.json)`, `Object.assign(user, body)`, Rails `permit!`, Laravel `$guarded = []`, Supabase `update()` with a spread body.
- **Fix:** explicit allow-list per endpoint (zod/valibot/pydantic schemas, strong params, `$fillable`); in Postgres, column-level privileges or a `before update` trigger that rejects protected columns; compute prices server-side.

### SEC-305 · Tenant isolation (multi-tenant / team apps)
- **Check:** every query includes the tenant ID from the session; caches, file paths, search indexes, background jobs and analytics are tenant-scoped; IDs are not guessable across tenants.
- **Fix:** tenant ID in RLS policies or a mandatory repository/ORM scope; tests that try cross-tenant reads.

### SEC-306 · Database permissions are least-privilege
- **Check:** the app connects with a role that can only do what it needs (no superuser, no `DROP`/`ALTER` at runtime); service-role / admin SDK used only in trusted server code; no publicly reachable DB port with password auth.
- **Fix:** separate migration and runtime roles; network restrictions; rotate credentials.

### SEC-307 · Public DB key only
- **Check:** client apps use only the public/anon/publishable key, and it's safe only because RLS/rules restrict it.
- **Fix:** see SEC-101 and SEC-303.

---

## 4. Input, output & injection

### SEC-401 · Validate all input on the server
- **Check:** types, lengths, formats, ranges and enums validated server-side for body, query, params, headers and webhook payloads. Client validation is UX only.
- **Fix:** a schema validator at every entry point (zod, valibot, yup, pydantic, marshmallow, Rails validations, Laravel FormRequest); reject unknown fields.

### SEC-402 · Parameterized queries (SQL/NoSQL injection)
- **Find:** SQL built with string concatenation, f-strings, template literals, `raw()`, `$queryRawUnsafe`, `sequelize.query` with interpolation; Mongo queries taking objects straight from `req.body` (operator injection like `{"$ne": null}`).
- **Fix:** bound parameters / query builder / ORM; cast NoSQL inputs to expected primitive types.

### SEC-403 · XSS: escape user content
- **Check:** user-supplied content rendered as text, not HTML. Rich text sanitized with an allow-list. Markdown renderers configured to drop raw HTML. URLs checked for `javascript:` scheme.
- **Find:** `dangerouslySetInnerHTML`, `innerHTML =`, `v-html`, `{@html`, `|safe`, `mark_safe`, `html_safe`, `raw(`, `document.write`.
- **Fix:** framework auto-escaping; DOMPurify (or equivalent server-side) when HTML is required; a strict Content-Security-Policy (SEC-502) as backup.

### SEC-404 · Sanitize forms
- **Check:** contact/sign-up/profile forms validate and normalize input, limit length, strip control characters, and protect any downstream sink: email headers (header injection), CSV exports (formula injection: prefix `= + - @` with `'`), logs (newline injection), HTML emails.

### SEC-405 · Command injection
- **Find:** `exec(`, `execSync(`, `spawn(..., {shell: true})`, `os.system`, `subprocess(..., shell=True)`, backticks, `Runtime.exec`, ImageMagick/ffmpeg calls with user-controlled filenames.
- **Fix:** avoid the shell — pass argument arrays; allow-list values; never put user input into a command string.

### SEC-406 · Insecure deserialization & code evaluation
- **Find:** `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal`, PHP `unserialize`, Java native serialization, `node-serialize`, `eval(`, `new Function(`, `vm.runIn*` on untrusted data.
- **Fix:** JSON with schema validation; `yaml.safe_load`; never evaluate user data.

### SEC-407 · File uploads restricted
- **Check:** size limits; allow-listed types checked by content (magic bytes), not only extension/MIME header; random server-generated filenames; stored outside the web root or in object storage; served with `Content-Disposition: attachment` or from a separate domain; SVG/HTML uploads not served inline from the main origin; images re-encoded to strip metadata (EXIF GPS); private buckets for private files; malware scanning where files are shared with other users.
- **Also:** path traversal on downloads (`../`) — resolve and verify the path stays inside the allowed directory.

### SEC-408 · Trim API responses
- **Check:** responses return only the fields the UI needs. No password hashes, tokens, internal flags, other users' emails, or full DB rows via `select *`. Error responses don't leak stack traces or SQL.
- **Fix:** explicit select lists / DTOs / serializers.

### SEC-409 · SSRF and open redirects
- **Check:** features that fetch a user-supplied URL (link previews, webhooks, image import) block internal addresses (169.254.169.254, localhost, private ranges) and re-check after redirects. Redirect parameters (`?next=`) only allow relative paths or an allow-list.

---

## 5. Transport & browser

### SEC-501 · HTTPS everywhere
- **Check:** HTTP redirects to HTTPS; HSTS header (`max-age` ≥ 15552000, `includeSubDomains` when all subdomains are HTTPS); no mixed content; valid certificate; APIs and webhooks HTTPS only.

### SEC-502 · Security headers
- `Content-Security-Policy` — start with `default-src 'self'`, add only needed origins, avoid `'unsafe-inline'`/`'unsafe-eval'` where possible (nonces/hashes), include `frame-ancestors 'none'` (or allowed parents), `object-src 'none'`, `base-uri 'self'`.
- `Strict-Transport-Security` (SEC-501)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` (legacy backup for `frame-ancestors`)
- `Referrer-Policy: strict-origin-when-cross-origin` (or stricter)
- `Permissions-Policy` disabling camera, microphone, geolocation, etc. unless used
- Remove `X-Powered-By` and version-revealing `Server` headers.
- **Find:** `check_live.py`. **Fix:** `helmet` (Express), `next.config` `headers()`, host config (Vercel/Netlify `_headers`, Cloudflare rules), Django `SecurityMiddleware`, Rails defaults.

### SEC-503 · CORS configured narrowly
- **Check:** no `Access-Control-Allow-Origin: *` on authenticated APIs; never reflect arbitrary `Origin` together with `Access-Control-Allow-Credentials: true`; allow-list exact origins (no regex that matches `evil-example.com`); preview/localhost origins not allowed in production.
- **Find:** `check_live.py` sends a foreign Origin and reports reflection; grep `origin: '*'`, `origin: true`, `CORS_ALLOW_ALL_ORIGINS = True`.

### SEC-504 · CSRF
- **Check:** cookie-authenticated, state-changing requests are protected (framework CSRF tokens, `SameSite` cookies plus Origin/Referer check). Not needed for pure bearer-token APIs.

---

## 6. API hardening & abuse

### SEC-601 · Every API endpoint is secured
- **Check:** an inventory of all endpoints (including serverless functions, server actions, GraphQL resolvers, webhooks, cron routes) with: auth requirement, authorization rule, input schema, rate limit. Unauthenticated endpoints are deliberate.
- **Webhooks:** verify signatures (Stripe `constructEvent`, GitHub HMAC, etc.) and reject replays; process idempotently.
- **Cron/internal routes:** require a secret header or platform-verified invocation.
- **GraphQL:** disable introspection in production if not needed, depth/complexity limits, per-field auth.

### SEC-602 · Rate limiting
- **Check:** global and per-user/IP limits on APIs; tighter limits on expensive operations (search, exports, AI calls, emails/SMS sent on behalf of a user, file processing); request body size limits; pagination caps (`limit` ≤ 100).
- **Fix:** gateway/CDN rules (Cloudflare, Vercel firewall), middleware, Redis/Upstash counters; spending caps on paid APIs (SMS, AI) so abuse can't run up a bill.

---

## 7. Data protection & recovery

### SEC-701 · Sensitive data encrypted
- **Check:** encryption in transit (SEC-501) and at rest (managed DB/storage encryption on). Extra application-level encryption for highly sensitive fields (government IDs, health data, third-party OAuth tokens, API keys users give you) with keys in a KMS/secret store, not next to the data. Backups encrypted.
- **Also:** don't store what you don't need (LEG-301). Card data → never touch it; use the payment provider's hosted fields/checkout.

### SEC-702 · Backups and tested restore
- **Check:** automated backups (point-in-time recovery where available), stored separately from production, retention defined, and **a restore has actually been tested**. Includes file storage, not just the DB. Know your RPO/RTO.
- **Status:** usually `MANUAL` — ask the user when they last restored.

---

## 8. Supply chain

### SEC-801 · No known-vulnerable dependencies
- **Run:** `npm audit --omit=dev` / `pnpm audit` / `yarn npm audit`, `pip-audit`, `osv-scanner -r .`, `bundle audit`, `composer audit`, `cargo audit`, `govulncheck ./...`, `flutter pub outdated`.
- **Fix:** update; prioritize vulnerabilities reachable in production code; enable Dependabot/Renovate.

### SEC-802 · Dependencies up to date
- Framework and runtime on supported versions (Node LTS, Python with security support, current framework major); lockfile committed and used in CI (`npm ci`, `pip install --require-hashes` where practical).

### SEC-803 · Malicious or suspicious packages
- **Check:** typosquats (`reqeusts`, `expresss`), very new or unmaintained packages with few downloads, packages with `postinstall` scripts doing network calls, unexpected packages in the lockfile, dependencies pulled from Git URLs or tarballs.
- **Fix:** remove or replace; `npm config set ignore-scripts true` where workable; review new deps before adding; Socket/OSV/`npm audit signatures`.

### SEC-804 · Remove unused packages
- **Find:** `npx depcheck`, `npx knip`, `pip-autoremove`/`deptry`. Fewer packages = smaller attack surface.

---

## 9. AI / LLM features

### SEC-901 · Prompt injection
- **Check:** any untrusted text (user messages, web pages, emails, uploaded files, DB content written by users) that reaches a model is treated as data that may contain instructions. The model's output is never trusted to make security decisions.
- **Fix:** keep secrets and other users' data out of the prompt; separate instructions from untrusted content and label it; validate model output against a schema before acting; escape model output before rendering (it can contain XSS or markdown image links that exfiltrate data); require human confirmation for consequential actions (sending, paying, deleting).

### SEC-902 · AI access is permissioned
- **Check:** tools/functions the model can call run with **the end user's** permissions, not a service role; RAG retrieval is filtered by the user's access before content reaches the model; agents can't reach admin APIs, the filesystem or the network beyond an allow-list; AI provider keys are server-side only (SEC-101).
- **Abuse limits:** per-user rate limits and spend caps on AI calls (SEC-602); max input/output tokens.

---

## 10. Operations & process

### SEC-1001 · Audit logs
- **Check:** security-relevant events are logged with who/what/when/where: logins (success/failure), password/email/2FA changes, permission and role changes, admin actions, data exports, deletions, payment events. Logs don't contain passwords, tokens or full card/ID numbers. Logs are append-only for app users and retained for a defined period.

### SEC-1002 · Security monitoring & alerting
- **Check:** error tracking (Sentry or similar), uptime monitoring, alerts on spikes in 401/403/429/5xx, failed logins, unusual spend on paid APIs; someone actually receives the alerts. Provider security notifications (GitHub, Supabase, cloud) go to a monitored inbox.

### SEC-1003 · Code is reviewed
- **Check:** branch protection on `main`, pull requests reviewed before merge (by a person or, at minimum, an automated review plus CI), CI runs tests + dependency audit + secret scan, AI-generated code reviewed with the same bar. No direct production edits.

### SEC-1004 · Full security audit before launch
- This skill is the audit. For apps handling payments, health or sensitive data at scale, also recommend an independent penetration test after fixes.
