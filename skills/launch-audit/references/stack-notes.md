# Stack-specific notes

Read only the sections for the stack in use. Version-specific advisories change; confirm against the framework's current security advisories.

## Supabase
- The `anon`/publishable key is public by design — **RLS is the only thing protecting your data**. The `service_role`/secret key bypasses RLS: server-only, never in the client, never in a mobile app, never in `NEXT_PUBLIC_*`.
- Enable RLS on every table in `public` (and any schema exposed via the API). Tables created in the SQL editor or migrations don't always get RLS automatically. Run the dashboard's Security Advisor.
- Policies: separate `select`/`insert`/`update`/`delete`; use `auth.uid()`; `update` policies need both `using` (which rows) and `with check` (what the row may become) or users can reassign ownership.
- Wrap `auth.uid()` as `(select auth.uid())` in policies for performance.
- Protect columns users must not change (`role`, `plan`, `credits`) with a trigger or by revoking column update privileges; don't keep roles in `user_metadata` (users can edit it) — use `app_metadata` or a server-maintained table.
- `security definer` functions run as owner and bypass RLS: set `search_path`, check `auth.uid()` inside, and revoke `execute` from `anon`/`authenticated` if not meant to be public. Views bypass RLS unless created with `security_invoker = true`.
- Storage: buckets private unless truly public; storage policies on `storage.objects` keyed by owner path; short-lived signed URLs.
- Edge Functions: verify the JWT (default) unless it's a webhook — then verify the webhook signature.
- Auth settings: email confirmation on, leaked-password protection, rate limits, redirect URL allow-list without wildcards for production, OTP expiry short.

## Firebase
- Firestore/Realtime DB/Storage rules: never `allow read, write: if true;` or test-mode rules with an expiry date. Rules check `request.auth.uid` against the document's owner field, and validate `request.resource.data` (types, allowed keys via `keys().hasOnly([...])`) to block field tampering.
- Firebase web config is public; security comes from rules + App Check. Turn on **App Check** for Firestore, Storage and Functions.
- Admin SDK / service account JSON: server only. Cloud Functions callable endpoints must check `context.auth`.
- Custom claims for roles, set only from trusted server code.

## Next.js
- Server Actions and Route Handlers are public HTTP endpoints — authenticate and authorize inside **each** one; don't rely on the page being hidden.
- Middleware is not a security boundary on its own: CVE-2025-29927 allowed bypassing middleware with an `x-middleware-subrequest` header (fixed in 12.3.5, 13.5.9, 14.2.25, 15.2.3). Stay on a patched version and check auth again in the data layer.
- Only `NEXT_PUBLIC_*` vars reach the browser — make sure no secret has that prefix. Mark server-only modules with `import 'server-only'`.
- Don't pass whole DB objects from Server Components to Client Components — props are serialized into the HTML.
- Security headers via `headers()` in `next.config.js` or middleware; CSP with nonces for inline scripts.
- `productionBrowserSourceMaps` off unless intended. Image optimizer `remotePatterns` restricted (no `**`).

## Vite / SPA (React, Vue, Svelte)
- Every `VITE_*` var is bundled into public JS. A pure SPA has no server: any secret it uses is public. Put a backend or serverless function in front of paid/secret APIs.
- Client-side route guards are UX only; the API must enforce access.

## Express / Node
- `helmet()`, `express-rate-limit`, `cors({ origin: [allow-list], credentials: true })`, `express.json({ limit: '100kb' })`, `app.disable('x-powered-by')`, `app.set('trust proxy', 1)` behind a proxy so rate limits see real IPs.
- Validate with zod/valibot at each route. Use parameterized queries (`pg` `$1`, Prisma/Drizzle query builders; avoid `$queryRawUnsafe`).
- Errors: central error handler that hides stack traces in production.

## Django
- `python manage.py check --deploy`. `DEBUG=False`, `ALLOWED_HOSTS` set, `SECRET_KEY` from env, `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS`.
- Avoid `.raw()`/`.extra()` with string formatting; `|safe`/`mark_safe` only on trusted content. DRF: explicit `fields` in serializers (never `__all__` for writes), permission classes on every view, object-level permissions.

## Rails
- Strong parameters (`permit(:a, :b)`, never `permit!`), `brakeman`, `bundle audit`, `config.force_ssl = true`, `rack-attack` for rate limiting, `html_safe`/`raw` only on trusted content, Pundit/CanCanCan for authorization.

## Laravel
- `APP_DEBUG=false`, `APP_ENV=production`, `$fillable` (not `$guarded = []`), policies/gates on every controller action, `{!! !!}` only for trusted HTML, `throttle` middleware on auth routes, `composer audit`.

## Mobile (Flutter, React Native, Swift, Kotlin)
- Everything in the binary is extractable: no secret keys, no admin endpoints, no "hidden" flags. Use a backend for privileged calls.
- Store tokens in Keychain/Keystore (`flutter_secure_storage`, `expo-secure-store`), not plain preferences/AsyncStorage.
- No sensitive data in logs or crash reports; disable debug logging in release builds.
- Deep links / universal links validated; WebViews don't load arbitrary URLs or expose JS bridges to untrusted pages.
- App Store / Play: in-app account deletion, privacy labels / Data safety form matching actual SDKs, App Tracking Transparency prompt before tracking on iOS.

## Stripe and payments
- Prices and amounts computed server-side from your own product IDs — never trust an amount from the client.
- Webhooks: verify signature with the endpoint secret, handle events idempotently, fulfil orders from the webhook (not from the success-page redirect).
- Use Checkout/Payment Element so card data never touches your servers. Restricted API keys with minimum permissions for each service.

## LLM / AI apps
- Provider keys server-side; per-user rate limits and monthly spend caps; set max tokens.
- Treat retrieved documents, web pages, emails and user uploads as untrusted (prompt injection). Tools run with the user's permissions, filtered RAG, human confirmation for side effects.
- Render model output as text or sanitized markdown; block auto-loading remote images in model output (data exfiltration via URL).
- Tell users when they're interacting with AI and how their inputs are used (training? retention?) — put it in the privacy policy (LEG-101) and check the provider's data-retention settings.
