---
name: launch-audit
description: Pre-launch audit for web and mobile apps covering security hardening, legal/privacy compliance and accessibility. Use when the user is about to launch, ship, deploy or publish an app or website; asks whether it is secure, safe, production-ready or compliant; wants a security audit, a GDPR/cookie/privacy check, or to avoid getting hacked or sued; or mentions leaked API keys, RLS, auth, CORS, security headers, rate limiting, privacy policy, terms of service or cookie banners. Also use when reviewing a codebase before its first production release.
license: MIT
---

# Launch Audit

Audit an app so it doesn't get **hacked** or **sued**. The work splits into four reference files — read only the ones (and the sections) that apply to the stack in front of you:

| File | Use it for |
|---|---|
| `references/prelaunch-checklist.md` | The 20-item go/no-go gate. Start here for a quick check. |
| `references/security.md` | Full security review: secrets, auth, access control, injection, browser/transport, supply chain, AI features, operations. |
| `references/legal-compliance.md` | Policies, consent, privacy rights, honest marketing, kids, email, IP, accessibility. |
| `references/stack-notes.md` | Platform-specific traps: Supabase, Firebase, Next.js, Express, Django, Rails, Laravel, mobile, Stripe, LLM apps. |

Every checklist item has an ID (`SEC-*`, `LEG-*`, `A11Y-*`). Use those IDs in the report so findings are traceable.

## Pick the mode

- **Quick** ("launch checklist", "am I ready to launch?", little time) → `prelaunch-checklist.md` only.
- **Security** ("security audit", "avoid getting hacked", "is this secure?") → `security.md` + relevant `stack-notes.md` sections.
- **Legal** ("avoid getting sued", "GDPR", "cookie banner", "privacy policy") → `legal-compliance.md`.
- **Full** (default when the user just says "audit my app" before launch) → all of the above.

## Workflow

### 1. Scope — mostly automatic

Work these out from the repository before asking anything:

- **Stack**: framework, language, backend/BaaS (Supabase, Firebase, own server), DB, auth provider, hosting, web vs mobile vs both. Look at `package.json`, lockfiles, `requirements.txt`/`pyproject.toml`, `Gemfile`, `composer.json`, `pubspec.yaml`, `supabase/`, `firebase.json`, `vercel.json`, `Dockerfile`, CI files.
- **Data inventory**: what personal data is collected (forms, sign-up fields, analytics), where it's stored, which third-party SDKs/services receive it (analytics, ads, crash reporting, payments, email, AI APIs).
- **Money**: payments, subscriptions, trials, in-app purchases.
- **Surface**: public pages, API routes, server actions, edge/cloud functions, webhooks, admin areas, file uploads, AI/LLM features.

Then ask the user — in **one** message, only for what the code can't tell you:
target markets (EU/UK/US/Brazil/other), whether minors can use it, the live or staging URL (if any), and whether they want fixes applied or a report only.

If the user is unavailable, assume EU + US, adults only, report first, and say so at the top of the report.

### 2. Automated pass

```bash
python3 scripts/scan.py <repo-path>              # working tree
python3 scripts/scan.py <repo-path> --history    # also scan git history for secrets
python3 scripts/scan.py <repo-path> --all-files  # include what .gitignore excludes (built bundles)
python3 scripts/check_live.py https://staging.example.com   # live headers, cookies, CORS, exposed files
```

Both scripts are Python 3 standard library only. `check_live.py` sends a handful of harmless GET requests — run it **only against sites the user owns or is authorized to test**.

Also run the ecosystem's dependency auditor when available (`npm audit`, `pnpm audit`, `pip-audit`, `osv-scanner`, `bundle audit`, `composer audit`, `cargo audit`); `scan.py` prints the right commands for the manifests it finds.

Treat script output as **leads, not verdicts**. Confirm each hit by reading the code; drop false positives. A clean scan does not mean safe: the most damaging bugs (broken access control, missing server-side checks, tenant leaks) are logic bugs that only reading finds.

### 3. Manual review

Read, in this order:

1. Auth setup and middleware; how the server learns who the caller is.
2. **Every** API route, server action, edge/cloud function and webhook handler.
3. Database access rules: RLS policies, Firebase rules, ORM scopes, DB user privileges.
4. Anything that builds SQL, shell commands, HTML, file paths or URLs from input.
5. File upload and download handlers.
6. AI/LLM features: what untrusted text reaches the model and what tools the model can call.
7. Legal pages, cookie banner, sign-up and checkout flows, marketing copy, emails.

For every endpoint, answer four questions: **Who is calling? Is that verified on the server? Is the record theirs (or their tenant's)? Which fields can they write?** A "no" or "don't know" is a finding.

### 4. Classify

Status per item: `FAIL` · `WARN` · `PASS` · `MANUAL` (needs a human: legal text review, restore drill, lawyer) · `N/A`.
Never mark `PASS` for something you didn't actually check — use `MANUAL`.

Severity for failures:

- **Critical** — exploitable now or already exposed: live secret in repo/bundle/history, database readable or writable without auth, RLS disabled on a table with user data, auth bypass, IDOR on personal data, SQL/command injection, RCE.
- **High** — serious with a small precondition: missing rate limit on login/reset, stored XSS, missing webhook signature check, weak password hashing, permissive CORS with credentials, debug mode on in production, no backups. Legal: a hard requirement for a stated market that's missing (no privacy policy while collecting personal data; non-essential tracking before consent in the EU/UK; no account deletion in an app-store app).
- **Medium** — defence-in-depth gaps: missing security headers, verbose errors, no audit log, outdated non-exploitable deps. Legal: incomplete policy content, consent UX issues, accessibility failures.
- **Low** — hygiene and polish.

### 5. Report

Fill in `templates/report.md`. Lead with the verdict:

- 🔴 **Not ready** — any Critical, or High items that touch personal data or money.
- 🟡 **Ready with fixes** — Highs/Mediums with a plan to fix this week.
- 🟢 **Ready** — no Critical/High; Mediums tracked.

Each finding: ID, severity, evidence (`file:line` or URL + header), one line on the risk, a concrete fix (code when it's short). Group by severity, not by checklist order. Keep PASS items to a compact table.

**Never paste a full secret** in the report or chat. Show the first 4 characters and mask the rest (`sk_l****`).

### 6. Fix

Offer to fix in severity order. Edit code only when the user asked for fixes or agrees. After fixing, re-run `scan.py` (and `check_live.py` after deploy) and update the report.

Leaked secret, always in this order: **revoke/rotate the key at the provider → remove it from code and move it to server-side env vars → purge it from git history** (`git filter-repo` or BFG) and force-push. Purging alone does nothing: the key is already in clones, forks, CI logs and caches.

## Ground rules

- **Not legal advice.** You may draft privacy policies, terms, cookie policies and refund policies, but a draft must describe what the app *actually* does (the data, SDKs and processors found in steps 1–3), must not be copied from another company, and must be flagged for review by a lawyer for the target markets.
- **Defensive only.** Test only systems the user owns or is authorized to test. Explain vulnerabilities and fixes; don't build working exploits against third parties.
- **No codebase, only a URL?** Run `check_live.py`, inspect the site (footer legal links; whether trackers fire before consent; whether "Reject" is as easy as "Accept"; forms and checkout), and mark code-level items `MANUAL`.
- **Mobile apps:** anything shipped in the app binary is public. Secrets in a mobile app are leaked secrets.
- Prefer platform-native fixes (RLS policies, framework middleware, provider settings) over hand-rolled ones.
