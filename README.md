# launch-audit

**Don't get hacked. Don't get sued. Then launch.**

An [Agent Skill](https://agentskills.io) that turns Claude into a pre-launch auditor for web and mobile apps. Say "I'm launching next week" or "is my app secure?" and Claude picks it up on its own — no slash command needed — then scans your repo, reads the parts scanners can't judge, and hands you a prioritized report with fixes.

```
🔴 Not ready — 2 Critical, 4 High

SEC-303 · Critical · RLS disabled on `public.orders`
  supabase/migrations/004_orders.sql
  Anyone with your public anon key can read every order.
  Fix: alter table public.orders enable row level security; + owner policies
```

## What it checks

| Area | Covers |
|---|---|
| 🔑 **Secrets** | API keys in client bundles and mobile binaries, `.env` handling, secrets in git history, public-prefix env vars, debug mode, exposed files and internal dashboards |
| 🔐 **Auth** | server-side enforcement, password hashing, login rate limits, bot protection, session cookies, OAuth config |
| 🧱 **Access control** | IDOR / record access, admin routes, Supabase RLS, Firebase rules, mass assignment & field tampering, tenant isolation, DB least privilege |
| 💉 **Injection** | input validation, SQL/NoSQL injection, XSS, command injection, insecure deserialization, file uploads, SSRF, over-sharing API responses |
| 🌐 **Transport** | HTTPS + HSTS, CSP and security headers, CORS, CSRF |
| 📦 **Supply chain** | vulnerable, outdated, unused and suspicious packages |
| 🤖 **AI features** | prompt injection, model tool permissions, AI spend limits |
| 🛠 **Ops** | audit logs, monitoring, backups with tested restores, code review |
| ⚖️ **Legal** | privacy policy, terms, refund & cookie policies, cookie consent, form consents, data minimization, SDK audit, account deletion, dark patterns, hidden fees, fake reviews, unsupported claims, kids & age consent, unsubscribe, image/font licences, business details |
| ♿ **Accessibility** | alt text, colour contrast, keyboard navigation (WCAG 2.2 AA) |

Plus stack notes for Supabase, Firebase, Next.js, Vite SPAs, Express, Django, Rails, Laravel, Flutter/React Native, Stripe and LLM apps.

## Install

### Claude apps (claude.ai, desktop, mobile)
1. Download `launch-audit.zip` from the [latest release](../../releases/latest).
2. Go to **Customize → Skills → + → Create skill → Upload a skill** and upload the ZIP.
3. Make sure code execution / file creation is enabled in your settings.

### Claude Code
```bash
git clone https://github.com/DiogoT2/launch-audit.git
mkdir -p ~/.claude/skills && cp -r launch-audit/skills/launch-audit ~/.claude/skills/
# or per project: cp -r launch-audit/skills/launch-audit .claude/skills/
```

### Claude API / other agents
The skill follows the open [Agent Skills specification](https://agentskills.io), so it works anywhere that supports it. For the API, see Anthropic's Skills guide.

## Use it

Just talk normally — Claude decides when to load it:

- "I'm about to launch my Supabase + Next.js app, anything I'm missing?"
- "Is this repo safe to make public?"
- "Do I need a cookie banner? I use PostHog."
- "Run a quick launch checklist on staging.myapp.com"

Modes: **quick** (20-item go/no-go gate), **security**, **legal**, **full** (default).

### The scripts on their own

Both are Python 3 standard library only:

```bash
# Repo scan: secrets, risky patterns, RLS, rules, deps, legal & a11y signals
python3 skills/launch-audit/scripts/scan.py path/to/repo --history

# Live site: headers, cookies, CORS, exposed files, source maps, trackers, legal links
python3 skills/launch-audit/scripts/check_live.py https://staging.myapp.com
```

`scan.py` exits with code 1 on Critical/High findings, so it can gate CI:

```yaml
# .github/workflows/launch-audit.yml
name: launch-audit
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - run: python3 path/to/launch-audit/scripts/scan.py . --history
```

Silence a false positive with a trailing comment containing `launch-audit: ignore`.

## Structure

```
skills/launch-audit/
├── SKILL.md                      # when to trigger + audit workflow
├── references/
│   ├── prelaunch-checklist.md    # 20-item launch gate
│   ├── security.md               # SEC-* checks
│   ├── legal-compliance.md       # LEG-* and A11Y-* checks
│   └── stack-notes.md            # platform-specific traps
├── scripts/
│   ├── scan.py                   # repo scanner
│   └── check_live.py             # live site checker
└── templates/
    └── report.md                 # report format
```

## Fine print

- **Not legal advice.** The legal checklist covers the common EU/UK/US baseline and app-store rules. Get a lawyer for anything high-stakes.
- **Scanners find leads, not guarantees.** The worst bugs (broken access control) need reading, which is why the skill makes Claude read your handlers, not just grep them.
- **Only test what you own.** `check_live.py` sends a few harmless GET requests; run it against your own or authorized sites only.

## Contributing

Found a false positive, a missing check, or a stack trap worth adding? Open an issue or PR. Keep checks concrete: *what to check → how to find it → how to fix it*.

## License

[MIT](LICENSE) © 2026 Diogo Trincheiras
