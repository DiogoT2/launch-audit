#!/usr/bin/env python3
# launch-audit: ignore-file
"""
launch-audit repo scanner — fast, dependency-free first pass.

Finds leads (not verdicts) for the launch-audit checklists:
secrets, client-exposed env vars, tracked .env files, debug flags,
risky code patterns, Supabase tables without RLS, open Firebase rules,
dependency hygiene, and legal/accessibility signals.

Usage:
  python3 scan.py [PATH] [--history] [--json] [--run-audits] [--max-per-rule N]

  --history      also scan git history (added lines) for secrets
  --json         machine-readable output
  --run-audits   run available dependency auditors (npm/pnpm/pip-audit/osv-scanner)
  --max-per-rule max findings printed per rule (default 15)

Exit code: 1 if any Critical or High finding, else 0 (handy in CI).
Silence a line with a trailing comment containing "launch-audit: ignore".
Python 3.8+, standard library only.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

SKIP_DIRS = {
    ".git", "node_modules", "vendor", ".venv", "venv", "env", "__pycache__",
    ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache", "coverage", ".dart_tool",
    "Pods", "DerivedData", "target", ".gradle", ".idea", ".vscode", "bower_components",
    ".terraform", ".pytest_cache", ".mypy_cache", "site-packages", ".expo",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".tiff", ".psd",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".webm",
    ".wav", ".ogg", ".flac", ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc",
    ".o", ".a", ".lib", ".db", ".sqlite", ".sqlite3", ".glb", ".gltf", ".fbx", ".blend",
    ".keystore", ".jks", ".p12", ".pfx", ".ipa", ".apk", ".aab",
}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "poetry.lock",
             "Pipfile.lock", "Gemfile.lock", "composer.lock", "Cargo.lock", "pubspec.lock",
             "go.sum", "uv.lock"}
CODE_EXT = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro",
    ".py", ".rb", ".php", ".go", ".java", ".kt", ".kts", ".swift", ".dart", ".cs",
    ".rs", ".erb", ".html", ".htm", ".jinja", ".j2", ".twig", ".blade.php",
}
MARKUP_EXT = {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".astro", ".erb", ".php", ".twig"}
MAX_FILE_BYTES = 2_000_000
PLACEHOLDER = re.compile(
    r"(example|placeholder|your[_-]?|changeme|change_me|xxxx|\*\*\*\*|<[^>]+>|\$\{|process\.env|"
    r"os\.environ|getenv|dummy|sample|test_?key|fake|redacted|replace[_-]?me|todo)", re.I)

# ---------------------------------------------------------------------------
# Rules: (id, severity, ref, title, regex, scope)   scope: "all" | "code" | "markup" | "env"
# ---------------------------------------------------------------------------
SECRET_RULES = [
    ("aws-access-key", "Critical", "SEC-101", "AWS access key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("stripe-live-secret", "Critical", "SEC-101", "Stripe live secret/restricted key", r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}"),
    ("stripe-test-secret", "Medium", "SEC-101", "Stripe test secret key", r"\bsk_test_[0-9a-zA-Z]{20,}"),
    ("stripe-webhook-secret", "High", "SEC-101", "Stripe webhook signing secret", r"\bwhsec_[0-9a-zA-Z]{20,}"),
    ("anthropic-key", "Critical", "SEC-101", "Anthropic API key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai-key", "Critical", "SEC-101", "OpenAI-style API key", r"\bsk-(?!ant-)(proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}"),
    ("github-token", "Critical", "SEC-101", "GitHub token", r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    ("slack-token", "Critical", "SEC-101", "Slack token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    ("sendgrid-key", "Critical", "SEC-101", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    ("resend-key", "Critical", "SEC-101", "Resend API key", r"\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}"),
    ("supabase-secret-key", "Critical", "SEC-101", "Supabase secret key", r"\bsb_secret_[A-Za-z0-9_\-]{20,}"),
    ("private-key", "Critical", "SEC-101", "Private key block", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("google-api-key", "Medium", "SEC-101", "Google API key (OK only if it's a referrer/app-restricted Firebase/Maps web key)", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("db-url-password", "High", "SEC-101", "Database URL with embedded password",
     r"\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp)://[^:\s/'\"]+:[^@\s'\"]{3,}@[^\s'\"]+"),
    ("generic-secret-assign", "Medium", "SEC-101", "Hard-coded credential-looking value",
     r"(?i)\b[\w\-]*(api[_\-]?key|secret|token|passw(or)?d|private[_\-]?key|client[_\-]?secret)[\w\-]*\b['\"]?\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"),
]
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

CODE_RULES = [
    # secrets exposure via public env prefixes
    ("public-env-secret", "High", "SEC-101", "Secret-looking variable with a client-exposed prefix",
     r"\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|GATSBY_)[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|TOKEN|ADMIN)[A-Z0-9_]*", "all"),
    # debug
    ("django-debug", "High", "SEC-104", "Django DEBUG = True (confirm it's not used in production)", r"^\s*DEBUG\s*=\s*True\b", "code"),
    ("flask-debug", "High", "SEC-104", "Flask/Werkzeug debug=True", r"\.run\([^)]*debug\s*=\s*True", "code"),
    ("laravel-debug", "Medium", "SEC-104", "APP_DEBUG=true", r"^\s*APP_DEBUG\s*=\s*true", "env"),
    ("prod-sourcemaps", "Low", "SEC-104", "Public production source maps enabled", r"productionBrowserSourceMaps\s*:\s*true", "code"),
    # injection & dangerous sinks
    ("xss-sink", "Medium", "SEC-403", "Raw HTML rendering — ensure content is sanitized",
     r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|\bv-html\b|\{@html\b|\|\s*safe\b|\bmark_safe\(|\.html_safe\b|<%==|\{!!|document\.write\(", "code"),
    ("eval", "High", "SEC-406", "Dynamic code evaluation", r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(", "code"),
    ("command-injection", "High", "SEC-405", "Shell command execution — check for user input",
     r"\b(exec|execSync)\s*\(\s*[`'\"][^`'\"]*(\$\{|\"\s*\+|'\s*\+)|\bshell\s*=\s*True|\bos\.system\s*\(|\bos\.popen\s*\(|spawn\([^)]*shell\s*:\s*true|\bshell_exec\s*\(|\bpassthru\s*\(", "code"),
    ("insecure-deserialization", "High", "SEC-406", "Insecure deserialization",
     r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)|\bunserialize\s*\(|\bmarshal\.loads\s*\(|node-serialize", "code"),
    ("sql-interpolation", "High", "SEC-402", "SQL built with string interpolation",
     r"(?i)(\.query|\.execute|\.raw|\$queryRawUnsafe|\$executeRawUnsafe|\.sql|db\.run|db\.all|db\.get|cursor\.execute)\s*\(\s*(f['\"]|`[^`]*\$\{[^`]*`|['\"][^'\"]*(select|insert|update|delete)[^'\"]*['\"]\s*(\+|%\s))", "code"),
    ("sql-unsafe-raw", "High", "SEC-402", "Unsafe raw query API", r"\$(queryRawUnsafe|executeRawUnsafe)\s*\(", "code"),
    ("mass-assignment", "High", "SEC-304", "Request body passed straight to a model/update",
     r"\.(create|update|insert|upsert|findOneAndUpdate|updateOne|build)\s*\(\s*(req|request|ctx\.request)\.body\s*\)|Object\.assign\([^,]+,\s*(req|request)\.body\)|\bpermit!|\$guarded\s*=\s*\[\s*\]|\*\*request\.(json|data|POST)", "code"),
    # transport / browser
    ("cors-wildcard", "Medium", "SEC-503", "Permissive CORS",
     r"origin\s*:\s*['\"]\*['\"]|origin\s*:\s*true\b|Access-Control-Allow-Origin['\"]?\s*[,:=]\s*['\"]\*|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|AllowAnyOrigin\(\)", "code"),
    ("cookie-insecure", "Medium", "SEC-205", "Cookie security flag disabled",
     r"httpOnly\s*:\s*false|\bsecure\s*:\s*false|(SESSION|CSRF)_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False", "code"),
    ("token-localstorage", "Low", "SEC-205", "Token stored in localStorage", r"localStorage\.setItem\(\s*['\"][^'\"]*(token|jwt|session)[^'\"]*['\"]", "code"),
    ("tls-verify-off", "Medium", "SEC-501", "TLS certificate verification disabled",
     r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=?\s*['\"]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)", "code"),
    # auth
    ("weak-password-hash", "High", "SEC-202", "Weak hash near password handling",
     r"(?i)(md5|sha1|sha256)\s*\(.*pass|pass\w*.*\b(md5|sha1)\s*\(|createHash\(\s*['\"](md5|sha1)['\"]\s*\).*pass", "code"),
    ("jwt-no-verify", "High", "SEC-201", "JWT decoded without verification / 'none' algorithm",
     r"verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]|jwt\.decode\([^)]*verify\s*=\s*False|algorithm\s*:\s*['\"]none['\"]", "code"),
    ("insecure-random-token", "Medium", "SEC-201", "Math.random used for tokens/codes",
     r"Math\.random\(\).*(token|code|otp|secret|password|reset)|(token|code|otp|secret|reset)\w*\s*=.*Math\.random\(", "code"),
]

RULE_INDEX = {}
for r in SECRET_RULES:
    RULE_INDEX[r[0]] = {"severity": r[1], "ref": r[2], "title": r[3]}
for r in CODE_RULES:
    RULE_INDEX[r[0]] = {"severity": r[1], "ref": r[2], "title": r[3]}

COMPILED_SECRETS = [(r[0], re.compile(r[4])) for r in SECRET_RULES]
COMPILED_CODE = [(r[0], re.compile(r[4], re.M), r[5]) for r in CODE_RULES]

TRACKING_PKGS = {
    "@vercel/analytics": "Vercel Analytics", "posthog-js": "PostHog", "posthog-node": "PostHog",
    "mixpanel-browser": "Mixpanel", "mixpanel": "Mixpanel", "@amplitude/analytics-browser": "Amplitude",
    "amplitude-js": "Amplitude", "react-ga4": "Google Analytics", "react-ga": "Google Analytics",
    "@next/third-parties": "Google tags (via @next/third-parties)", "@segment/analytics-next": "Segment",
    "analytics": "Segment/analytics", "react-hotjar": "Hotjar", "@hotjar/browser": "Hotjar",
    "@sentry/browser": "Sentry", "@sentry/react": "Sentry", "@sentry/nextjs": "Sentry",
    "@sentry/react-native": "Sentry", "sentry_flutter": "Sentry", "sentry-sdk": "Sentry",
    "logrocket": "LogRocket", "@fullstory/browser": "FullStory", "@microsoft/clarity": "Microsoft Clarity",
    "react-facebook-pixel": "Meta Pixel", "firebase": "Firebase (Analytics if enabled)",
    "@react-native-firebase/analytics": "Firebase Analytics", "firebase_analytics": "Firebase Analytics",
    "appsflyer-react-native": "AppsFlyer", "react-native-branch": "Branch", "@intercom/messenger-js-sdk": "Intercom",
    "crisp-sdk-web": "Crisp", "@tawk.to/tawk-messenger-react": "Tawk.to", "plausible-tracker": "Plausible",
    "@datadog/browser-rum": "Datadog RUM", "openai": "OpenAI API", "@anthropic-ai/sdk": "Anthropic API",
    "stripe": "Stripe", "@stripe/stripe-js": "Stripe", "resend": "Resend", "@sendgrid/mail": "SendGrid",
    "mailchimp-marketing": "Mailchimp", "@mapbox/mapbox-gl": "Mapbox", "@googlemaps/js-api-loader": "Google Maps",
}
CONSENT_PKGS = {"vanilla-cookieconsent", "cookieconsent", "react-cookie-consent", "@cookiehub/cookiehub",
                "klaro", "@osano/cookieconsent", "cookiebot", "react-cookiebot", "@onetrust/onetrust",
                "iubenda", "termly", "@c15t/react", "c15t"}
CONSENT_TEXT = re.compile(r"(?i)cookiebot|onetrust|cookieconsent|cookie-consent|consentmanager|iubenda|termly|klaro|usercentrics|didomi|axeptio|complianz|gtag\(\s*['\"]consent['\"]")

LEGAL_PAGES = {
    "LEG-101 Privacy policy": re.compile(r"(?i)privacy[-_ ]?policy|/privacy\b|privacidade|privacidad|datenschutz"),
    "LEG-102 Terms of service": re.compile(r"(?i)terms[-_ ]?(of[-_ ]?(service|use)|and[-_ ]?conditions)|/terms\b|/tos\b|termos|t[eé]rminos|\bagb\b"),
    "LEG-103 Refund policy": re.compile(r"(?i)refund|reembolso|devolu[cç][aã]o|withdrawal|cancellation[-_ ]?policy"),
    "LEG-104 Cookie policy": re.compile(r"(?i)cookie[-_ ]?policy|pol[ií]tica[-_ ]de[-_ ]cookies|/cookies\b"),
    "LEG-105 Business details / imprint": re.compile(r"(?i)imprint|impressum|legal[-_ ]?notice|aviso[-_ ]legal|livro[-_ ]de[-_ ]reclama|vat\s*(no|number)|\bnif\b|\bnipc\b"),
}
DELETE_ACCOUNT = re.compile(r"(?i)delete[-_ ]?(my[-_ ]?)?account|deleteAccount|delete_account|deleteUser\b|delete_user\b|account[-_ ]deletion|apagar[-_ ]conta|eliminar[-_ ]conta")
UNSUB = re.compile(r"(?i)unsubscribe|List-Unsubscribe|cancelar[-_ ]subscri")
AUTH_HINT = re.compile(r"(?i)signUp|sign_up|signup|createUserWith|register\(|auth\.signIn|supabase\.auth|firebase/auth|next-auth|@clerk|lucia|passport|devise|django\.contrib\.auth")
EMAIL_HINT = re.compile(r"(?i)nodemailer|@sendgrid|resend|mailchimp|postmark|mailgun|brevo|sendinblue|ses\.send|send_mail\(")
IMG_NO_ALT = re.compile(r"<(img|Image)\b(?![^>]*\balt\s*=)[^>]*>", re.S)

# ---------------------------------------------------------------------------


def mask(value: str) -> str:
    value = value.strip()
    return value[:4] + "****" if len(value) > 4 else "****"


def b64json(seg: str):
    try:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad).decode("utf-8", "ignore"))
    except Exception:
        return None


class Scanner:
    def __init__(self, root: Path, max_per_rule: int):
        self.root = root
        self.max_per_rule = max_per_rule
        self.findings = []           # dicts
        self._seen = set()
        self.files_scanned = 0
        self.manifests = []
        self.lockfiles = set()
        self.pkg_deps = {}
        self.signals = defaultdict(list)  # name -> [paths]
        self.sql_tables = {}         # table -> file
        self.rls_tables = set()
        self.img_no_alt = []
        self.has_supabase = (root / "supabase").is_dir()

    # -- helpers -------------------------------------------------------------
    def add(self, rule, path, line=None, detail="", severity=None, ref=None, title=None):
        meta = RULE_INDEX.get(rule, {})
        key = (rule, str(path), line, detail)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append({
            "rule": rule,
            "severity": severity or meta.get("severity", "Info"),
            "ref": ref or meta.get("ref", ""),
            "title": title or meta.get("title", rule),
            "file": str(path),
            "line": line,
            "detail": detail,
        })

    def rel(self, p: Path) -> str:
        try:
            return str(p.relative_to(self.root))
        except ValueError:
            return str(p)

    # -- walk ----------------------------------------------------------------
    def walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
            for name in filenames:
                p = Path(dirpath) / name
                if name in LOCKFILES:
                    self.lockfiles.add(name)
                if name in {"package.json", "requirements.txt", "pyproject.toml", "Pipfile", "Gemfile",
                            "composer.json", "Cargo.toml", "go.mod", "pubspec.yaml", "build.gradle",
                            "build.gradle.kts", "Podfile"}:
                    self.manifests.append(self.rel(p))
                ext = "".join(p.suffixes[-2:]) if name.endswith(".blade.php") else p.suffix.lower()
                if ext in BINARY_EXT or name.endswith(".min.js") or name.endswith(".map") or name in LOCKFILES:
                    continue
                try:
                    if p.stat().st_size > MAX_FILE_BYTES:
                        continue
                    raw = p.read_bytes()
                except OSError:
                    continue
                if b"\x00" in raw[:4096]:
                    continue
                text = raw.decode("utf-8", "ignore")
                if "launch-audit: ignore-file" in text[:400]:
                    continue
                self.files_scanned += 1
                self.scan_file(p, name, ext, text)

    def scan_file(self, p: Path, name: str, ext: str, text: str):
        rel = self.rel(p)
        lname = name.lower()
        is_env = lname.startswith(".env") or lname.endswith(".env")
        is_example = any(s in lname for s in ("example", "sample", "template", ".dist"))
        is_code = ext in CODE_EXT or ext in {".blade.php"}
        is_doc = ext in {".md", ".mdx", ".txt", ".rst"}
        lines = text.splitlines()

        for i, line in enumerate(lines, 1):
            if "launch-audit: ignore" in line or len(line) > 5000:
                continue
            # secrets: everywhere (docs too — README leaks are real), skip obvious placeholders
            for rule, rx in COMPILED_SECRETS:
                m = rx.search(line)
                if not m:
                    continue
                val = m.group(0)
                if rule in ("generic-secret-assign", "db-url-password"):
                    if PLACEHOLDER.search(val) or is_example:
                        continue
                    if rule == "db-url-password" and re.search(r"@(localhost|127\.0\.0\.1|db|postgres|mysql|mongo|redis)(:|/|$)", val):
                        self.add(rule, rel, i, mask(val), severity="Low",
                                 title="Database URL with password (local/dev host)")
                        continue
                if is_example and rule not in ("private-key",):
                    continue
                if is_doc and rule in ("generic-secret-assign", "google-api-key"):
                    continue
                self.add(rule, rel, i, mask(val))
            for m in JWT_RE.finditer(line):
                payload = b64json(m.group(0).split(".")[1]) or {}
                role = str(payload.get("role", ""))
                if role == "service_role":
                    self.add("supabase-service-role", rel, i, mask(m.group(0)), severity="Critical", ref="SEC-101",
                             title="Supabase service_role JWT (bypasses RLS) in source")
                elif role not in ("anon", "authenticated") and not is_example:
                    self.add("jwt-literal", rel, i, mask(m.group(0)), severity="Medium", ref="SEC-101",
                             title="Hard-coded JWT")
            # code rules
            for rule, rx, scope in COMPILED_CODE:
                if scope == "code" and not is_code:
                    continue
                if scope == "env" and not (is_env and not is_example):
                    continue
                if scope == "all" and is_doc:
                    continue
                if rx.search(line):
                    snippet = line.strip()[:140]
                    if rule in ("generic-secret-assign",):
                        snippet = ""
                    self.add(rule, rel, i, snippet)

        # file-level checks
        if (lname.endswith(".rules") or lname in {"firestore.rules", "storage.rules", "database.rules.json"}):
            for i, line in enumerate(lines, 1):
                if re.search(r"allow\s+[\w ,]+:\s*if\s+true\b", line) or re.search(r'"\.(read|write)"\s*:\s*true', line):
                    self.add("firebase-open-rules", rel, i, line.strip()[:140], severity="Critical", ref="SEC-303",
                             title="Firebase rules allow public read/write")
                if re.search(r"request\.time\s*<\s*timestamp\.date", line):
                    self.add("firebase-test-mode", rel, i, line.strip()[:140], severity="Critical", ref="SEC-303",
                             title="Firebase test-mode rules (open until a date)")

        if ext == ".sql":
            for m in re.finditer(r"(?i)create\s+table\s+(if\s+not\s+exists\s+)?([\"\w.]+)", text):
                t = m.group(2).replace('"', "").lower()
                if "." in t:
                    schema, t = t.split(".", 1)
                    if schema not in ("public",):
                        continue
                self.sql_tables.setdefault(t, rel)
            for m in re.finditer(r"(?i)alter\s+table\s+(only\s+)?(if\s+exists\s+)?([\"\w.]+)\s+enable\s+row\s+level\s+security", text):
                self.rls_tables.add(m.group(3).replace('"', "").lower().split(".")[-1])

        if lname == "package.json":
            try:
                pkg = json.loads(text)
                for sect in ("dependencies", "devDependencies", "optionalDependencies"):
                    for k, v in (pkg.get(sect) or {}).items():
                        self.pkg_deps[k] = str(v)
                        if re.match(r"^(git\+|git:|github:|gitlab:|bitbucket:|https?://|file:)", str(v)):
                            self.add("dep-unpinned-source", rel, None, f"{k}: {v}", severity="Medium", ref="SEC-803",
                                     title="Dependency installed from git/URL/file instead of the registry")
            except Exception:
                pass
        if lname in ("requirements.txt",):
            for i, line in enumerate(lines, 1):
                s = line.strip()
                if s and not s.startswith("#") and not s.startswith("-") and not re.search(r"==|@", s):
                    self.add("py-unpinned", rel, i, s, severity="Low", ref="SEC-802",
                             title="Unpinned Python dependency")
                if re.search(r"git\+|https?://", s):
                    self.add("dep-unpinned-source", rel, i, s, severity="Medium", ref="SEC-803",
                             title="Dependency installed from git/URL instead of the registry")
        if lname == "pubspec.yaml":
            for k in ("firebase_analytics", "sentry_flutter", "appsflyer_sdk", "facebook_app_events", "google_mobile_ads"):
                if re.search(rf"^\s*{k}\s*:", text, re.M):
                    self.pkg_deps[k] = "pubspec"

        # signals for legal / a11y
        if is_code or is_doc or ext in {".json", ".yaml", ".yml"}:
            hay = rel + "\n" + text if is_code else rel
            for label, rx in LEGAL_PAGES.items():
                if rx.search(hay):
                    self.signals[label].append(rel)
            if is_code:
                if DELETE_ACCOUNT.search(text):
                    self.signals["delete-account"].append(rel)
                if UNSUB.search(text):
                    self.signals["unsubscribe"].append(rel)
                if AUTH_HINT.search(text):
                    self.signals["auth"].append(rel)
                if EMAIL_HINT.search(text):
                    self.signals["email-sending"].append(rel)
                if CONSENT_TEXT.search(text):
                    self.signals["consent"].append(rel)
        if ext in MARKUP_EXT:
            for m in IMG_NO_ALT.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                if "{...props}" in m.group(0) or "{...rest}" in m.group(0):
                    continue
                self.img_no_alt.append(f"{rel}:{line_no}")

    # -- repo-level checks ---------------------------------------------------
    def git_checks(self):
        if not (self.root / ".git").exists() or not shutil.which("git"):
            self.add("no-git", ".", None, "", severity="Info", ref="SEC-103",
                     title="Not a git repository (history and tracked-file checks skipped)")
            return
        try:
            tracked = subprocess.run(["git", "-C", str(self.root), "ls-files"], capture_output=True,
                                     text=True, timeout=60).stdout.splitlines()
        except Exception:
            tracked = []
        for f in tracked:
            base = os.path.basename(f).lower()
            if (base.startswith(".env") or base.endswith(".env")) and not any(
                    s in base for s in ("example", "sample", "template", ".dist")):
                self.add("env-tracked", f, None, "", severity="High", ref="SEC-102",
                         title=".env file is tracked by git (rotate anything it ever contained)")
            if base.endswith((".pem", ".key", ".p12", ".pfx", ".keystore", ".jks")) or base in (
                    "id_rsa", "id_ed25519", "serviceaccountkey.json", "service-account.json", "credentials.json"):
                self.add("key-file-tracked", f, None, "", severity="High", ref="SEC-101",
                         title="Key/credential file tracked by git")
        gi = self.root / ".gitignore"
        if not gi.exists() or not re.search(r"(?m)^\s*\*?\.env", gi.read_text(errors="ignore")):
            self.add("gitignore-env", ".gitignore", None, "", severity="Medium", ref="SEC-102",
                     title=".gitignore does not ignore .env files")

    def history_scan(self, limit_lines=3_000_000):
        if not (self.root / ".git").exists() or not shutil.which("git"):
            return
        try:
            proc = subprocess.Popen(["git", "-C", str(self.root), "log", "-p", "--all", "--no-color",
                                     "--no-merges", "--format=__COMMIT__ %h"],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="ignore")
        except Exception:
            return
        commit, current_file, n = "?", "?", 0
        found = set()
        for line in proc.stdout:
            n += 1
            if n > limit_lines:
                proc.kill()
                self.add("history-truncated", ".git", None, f"stopped after {limit_lines} lines",
                         severity="Info", ref="SEC-103", title="History scan truncated — run gitleaks for full coverage")
                break
            if line.startswith("__COMMIT__ "):
                commit = line.split()[1]
                continue
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            if "launch-audit: ignore" in line:
                continue
            for rule, rx in COMPILED_SECRETS:
                if rule in ("generic-secret-assign", "google-api-key"):
                    continue
                m = rx.search(line)
                if m:
                    val = m.group(0)
                    if rule == "db-url-password" and (PLACEHOLDER.search(val) or re.search(r"@(localhost|127\.0\.0\.1)", val)):
                        continue
                    if any(s in current_file.lower() for s in ("example", "sample")):
                        continue
                    k = (rule, val)
                    if k in found:
                        continue
                    found.add(k)
                    meta = RULE_INDEX[rule]
                    self.add("history-" + rule, current_file, None, f"commit {commit}: {mask(val)}",
                             severity=meta["severity"], ref="SEC-103",
                             title=f"In git history: {meta['title']} (rotate, then purge)")
            for m in JWT_RE.finditer(line):
                payload = b64json(m.group(0).split(".")[1]) or {}
                if payload.get("role") == "service_role" and ("srv", m.group(0)) not in found:
                    found.add(("srv", m.group(0)))
                    self.add("history-supabase-service-role", current_file, None, f"commit {commit}: {mask(m.group(0))}",
                             severity="Critical", ref="SEC-103", title="In git history: Supabase service_role JWT")
        try:
            proc.wait(timeout=5)
        except Exception:
            pass

    def post_checks(self):
        # Supabase RLS
        if self.sql_tables:
            missing = sorted(t for t in self.sql_tables if t not in self.rls_tables)
            sev = "Critical" if self.has_supabase else "High"
            for t in missing:
                self.add("rls-missing", self.sql_tables[t], None, f"table `{t}`", severity=sev, ref="SEC-303",
                         title="Table created without `enable row level security` in migrations"
                         + ("" if self.has_supabase else " (only matters if exposed via a Supabase/PostgREST API)"))
        # lockfiles
        js = any(m.endswith("package.json") for m in self.manifests)
        if js and not ({"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"} & self.lockfiles):
            self.add("no-lockfile", "package.json", None, "", severity="Medium", ref="SEC-802",
                     title="No JS lockfile committed (non-reproducible installs)")
        # a11y
        for loc in self.img_no_alt:
            f, ln = loc.rsplit(":", 1)
            self.add("img-no-alt", f, int(ln), "", severity="Medium", ref="A11Y-1", title="<img>/<Image> without alt attribute")
        # legal signals
        for label in LEGAL_PAGES:
            if not self.signals.get(label):
                ref = label.split()[0]
                self.add("legal-missing", "(project)", None, label, severity="Medium", ref=ref,
                         title=f"No sign of: {label.split(' ', 1)[1]} — confirm it exists and is linked")
        trackers = sorted({TRACKING_PKGS[d] for d in self.pkg_deps if d in TRACKING_PKGS})
        has_consent = bool(CONSENT_PKGS & set(self.pkg_deps)) or bool(self.signals.get("consent"))
        if trackers:
            self.add("third-party-inventory", "package.json", None, ", ".join(trackers), severity="Info", ref="LEG-303",
                     title="Third-party SDKs/services detected — list them in the privacy policy and check consent/DPAs")
        analytics_like = [t for t in trackers if any(w in t for w in (
            "Analytics", "PostHog", "Mixpanel", "Amplitude", "Hotjar", "LogRocket", "FullStory", "Clarity",
            "Pixel", "Segment", "AppsFlyer", "Branch", "Google tags", "Datadog"))]
        if analytics_like and not has_consent:
            self.add("no-consent-mgmt", "(project)", None, ", ".join(analytics_like), severity="High", ref="LEG-201",
                     title="Analytics/tracking SDKs found but no consent management detected (EU/UK)")
        if self.signals.get("auth") and not self.signals.get("delete-account"):
            self.add("no-account-deletion", "(project)", None, "", severity="High", ref="LEG-302",
                     title="Sign-up/auth found but no account-deletion flow detected")
        if self.signals.get("email-sending") and not self.signals.get("unsubscribe"):
            self.add("no-unsubscribe", "(project)", None, "", severity="Medium", ref="LEG-601",
                     title="Email sending found but no unsubscribe handling detected (needed for marketing email)")

    def audit_commands(self):
        cmds = []
        m = " ".join(self.manifests)
        if "package.json" in m:
            if "pnpm-lock.yaml" in self.lockfiles:
                cmds.append("pnpm audit --prod")
            elif "yarn.lock" in self.lockfiles:
                cmds.append("yarn npm audit --environment production  # yarn berry; classic: yarn audit")
            else:
                cmds.append("npm audit --omit=dev")
            cmds.append("npx depcheck   # unused packages (SEC-804)")
        if "requirements.txt" in m or "pyproject.toml" in m or "Pipfile" in m:
            cmds.append("pip-audit")
        if "Gemfile" in m:
            cmds += ["bundle audit check --update", "brakeman"]
        if "composer.json" in m:
            cmds.append("composer audit")
        if "Cargo.toml" in m:
            cmds.append("cargo audit")
        if "go.mod" in m:
            cmds.append("govulncheck ./...")
        if "pubspec.yaml" in m:
            cmds.append("flutter pub outdated")
        cmds.append("osv-scanner -r .   # cross-ecosystem")
        cmds.append("gitleaks detect --redact   # deeper secret scan incl. history")
        return cmds

    def run_audits(self):
        results = []
        def run(cmd, cwd):
            try:
                out = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)
                return out.stdout
            except Exception as e:
                return None
        if (self.root / "package.json").exists() and shutil.which("npm"):
            out = run(["npm", "audit", "--omit=dev", "--json"], self.root)
            try:
                v = json.loads(out or "{}").get("metadata", {}).get("vulnerabilities", {})
                results.append(("npm audit", v))
                for sev in ("critical", "high"):
                    if v.get(sev):
                        self.add("npm-audit-" + sev, "package.json", None, f"{v[sev]} {sev} vulnerabilities",
                                 severity=sev.capitalize(), ref="SEC-801", title=f"npm audit: {sev} vulnerabilities")
            except Exception:
                results.append(("npm audit", "could not parse output (network blocked?)"))
        if shutil.which("pip-audit") and ((self.root / "requirements.txt").exists() or (self.root / "pyproject.toml").exists()):
            out = run(["pip-audit", "-f", "json"], self.root)
            results.append(("pip-audit", (out or "")[:200]))
        if shutil.which("osv-scanner"):
            out = run(["osv-scanner", "-r", "--format", "json", "."], self.root)
            results.append(("osv-scanner", "ran" if out else "no output"))
        return results


def render_md(sc: Scanner, audits, cmds) -> str:
    out = []
    counts = defaultdict(int)
    for f in sc.findings:
        counts[f["severity"]] += 1
    out.append(f"# launch-audit scan — `{sc.root}`\n")
    out.append(f"Files scanned: {sc.files_scanned} · Manifests: {', '.join(sc.manifests) or 'none'}\n")
    out.append("| " + " | ".join(SEVERITY_ORDER) + " |")
    out.append("|" + "---:|" * len(SEVERITY_ORDER))
    out.append("| " + " | ".join(str(counts[s]) for s in SEVERITY_ORDER) + " |\n")
    out.append("> Leads, not verdicts: confirm each hit in the code. A clean scan does not prove the app is safe — "
               "access-control and server-side auth bugs need manual review.\n")
    by_sev = defaultdict(lambda: defaultdict(list))
    for f in sc.findings:
        by_sev[f["severity"]][(f["rule"], f["title"], f["ref"])].append(f)
    for sev in SEVERITY_ORDER:
        if not by_sev[sev]:
            continue
        out.append(f"## {sev}\n")
        for (rule, title, ref), items in sorted(by_sev[sev].items(), key=lambda kv: kv[0][2]):
            out.append(f"### {ref} · {title}  `{rule}` ({len(items)})")
            for f in items[: sc.max_per_rule]:
                loc = f["file"] + (f":{f['line']}" if f["line"] else "")
                det = f" — `{f['detail']}`" if f["detail"] else ""
                out.append(f"- {loc}{det}")
            if len(items) > sc.max_per_rule:
                out.append(f"- … +{len(items) - sc.max_per_rule} more")
            out.append("")
    if audits:
        out.append("## Dependency audit results\n")
        for name, res in audits:
            out.append(f"- **{name}**: {res}")
        out.append("")
    out.append("## Run next\n")
    out.append("```bash")
    out += cmds
    out.append("```")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="launch-audit repository scanner")
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--history", action="store_true", help="scan git history for secrets")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--run-audits", action="store_true", help="run available dependency auditors")
    ap.add_argument("--max-per-rule", type=int, default=15)
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Not a directory: {root}", file=sys.stderr)
        sys.exit(2)
    sc = Scanner(root, args.max_per_rule)
    sc.walk()
    sc.git_checks()
    if args.history:
        sc.history_scan()
    sc.post_checks()
    audits = sc.run_audits() if args.run_audits else []
    cmds = sc.audit_commands()
    sc.findings.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["ref"], f["file"], f["line"] or 0))

    if args.json:
        print(json.dumps({"root": str(root), "files_scanned": sc.files_scanned, "manifests": sc.manifests,
                          "findings": sc.findings, "audits": audits, "next_commands": cmds}, indent=2, default=str))
    else:
        print(render_md(sc, audits, cmds))
    sys.exit(1 if any(f["severity"] in ("Critical", "High") for f in sc.findings) else 0)


if __name__ == "__main__":
    main()
