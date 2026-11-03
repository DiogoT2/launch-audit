#!/usr/bin/env python3
# launch-audit: ignore-file
"""
launch-audit live check — inspect a deployed site you own or are authorized to test.

Sends a small number of harmless GET requests and reports on:
HTTPS redirect & HSTS, security headers, cookie flags, CORS reflection,
information-leaking headers, commonly exposed files (.env, .git, backups),
public source maps, mixed content, trackers in the initial HTML,
legal links, and basic accessibility signals on the landing page.

Usage:
  python3 check_live.py https://staging.example.com [--json] [--no-probe]

  --no-probe   skip exposed-file probing (headers/cookies/HTML only)

Python 3.8+, standard library only. Honors HTTPS_PROXY / SSL_CERT_FILE.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

def setup_console() -> bool:
    """Never crash on output. Windows consoles and pipes often use cp1252,
    which can't encode emoji or arrows. Returns True if stdout can show them."""
    unicode_ok = True
    for stream in (sys.stdout, sys.stderr):
        enc = getattr(stream, "encoding", None) or "ascii"
        try:
            "✅❌⚠ℹ→—…".encode(enc)
        except (LookupError, UnicodeEncodeError):
            if stream is sys.stdout:
                unicode_ok = False
        try:
            stream.reconfigure(errors="replace")  # last-resort safety net
        except (AttributeError, ValueError):
            pass
    return unicode_ok


ASCII_MAP = str.maketrans({"→": "->", "—": "-", "–": "-", "…": "...", "·": "-",
                           "“": '"', "”": '"', "‘": "'", "’": "'"})
UNICODE_ICONS = {"FAIL": "❌", "WARN": "⚠️ ", "PASS": "✅", "INFO": "ℹ️ "}
ASCII_ICONS = {"FAIL": "[FAIL]", "WARN": "[WARN]", "PASS": "[PASS]", "INFO": "[INFO]"}


UA = "launch-audit/1.0 (+security self-check)"
TIMEOUT = 15
EVIL_ORIGIN = "https://evil.launch-audit.invalid"

PROBE_PATHS = [
    ("/.env", lambda b: re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", b) and b"<html" not in b.lower()),
    ("/.env.local", lambda b: re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", b) and b"<html" not in b.lower()),
    ("/.env.production", lambda b: re.search(rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", b) and b"<html" not in b.lower()),
    ("/.git/HEAD", lambda b: b.startswith(b"ref:") or re.match(rb"^[0-9a-f]{40}\s*$", b)),
    ("/.git/config", lambda b: b"[core]" in b),
    ("/.DS_Store", lambda b: b[:8] == b"\x00\x00\x00\x01Bud1"),
    ("/backup.zip", lambda b: b[:2] == b"PK"),
    ("/backup.sql", lambda b: re.search(rb"(?i)(create table|insert into)", b[:20000])),
    ("/dump.sql", lambda b: re.search(rb"(?i)(create table|insert into)", b[:20000])),
    ("/db.sqlite", lambda b: b.startswith(b"SQLite format 3")),
    ("/phpinfo.php", lambda b: b"phpinfo()" in b or b"PHP Version" in b),
    ("/server-status", lambda b: b"Apache Server Status" in b),
    ("/config.json", lambda b: re.search(rb"(?i)\"(secret|password|api_?key|private)", b) and b"<html" not in b.lower()),
    ("/wp-config.php.bak", lambda b: b"DB_PASSWORD" in b),
    ("/.vscode/sftp.json", lambda b: b"password" in b.lower()),
    ("/docker-compose.yml", lambda b: b"services:" in b),
    ("/swagger.json", lambda b: b"\"swagger\"" in b or b"\"openapi\"" in b),
    ("/openapi.json", lambda b: b"\"openapi\"" in b),
    ("/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D", lambda b: b"__schema" in b and b"types" in b),
    ("/admin", None),       # reported if 200 without auth redirect
    ("/api/admin", None),
]

TRACKERS = {
    "googletagmanager.com": "Google Tag Manager / GA4", "google-analytics.com": "Google Analytics",
    "connect.facebook.net": "Meta Pixel", "static.hotjar.com": "Hotjar", "clarity.ms": "Microsoft Clarity",
    "cdn.segment.com": "Segment", "js.hs-scripts.com": "HubSpot", "snap.licdn.com": "LinkedIn Insight",
    "analytics.tiktok.com": "TikTok Pixel", "posthog": "PostHog", "cdn.mxpnl.com": "Mixpanel",
    "fullstory.com": "FullStory", "cdn.logrocket": "LogRocket", "doubleclick.net": "Google Ads",
}
CONSENT_HINTS = re.compile(r"(?i)cookiebot|onetrust|cookieconsent|cookie-consent|consentmanager|iubenda|termly|klaro|"
                           r"usercentrics|didomi|axeptio|complianz|osano|cookiehub|gtag\(\s*['\"]consent['\"]")
LEGAL_LINKS = {
    "LEG-101 Privacy policy": re.compile(r"(?i)privacy|privacidade|privacidad|datenschutz|confidentialit"),
    "LEG-102 Terms": re.compile(r"(?i)terms|termos|t[eé]rminos|\bagb\b|conditions"),
    "LEG-104 Cookie policy/settings": re.compile(r"(?i)cookie"),
    "LEG-105 Business details / imprint": re.compile(r"(?i)imprint|impressum|legal|aviso legal|livro de reclama|contact|contacto"),
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def make_opener():
    ctx = ssl.create_default_context()
    return urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ctx),
                                       urllib.request.ProxyHandler())


OPENER = make_opener()


def fetch(url, headers=None, max_bytes=300_000, method="GET"):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})}, method=method)
    try:
        resp = OPENER.open(req, timeout=TIMEOUT)
        status, hdrs = resp.status, resp.headers
        body = resp.read(max_bytes)
    except urllib.error.HTTPError as e:
        status, hdrs = e.code, e.headers
        try:
            body = e.read(max_bytes)
        except Exception:
            body = b""
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}", "url": url}
    return {"status": status, "headers": hdrs, "body": body or b"", "url": url}


def follow(url, headers=None, limit=6):
    chain = []
    for _ in range(limit):
        r = fetch(url, headers)
        chain.append(r)
        if "error" in r or r["status"] not in (301, 302, 303, 307, 308):
            break
        loc = r["headers"].get("Location")
        if not loc:
            break
        url = urllib.parse.urljoin(url, loc)
    return chain


class Report:
    def __init__(self):
        self.items = []

    def add(self, status, ref, title, detail=""):
        self.items.append({"status": status, "ref": ref, "title": title, "detail": detail})


def check(url, probe=True):
    rep = Report()
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urllib.parse.urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # --- main page ---------------------------------------------------------
    chain = follow(url)
    final = chain[-1]
    if "error" in final:
        rep.add("FAIL", "SEC-501", "Could not load the site", final["error"])
        return rep, None
    rep.add("INFO", "-", f"Final URL {final['url']} → HTTP {final['status']}",
            " → ".join(f"{c.get('status', 'ERR')} {c['url']}" for c in chain))

    # A redirect to another host (not just www. ↔ apex) is usually a login/SSO page
    # (Cloudflare Access, Auth0, Okta...). Its headers and HTML are the provider's, not the site's:
    # check the last response the target itself sent, and skip the HTML checks.
    def bare(host):
        host = host.lower()
        return host[4:] if host.startswith("www.") else host
    final_host = urllib.parse.urlparse(final["url"]).netloc
    other_host = bare(final_host) != bare(parsed.netloc)
    if other_host:
        own = [c for c in chain if "error" not in c
               and bare(urllib.parse.urlparse(c["url"]).netloc) == bare(parsed.netloc)]
        final = own[-1]
        rep.add("INFO", "-", f"Redirects to another host ({final_host}), probably a login page",
                f"HSTS checked on the HTTP {final['status']} from {final['url']}; HTML checks skipped "
                f"(run again with the final URL if that is your site)")
    if not final["url"].startswith("https://"):
        rep.add("FAIL", "SEC-501", "Site is not served over HTTPS")

    # --- http -> https -----------------------------------------------------
    http_chain = follow("http://" + parsed.netloc + (parsed.path or "/"))
    hfirst = http_chain[0]
    if "error" in hfirst:
        rep.add("INFO", "SEC-501", "Plain HTTP not reachable (fine if port 80 is closed)", hfirst["error"])
    elif hfirst["status"] in (301, 302, 307, 308) and str(hfirst["headers"].get("Location", "")).startswith("https://"):
        rep.add("PASS", "SEC-501", f"HTTP redirects to HTTPS ({hfirst['status']})")
    else:
        rep.add("FAIL", "SEC-501", "HTTP does not redirect to HTTPS", f"status {hfirst.get('status')}")

    h = final["headers"]

    def hv(name):
        return h.get(name) or ""

    # --- headers -----------------------------------------------------------
    hsts = hv("Strict-Transport-Security")
    m = re.search(r"max-age=(\d+)", hsts)
    if not hsts:
        rep.add("WARN" if other_host else "FAIL", "SEC-501", "Missing Strict-Transport-Security (HSTS)",
                "on the login redirect; check the app's own responses after logging in" if other_host else "")
    elif m and int(m.group(1)) < 15552000:
        rep.add("WARN", "SEC-501", "HSTS max-age below 180 days", hsts)
    else:
        rep.add("PASS", "SEC-501", "HSTS present", hsts)

    if other_host:
        rep.add("INFO", "SEC-502", "Behind a login on another host: headers, cookies and CORS not checked",
                "they would describe the login redirect, not the app; check them with a logged-in browser")
    else:
        csp = hv("Content-Security-Policy")
        csp_ro = hv("Content-Security-Policy-Report-Only")
        if not csp:
            rep.add("FAIL" if not csp_ro else "WARN", "SEC-502",
                    "Missing Content-Security-Policy" + (" (report-only present)" if csp_ro else ""))
        else:
            weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'", " * ", "data: *") if w in f" {csp} "]
            if "script-src" not in csp and "default-src" not in csp:
                weak.append("no script-src/default-src")
            rep.add("WARN" if weak else "PASS", "SEC-502", "Content-Security-Policy present" + (f" but weak: {', '.join(weak)}" if weak else ""), csp[:300])
        frame_ok = "frame-ancestors" in csp or hv("X-Frame-Options").upper() in ("DENY", "SAMEORIGIN")
        rep.add("PASS" if frame_ok else "FAIL", "SEC-502", "Clickjacking protection (frame-ancestors / X-Frame-Options)",
                hv("X-Frame-Options") or ("frame-ancestors in CSP" if frame_ok else "missing"))
        rep.add("PASS" if hv("X-Content-Type-Options").lower() == "nosniff" else "FAIL", "SEC-502",
                "X-Content-Type-Options: nosniff", hv("X-Content-Type-Options") or "missing")
        rp = hv("Referrer-Policy")
        rep.add("PASS" if rp and rp.lower() not in ("unsafe-url", "no-referrer-when-downgrade") else "WARN", "SEC-502",
                "Referrer-Policy", rp or "missing (browser default applies)")
        rep.add("PASS" if hv("Permissions-Policy") else "WARN", "SEC-502", "Permissions-Policy",
                hv("Permissions-Policy")[:200] or "missing")
        leaks = [f"{k}: {hv(k)}" for k in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")
                 if hv(k)]
        if re.search(r"\d", hv("Server")):
            leaks.append(f"Server: {hv('Server')}")
        rep.add("WARN" if leaks else "PASS", "SEC-502", "Version-revealing headers", "; ".join(leaks) or "none")

        # --- cookies -----------------------------------------------------------
        cookies = h.get_all("Set-Cookie") or []
        for c in cookies:
            name = c.split("=", 1)[0].strip()
            low = c.lower()
            missing = [f for f, ok in (("HttpOnly", "httponly" in low), ("Secure", "secure" in low),
                                       ("SameSite", "samesite" in low)) if not ok]
            sessiony = re.search(r"(?i)sess|auth|token|sid|jwt|login", name)
            if missing:
                rep.add("FAIL" if sessiony else "WARN", "SEC-205", f"Cookie `{name}` missing {', '.join(missing)}",
                        "looks like a session cookie" if sessiony else "check whether it's sensitive")
            else:
                rep.add("PASS", "SEC-205", f"Cookie `{name}` has HttpOnly, Secure, SameSite")
        if not cookies:
            rep.add("INFO", "SEC-205", "No cookies set on the landing page (check again after logging in)")

        # --- CORS ---------------------------------------------------------------
        cr = fetch(final["url"], headers={"Origin": EVIL_ORIGIN})
        if "error" not in cr:
            acao = cr["headers"].get("Access-Control-Allow-Origin", "")
            acac = cr["headers"].get("Access-Control-Allow-Credentials", "")
            if acao == EVIL_ORIGIN and acac.lower() == "true":
                rep.add("FAIL", "SEC-503", "CORS reflects any Origin WITH credentials", f"ACAO={acao}, ACAC={acac}")
            elif acao == EVIL_ORIGIN:
                rep.add("WARN", "SEC-503", "CORS reflects any Origin", f"ACAO={acao}")
            elif acao == "*":
                rep.add("WARN", "SEC-503", "CORS allows all origins (*) — fine for public static content only")
            else:
                rep.add("PASS", "SEC-503", "CORS does not trust a foreign origin on the landing page",
                        "test your API endpoints too")

    # --- HTML analysis -----------------------------------------------------
    html = final["body"].decode("utf-8", "ignore")
    is_html = not other_host and ("<html" in html.lower() or "<!doctype html" in html.lower())
    if is_html:
        mixed = sorted(set(re.findall(r"(?i)(?:src|href)\s*=\s*['\"](http://[^'\"]+)", html)))
        mixed = [u for u in mixed if not re.search(r"(?i)\.(dtd|xsd)$|w3\.org|schema\.org", u)]
        rep.add("FAIL" if mixed else "PASS", "SEC-501", "Mixed content (http:// resources)", ", ".join(mixed[:5]))

        found_trackers = sorted({v for k, v in TRACKERS.items() if k in html})
        consent = bool(CONSENT_HINTS.search(html))
        if found_trackers:
            rep.add("WARN", "LEG-201",
                    "Trackers referenced in initial HTML: " + ", ".join(found_trackers),
                    ("consent tool detected — verify trackers don't fire before consent" if consent
                     else "no consent tool detected — likely tracking before consent (EU/UK)"))
        rep.add("PASS" if consent else "WARN", "LEG-201",
                "Consent management detected" if consent else "No consent management detected in initial HTML",
                "client-rendered banners may not show here — verify in a browser")

        anchors = re.findall(r"(?is)<a\b[^>]*href\s*=\s*['\"]([^'\"]*)['\"][^>]*>(.*?)</a>", html)
        hay = " ".join(f"{hrefv} {re.sub('<[^>]+>', ' ', txt)}" for hrefv, txt in anchors)
        for label, rx in LEGAL_LINKS.items():
            ok = bool(rx.search(hay))
            rep.add("PASS" if ok else "WARN", label.split()[0], f"Link to {label.split(' ', 1)[1]} on landing page",
                    "" if ok else "not found in server HTML (may be client-rendered — check the footer)")

        if not re.search(r"(?i)<html[^>]*\blang\s*=", html):
            rep.add("WARN", "A11Y-4", "<html> has no lang attribute")
        imgs = re.findall(r"(?is)<img\b[^>]*>", html)
        no_alt = [i for i in imgs if not re.search(r"(?i)\salt(?=\s*=|\s|/?>)", i)]
        if imgs:
            rep.add("FAIL" if no_alt else "PASS", "A11Y-1", f"Images without alt: {len(no_alt)}/{len(imgs)}",
                    "; ".join(x[:80] for x in no_alt[:3]))
        if re.search(r"(?i)user-scalable\s*=\s*no|maximum-scale\s*=\s*1(\.0)?\b", html):
            rep.add("WARN", "A11Y-4", "Viewport blocks zoom (user-scalable=no / maximum-scale=1)")

        # source maps
        scripts = re.findall(r"(?i)<script[^>]+src\s*=\s*['\"]([^'\"]+\.js)(?:\?[^'\"]*)?['\"]", html)
        same_origin = [urllib.parse.urljoin(final["url"], s) for s in scripts]
        same_origin = [s for s in same_origin if urllib.parse.urlparse(s).netloc == parsed.netloc][:3]
        exposed_maps = []
        for s in same_origin:
            mr = fetch(s + ".map", max_bytes=2000)
            if "error" not in mr and mr["status"] == 200 and b"\"sources\"" in mr["body"]:
                exposed_maps.append(s + ".map")
            time.sleep(0.2)
        if same_origin:
            rep.add("WARN" if exposed_maps else "PASS", "SEC-104", "Public JavaScript source maps",
                    ", ".join(exposed_maps) or "none found on first scripts")
        # secrets in first-party JS
        secret_rx = re.compile(r"(sk_live_[0-9a-zA-Z]{20,}|sk-ant-[A-Za-z0-9_\-]{20,}|sk-(?:proj-)?[A-Za-z0-9_\-]{32,}|"
                               r"AKIA[0-9A-Z]{16}|sb_secret_[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{36,})")
        hits = []
        for s in same_origin:
            jr = fetch(s, max_bytes=3_000_000)
            if "error" in jr:
                continue
            for mm in secret_rx.finditer(jr["body"].decode("utf-8", "ignore")):
                hits.append(f"{s}: {mm.group(0)[:4]}****")
            if b"service_role" in jr["body"]:
                hits.append(f"{s}: contains 'service_role'")
            time.sleep(0.2)
        if same_origin:
            rep.add("FAIL" if hits else "PASS", "SEC-101", "Secrets in first-party JS bundles (first scripts only)",
                    "; ".join(hits[:5]) or "none found")

    # --- exposed files -------------------------------------------------------
    if probe:
        baseline = fetch(origin + "/launch-audit-" + hashlib.sha1(str(time.time()).encode()).hexdigest()[:10])
        base_hash = hashlib.sha1(baseline.get("body", b"")).hexdigest() if "error" not in baseline else None
        exposed = []
        for path, validator in PROBE_PATHS:
            r = fetch(origin + path, max_bytes=50_000)
            time.sleep(0.15)
            if "error" in r or r["status"] != 200:
                continue
            body = r["body"]
            if base_hash and hashlib.sha1(body).hexdigest() == base_hash:
                continue  # SPA catch-all
            if validator is None:
                low = body.lower()
                if b"<form" in low and (b"password" in low or b"login" in low or b"sign in" in low):
                    continue  # login page = protected
                exposed.append(f"{path} (200 — confirm it requires auth)")
            elif validator(body):
                exposed.append(path)
        sev_paths = [p for p in exposed if "confirm" not in p]
        if sev_paths:
            rep.add("FAIL", "SEC-105", "Sensitive files publicly reachable", ", ".join(sev_paths))
        soft = [p for p in exposed if "confirm" in p]
        if soft:
            rep.add("WARN", "SEC-105", "Admin-like routes return 200", ", ".join(soft))
        if not exposed:
            rep.add("PASS", "SEC-105", f"No common sensitive files exposed ({len(PROBE_PATHS)} paths probed)")
    return rep, final


def main():
    ap = argparse.ArgumentParser(description="launch-audit live site check")
    ap.add_argument("url")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--ascii", action="store_true", help="plain ASCII output (no emoji)")
    args = ap.parse_args()
    unicode_ok = setup_console() and not args.ascii
    rep, _ = check(args.url, probe=not args.no_probe)
    order = {"FAIL": 0, "WARN": 1, "PASS": 2, "INFO": 3}
    items = sorted(rep.items, key=lambda i: order.get(i["status"], 9))
    if args.json:
        print(json.dumps({"url": args.url, "results": items}, indent=2))  # ensure_ascii: always safe
    else:
        icon = UNICODE_ICONS if unicode_ok else ASCII_ICONS

        def emit(text=""):
            print(text if unicode_ok else text.translate(ASCII_MAP))

        emit(f"# launch-audit live check — {args.url}\n")
        emit("Only run against sites you own or are authorized to test.\n")
        for i in items:
            det = f" — {i['detail']}" if i["detail"] else ""
            emit(f"{icon.get(i['status'], '')} [{i['ref']}] {i['title']}{det}")
    sys.exit(1 if any(i["status"] == "FAIL" for i in rep.items) else 0)


if __name__ == "__main__":
    main()
