# Launch Audit — {{app name}}

**Date:** {{YYYY-MM-DD}} · **Scope:** {{repo / commit SHA / URL}} · **Mode:** {{quick | security | legal | full}}
**Assumptions:** {{markets, audience age, anything assumed because the user wasn't asked}}

## Verdict: {{🔴 Not ready | 🟡 Ready with fixes | 🟢 Ready}}

{{2–3 sentences: the biggest risks and what must happen before launch.}}

| Critical | High | Medium | Low | Manual checks |
|---:|---:|---:|---:|---:|
| {{n}} | {{n}} | {{n}} | {{n}} | {{n}} |

## Stack & data inventory

- **Stack:** {{framework, backend, DB, auth, hosting, platforms}}
- **Personal data collected:** {{fields / events}}
- **Third parties receiving data:** {{SDK/service → data → purpose}}
- **Payments:** {{provider / none}}

## Findings

### 🔴 Critical

#### {{ID}} · {{short title}}
- **Evidence:** `{{file:line}}` / {{URL + header}}
- **Risk:** {{one line — what an attacker or regulator can do}}
- **Fix:**
  ```{{lang}}
  {{concise code or config}}
  ```

### 🟠 High
{{same format}}

### 🟡 Medium
{{same format, can be shorter}}

### ⚪ Low
{{one line each}}

## Needs a human (MANUAL)

| ID | What to check | Who |
|---|---|---|
| {{SEC-702}} | {{Run a restore of last night's backup into a scratch project}} | {{dev}} |
| {{LEG-101}} | {{Lawyer review of the privacy policy for EU + US}} | {{lawyer}} |

## Passed

| Area | Items |
|---|---|
| {{Secrets}} | {{SEC-102, SEC-104}} |

## Fix plan

1. {{Today: Criticals, in order}}
2. {{Before launch: Highs}}
3. {{First month: Mediums}}

*Automated scans find leads, not guarantees. Legal items are not legal advice.*
