# Legal, privacy & accessibility checklist

> **Not legal advice.** Requirements depend on where the business is established and where users are. This list targets the common baseline for the EU/UK (GDPR, ePrivacy, consumer law), the US (FTC Act, state privacy laws, COPPA, CAN-SPAM) and app stores. Flag anything high-stakes for a lawyer. When a rule's details matter (thresholds, dates, which state law applies), verify against the current official source rather than memory.

Contents:
1. Legal documents (LEG-1xx)
2. Consent (LEG-2xx)
3. Data practices & user rights (LEG-3xx)
4. Honest marketing & pricing (LEG-4xx)
5. Children (LEG-5xx)
6. Email & messaging (LEG-6xx)
7. Intellectual property (LEG-7xx)
8. Accessibility (A11Y-x)

---

## 1. Legal documents

All documents must be easy to find (footer on every page, in the app's settings, and in the app-store listing where required), dated, written in plain language, and available in the languages of the markets you sell in.

### LEG-101 · Privacy policy
Must match what the app **really** does — build it from the data inventory, not a template. Cover: who the controller is and how to contact them (plus DPO/EU representative if required); what data is collected and from where; purposes and legal basis for each (EU/UK); retention periods; recipients and processors (list categories, ideally named: hosting, analytics, payments, email, AI providers); international transfers and safeguards; user rights and how to exercise them; cookies/tracking (or link to cookie policy); children; how changes are announced; right to complain to a supervisory authority (EU/UK). US state laws (e.g. California) add disclosures such as categories collected, "sale/sharing" and opt-out links where applicable.
App stores also require a privacy policy URL and accurate privacy labels (Apple App Privacy, Google Play Data safety) — these must agree with the policy and the SDK audit (LEG-303).

### LEG-102 · Terms of service
Who the provider is; what the service does; eligibility/age; account rules; acceptable use; user content licence and moderation; payment, renewal and cancellation terms; IP ownership; disclaimers and liability limits (consumer law limits what you can exclude — you can't waive statutory consumer rights in the EU/UK); termination; governing law and disputes; how changes are notified. Users should actively accept at sign-up/checkout, and you should record which version they accepted.

### LEG-103 · Refund policy
Required whenever you sell anything. Must state the real process and timelines and must not undercut statutory rights: in the EU/UK, distance sales generally carry a 14-day withdrawal right; for digital content/services it can be lost only with the consumer's express consent and acknowledgement before supply begins — collect that at checkout if you rely on it. Subscriptions: explain renewal, cancellation and pro-rating. App-store purchases follow the store's refund process — say so.

### LEG-104 · Cookie policy
List every cookie and similar technology (localStorage, pixels, SDK identifiers): name, provider, purpose, duration, category (strictly necessary / preferences / analytics / marketing). Can be part of the privacy policy. Keep it in sync with what the site really sets — check DevTools → Application on a fresh profile.

### LEG-105 · Business details
Show legal name, registered address, company/registration number, VAT number (if registered) and a working contact email. EU e-commerce rules require these for online services; many countries add more (e.g. Portugal requires providers to show the electronic complaints book — *Livro de Reclamações Eletrónico* — and information about alternative dispute resolution entities). An "Imprint"/"Legal" page or footer block covers it.

---

## 2. Consent

### LEG-201 · Cookie consent banner (EU/UK and other opt-in markets)
- No non-essential cookies, pixels or SDK tracking **before** consent. Verify: load the site in a clean profile, don't click anything, and check network requests and cookies.
- "Reject all" is as easy and prominent as "Accept all" (same layer, same weight).
- Granular choices by category; no pre-ticked boxes; consent is not "by continuing to browse".
- Consent is recorded (time, version, choices) and can be changed or withdrawn as easily as given (a persistent "Cookie settings" link).
- Use Google Consent Mode v2 (or equivalent) if running Google ads/analytics in the EEA.
- US: honor opt-out signals such as Global Privacy Control where state laws require it.

### LEG-202 · Form consents are valid
- Each optional purpose (newsletter, marketing, sharing with partners) has its own **unticked** checkbox, separate from accepting the terms.
- Consent isn't a condition of service unless strictly needed.
- The form says what happens with the data (short notice + link to the privacy policy).
- Store proof: timestamp, what text was shown, source form, IP/user ID.
- Sensitive data (health, biometrics, etc.) needs explicit consent or another specific legal basis.

---

## 3. Data practices & user rights

### LEG-301 · Collect only needed data (data minimization)
Every field on every form and every tracked event must have a purpose. Remove "nice to have" fields (date of birth, phone, gender, address) unless used. Set retention and delete or anonymize old data automatically. Don't log personal data unnecessarily.

### LEG-302 · Data deletion option
- Users can delete their account and associated data. **Apple requires in-app account deletion** for apps that allow account creation; **Google Play requires** an in-app path and a web link for deletion requests.
- Deletion must cascade: DB rows, storage files, search indexes, third-party processors (email lists, analytics user profiles, CRM), backups expire within the stated window.
- Also support access/export ("download my data") and correction requests, with a defined response time (GDPR: one month).

### LEG-303 · Third-party SDK and service audit
Inventory every SDK, script and API that receives user data: analytics, ads, attribution, crash reporting, session replay, chat widgets, fonts/CDNs, maps, payments, email, AI providers. For each: what data it gets, purpose, whether it needs consent, data processing agreement signed, data location/transfer mechanism. Remove what isn't used. Session replay and ad SDKs are frequent problems: they may capture form inputs or share data for advertising. Make sure the privacy policy and app-store privacy labels list them.

---

## 4. Honest marketing & pricing

### LEG-401 · No dark patterns
Remove: confirm-shaming ("No, I don't want to save money"), pre-ticked add-ons, sneaking items into the basket, fake countdown timers or fake scarcity ("only 2 left" when false), forced continuity (trial auto-converting without clear notice), roach motels (sign up in one click, cancel only by phone), nagging, hidden opt-outs, disguised ads, misleading button hierarchy. Cancellation should be as easy as sign-up, online, and reachable without a maze. EU (Digital Services Act, consumer law) and US (FTC) regulators actively enforce against these.

### LEG-402 · No hidden fees
Show the total price including mandatory fees and taxes (EU: consumer prices must include VAT) up front, not only at the last checkout step. Disclose recurring charges, renewal price after an introductory offer, trial end date, and shipping costs before the user commits. "Free" must mean free.

### LEG-403 · No fake reviews or testimonials
No invented reviews, paid reviews without disclosure, reviews from employees/family presented as independent, suppressing negative reviews, or AI-generated testimonials. Influencer/affiliate content must be disclosed as such. In the EU you must say whether and how you check that reviews come from real customers; the US FTC rule on consumer reviews and testimonials bans fake ones explicitly.

### LEG-404 · No unsupported claims
Every factual claim needs evidence on file before publishing: "#1", "best", "fastest", "military-grade encryption", "100% secure", "GDPR compliant", "used by 10,000 teams", health/financial results, "AI-powered" when it isn't, environmental claims ("eco-friendly", "carbon neutral"). Remove or rephrase what you can't prove. Comparative claims about competitors must be accurate and verifiable.

---

## 5. Children

### LEG-501 · Age gate and parental consent
- Decide: is the service directed at children, or could they realistically use it? If not, say so in the terms and add a neutral age gate (ask date of birth without hinting the "right" answer) where appropriate.
- If children may use it: US COPPA requires verifiable parental consent before collecting personal data from children under 13; under GDPR, where consent is the legal basis for an online service offered to a child, parental consent is needed below the national digital-consent age (13–16 depending on the EU country — check the target country). UK Age Appropriate Design Code applies to services likely to be accessed by children.
- Defaults for minors: high privacy, no profiling-based ads, no public location, no nudging.
- App stores: kids' categories carry extra SDK and ad restrictions.

---

## 6. Email & messaging

### LEG-601 · Unsubscribe link
Every marketing email has a clear, working unsubscribe link that works without logging in, processed promptly (CAN-SPAM: within 10 business days; good practice: immediately). Bulk senders to Gmail/Yahoo need one-click unsubscribe (`List-Unsubscribe` + `List-Unsubscribe-Post` headers) plus SPF, DKIM and DMARC. Include sender identity and a physical postal address (CAN-SPAM). EU/UK: marketing emails need prior consent (or the soft opt-in for existing customers and similar products, with an opt-out each time). Transactional emails must not be used to smuggle marketing.

---

## 7. Intellectual property

### LEG-701 · Licensed images, fonts, icons, audio, video
Every asset has a licence that covers commercial use in this context: stock photos (keep the licence/receipt), illustrations, icon sets, fonts (desktop vs web/app embedding licences differ), music, video, mockups, AI-generated images (check the generator's terms). Remove images pulled from Google search, Pinterest or competitors. Attribute where the licence requires (e.g. Creative Commons BY).

### LEG-702 · Open-source licence compliance
Run a licence check (`npx license-checker --summary`, `pip-licenses`). Copyleft licences (GPL/AGPL) can impose obligations on distributed or network-served software. Include required notices (an "Open source licences" screen in mobile apps).

### LEG-703 · Trademarks and naming
Check the app/brand name and logo against trademark registers (EUIPO, USPTO, national office) and app stores before launch; don't use others' marks in a way that suggests endorsement.

---

## 8. Accessibility

Target **WCAG 2.2 level AA**. Beyond being the right thing, it's legally relevant: the European Accessibility Act applies to many consumer digital services (e-commerce, banking, e-books, transport, communications) in the EU from June 2025 (micro-enterprises providing services are exempt), and US ADA lawsuits over inaccessible websites are common.

### A11Y-1 · Alt text
Informative images have concise `alt` describing their purpose; decorative images have `alt=""` (or are CSS backgrounds); icon-only buttons have an accessible name (`aria-label`); images of text are avoided; charts have a text alternative. Mobile: `accessibilityLabel` / `contentDescription` / `semanticsLabel`.

### A11Y-2 · Colour contrast
Text ≥ **4.5:1** against its background (≥ **3:1** for large text: 24px regular or ~18.66px bold); UI components and focus indicators ≥ **3:1**; information not conveyed by colour alone (errors need text/icon, not only red). Check dark mode, disabled-but-readable states, placeholder text and text over images. Tools: axe DevTools, Lighthouse, WebAIM contrast checker.

### A11Y-3 · Keyboard navigation
Everything works with keyboard alone: logical tab order, visible focus indicator, no keyboard traps, modals trap focus while open and return it on close, `Esc` closes dialogs, a "skip to content" link, custom widgets use native elements or correct ARIA roles. Test: unplug the mouse and complete sign-up and checkout.

### A11Y-4 · Forms and structure (bonus, frequently failed)
Labels tied to inputs (placeholder is not a label); errors announced and described in text; one `h1` and a logical heading order; `lang` attribute set; page titles unique; text resizes to 200% without loss; touch targets ≥ 24×24 CSS px; respects `prefers-reduced-motion`; captions for video.

Automated tools catch only part of the problems — finish with a manual keyboard pass and a quick screen-reader pass (VoiceOver/NVDA/TalkBack). Do not rely on accessibility overlay widgets; they don't make a site compliant.
