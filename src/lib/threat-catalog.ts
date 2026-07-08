// Curated catalog of the 6 biggest real-world email / messaging threats for 2025-2026.
// Sources cited inline; figures reflect public reports (FBI IC3 2025, Verizon DBIR 2025,
// Europol IOCTA 2026, Google Advisory June 2026, UK Action Fraud, Keepnet Labs).

export type ThreatCard = {
  id: string;
  title: string;
  tagline: string;
  loss: string;                     // headline loss/impact figure
  trend: string;                    // year-over-year change
  sources: string[];                // short attribution list
  techniques: string[];             // how the attack actually works
  detection: string[];              // signals MailGuard looks for
  userAction: string[];             // what the end user should do
  mapsTo: string;                   // which pipeline component handles it
  color: "critical" | "danger" | "warn";
};

export const THREAT_CATALOG: ThreatCard[] = [
  {
    id: "gmail_ato",
    title: "Gmail Account Takeover",
    tagline: "AiTM phishing, calendar-invite lures, and ClickFix fake-update prompts targeting Gmail directly.",
    loss: "$580B global fraud losses in 2025 · ~1 in 5 adults hit",
    trend: "Gmail used in 73.5% of BEC scams in Q1 2025 (vs 81% Q4 2024)",
    sources: ["Google Advisory Jun 2026", "DeepStrike AtomicMail"],
    techniques: [
      "Adversary-in-the-Middle proxy pages that harvest session cookies live.",
      "Malicious Google Calendar invites with embedded phishing links.",
      "ClickFix — fake browser/OS update dialog that runs paste-to-PowerShell.",
    ],
    detection: [
      "Header check: mismatched Received / From / Return-Path domains.",
      "URLs pointing to lookalike Google login shells (accounts-google-*.tld).",
      "Calendar (.ics) attachments with untrusted event organizers.",
    ],
    userAction: [
      "Never paste any command a webpage tells you to run.",
      "Decline unexpected calendar invites and revoke them from Google Calendar.",
      "Turn on 2-Step Verification with a security key or passkey — AiTM defeats OTP but not FIDO2.",
    ],
    mapsTo: "analyze-email.functions.ts · header + link scoring",
    color: "critical",
  },
  {
    id: "otp_bank_fraud",
    title: "Bank OTP Fraud via Email",
    tagline: "Emails impersonating your bank asking you to 'confirm' an OTP or click a login link.",
    loss: "$20.9B FBI IC3 losses in 2025 (+26% YoY) · BEC alone $3B / 24,768 complaints",
    trend: "OTP-relay scams via email now co-ordinated with real-time phone calls.",
    sources: ["FBI IC3 2025", "Keepnet Labs"],
    techniques: [
      "Sender spoofs bank domain or uses a homoglyph (rn-vs-m, 1-vs-l).",
      "Urgency language ('account will be suspended in 24 hours').",
      "Embedded login link → attacker-controlled page that captures username + OTP.",
    ],
    detection: [
      "Bank brand keywords + urgency triggers + login link fired together.",
      "SPF/DKIM/DMARC failure on a message claiming to be from a bank.",
      "New / young domain age on the click-through URL.",
    ],
    userAction: [
      "Banks never ask for OTPs by email. Delete on sight.",
      "Log in only via the app you already have installed, never via mail link.",
      "Report to RBI Sachet and cybercrime.gov.in within 24h to freeze the transfer.",
    ],
    mapsTo: "explainable.py · email_auth + ocr signals",
    color: "critical",
  },
  {
    id: "ai_phishing",
    title: "AI-Powered Phishing Links",
    tagline: "LLM-crafted, polymorphic emails that mutate per victim to evade filters.",
    loss: "$215.8M reported phishing/spoofing losses in 2025 (3× 2024's $70M)",
    trend: "+400% successful phishing scams attributed to AI · 92% of polymorphic attacks use AI",
    sources: ["DeepStrike", "Bright Defense"],
    techniques: [
      "Body text rewritten per recipient — traditional signature filters miss it.",
      "URLs rotated via automated domain generation (DGA).",
      "Fake-CEO tone-matching after scraping LinkedIn.",
    ],
    detection: [
      "AI-vs-AI: MailGuard's Gemini classifier looks at intent, not fingerprints.",
      "Link reputation scanner (Safe Browsing + VirusTotal + PhishTank feeds).",
      "Domain-age & registrar reputation surfaced per-URL.",
    ],
    userAction: [
      "Assume perfect grammar means nothing anymore. Verify the request out-of-band.",
      "Use a password manager — it refuses to autofill on lookalike domains.",
    ],
    mapsTo: "analyze-email.functions.ts (Gemini) + threat-intel.functions.ts",
    color: "danger",
  },
  {
    id: "quishing",
    title: "QR Code Scams (Quishing)",
    tagline: "QR codes inside PDFs, images or fake internal memos that lead to phishing pages.",
    loss: "$2.3M single-campaign loss reported at a financial institution",
    trend: "+587% QR-phishing reports in the UK (2023→2025) · Europol IOCTA flags fastest-rising",
    sources: ["UK Action Fraud", "Europol IOCTA 2026", "FastestPass"],
    techniques: [
      "QR embedded in an image/PDF so URL scanners never see the link.",
      "Redirects to a mobile-optimized credential harvester.",
      "Sometimes points at malicious APK for Android sideload.",
    ],
    detection: [
      "MailGuard extracts QR content from attached images/PDFs and re-runs it through link intelligence.",
      "Attachment OCR pipeline (pyzbar + pytesseract) surfaces both text and QR payloads.",
    ],
    userAction: [
      "Preview the decoded URL before opening; never install APKs from a QR.",
      "For internal notices (payroll, printer, MFA reset), confirm on the corporate portal.",
    ],
    mapsTo: "services/qr/decoder.py + workers/qr_tasks.py",
    color: "danger",
  },
  {
    id: "sqli_links",
    title: "SQL Injection & Malicious Links",
    tagline: "Emails link to weaponized pages that pop the site the moment you visit.",
    loss: "Vulnerability exploitation = 20% of breaches · Ransomware in 44% of breaches",
    trend: "Verizon DBIR 2025: exploited-vuln entry vectors doubled YoY",
    sources: ["Verizon DBIR 2025", "DeXpose"],
    techniques: [
      "Link parameters carry SQLi / XSS payload against a vulnerable site.",
      "Drive-by exploit chains fire on outdated browsers.",
      "Long redirect chains hide the final malicious domain.",
    ],
    detection: [
      "URL analyzer flags suspicious query parameters (union/select, <script>, %27, ../).",
      "Redirect-chain resolution + final domain reputation check.",
    ],
    userAction: [
      "Keep browser + OS on auto-update.",
      "Hover to inspect the real URL; distrust anything long, encoded, or with query blobs.",
    ],
    mapsTo: "services/url_scan/scanner.py + lib/link-intel.ts",
    color: "warn",
  },
  {
    id: "session_hijack",
    title: "Multi-Device Session Hijacking",
    tagline: "Infostealer malware harvests cookies so attackers log in as you without a password.",
    loss: "~16 billion exposed login records across ~30 datasets in 2025",
    trend: "Gmail credentials a large share of the leaked mix",
    sources: ["Cybersecurity Ventures"],
    techniques: [
      "Malicious download → infostealer (RedLine, Lumma, Raccoon) grabs browser cookies.",
      "Cookie replayed from attacker's browser: skips password AND MFA.",
      "Follow-on: mailbox rules created to auto-forward incoming OTPs.",
    ],
    detection: [
      "Trusted-device panel: alerts on new device / new geo signing into the account.",
      "Post-scan check for silent mailbox forwarding rules (Gmail integration).",
    ],
    userAction: [
      "Sign out of all sessions when you see an unknown device.",
      "Rotate passwords + revoke OAuth apps after any suspected infostealer hit.",
    ],
    mapsTo: "lib/devices.functions.ts + services/gmail/sync.py",
    color: "critical",
  },
];
