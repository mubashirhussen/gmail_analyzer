// Static, honest per-category explainer shown after every scan.
// Answers: "What can this scam actually do to me / my device, and why are we telling you?"
// No fake telemetry — this is curated from CERT-In, Google Safe Browsing, and NCSC guidance.

export type ImpactCard = {
  what: string;              // what the scam is trying to do
  device: string[];          // concrete effects on the user's device / accounts
  data: string[];            // data the attacker can obtain
  reasoning: string;         // why we surface this to the user
};

export const DEVICE_IMPACT: Record<string, ImpactCard> = {
  credential_theft: {
    what: "Trick you into typing your password / OTP into a fake login page.",
    device: [
      "No malware installed on your device — the theft happens on the fake page.",
      "Attacker signs in as you from their own device, often within minutes.",
      "If you reuse the password, every other account with the same password is now exposed.",
    ],
    data: ["Email/username", "Password", "OTP / 2FA code", "Recovery phone or backup email"],
    reasoning: "Credential-harvesting pages are the #1 initial-access vector for account takeover and follow-on fraud.",
  },
  upi_fraud: {
    what: "Push a UPI collect-request or fake refund to move money out of your account.",
    device: [
      "No device compromise — you approve the payment yourself in your UPI app.",
      "Money debits instantly and is usually pulled out via mule accounts within seconds.",
      "Screenshots of your UPI ID + name are used to run the same scam against your contacts.",
    ],
    data: ["UPI VPA", "Mobile number", "Bank account balance (inferred)", "Contact list of common recipients"],
    reasoning: "RBI and NPCI report UPI collect-request abuse as the fastest-growing consumer fraud in India.",
  },
  bec: {
    what: "Impersonate an executive, vendor, or finance team to redirect a real payment.",
    device: [
      "Usually zero malware — the attack is pure social engineering over email.",
      "Payments go to attacker-controlled bank accounts and are hard to reverse.",
      "Follow-up mails from the same spoofed identity can pull HR records or W-2/PAN data.",
    ],
    data: ["Wire/UPI instructions", "Invoice PDFs", "Employee payroll data", "Vendor contact list"],
    reasoning: "FBI IC3 puts BEC losses above $50B globally — the highest-loss email scam category.",
  },
  job_scam: {
    what: "Fake job / task offer that asks you to pay a fee or deposit money to 'unlock' bigger returns.",
    device: [
      "Attacker may push you to install a Telegram/WhatsApp-linked wallet app.",
      "Malicious 'employer' APKs can request Accessibility permission and read OTPs.",
      "Bank credentials get skimmed once you deposit the 'commission'.",
    ],
    data: ["Aadhaar/PAN", "Bank details", "OTPs", "Selfie/KYC video"],
    reasoning: "CERT-In flagged task-based job scams as the top-reported cyber fraud in 2024.",
  },
  romance: {
    what: "Long-con emotional manipulation to eventually extract money or intimate images.",
    device: [
      "No malware — the attacker builds trust across weeks.",
      "May coerce you into installing a 'private chat' app that exfiltrates photos.",
      "Extortion follow-up uses your own images against you.",
    ],
    data: ["Personal photos/videos", "Location", "Family details", "Financial situation"],
    reasoning: "Romance and sextortion scams have the highest per-victim loss reported to India's I4C helpline.",
  },
  crypto_investment: {
    what: "'Guaranteed returns' group that lets you 'win' a few trades, then blocks withdrawal.",
    device: [
      "Attacker walks you through installing a lookalike exchange app or WalletConnect malware.",
      "Approve-all token contracts drain your entire wallet in one transaction.",
      "Once you deposit fiat, the group blocks you and moves on.",
    ],
    data: ["Wallet seed phrase", "Exchange KYC", "Bank statements", "Signed token approvals"],
    reasoning: "Pig-butchering (Sha Zhu Pan) is the fastest-growing organized crime typology worldwide.",
  },
  courier_delivery: {
    what: "Fake India Post / DHL / BlueDart 'customs fee' or 'address update' SMS/mail.",
    device: [
      "Link opens a page that harvests card details for a tiny ₹25–₹150 'fee'.",
      "Some campaigns push a malicious APK that requests SMS + Accessibility.",
      "Card gets used for high-value CNP transactions within hours.",
    ],
    data: ["Card PAN / CVV / expiry", "OTP", "Home address"],
    reasoning: "Impersonating India Post is one of the most-reported SMS phishing campaigns in India.",
  },
  fake_kyc: {
    what: "Bank/RBI/PAN-Aadhaar 'KYC expired' pressure to hand over full account access.",
    device: [
      "Very often paired with an AnyDesk/TeamViewer install — attacker controls your screen.",
      "OTPs read straight off your screen; funds transferred while you watch.",
      "Follow-up loan fraud may open new credit lines in your name.",
    ],
    data: ["Net banking login", "Debit card", "OTPs", "Aadhaar/PAN", "Full remote control of device"],
    reasoning: "KYC lures combined with remote-access apps are the highest-loss vector reported to RBI Sachet.",
  },
  lottery_prize: {
    what: "'You won X lakh' — pay small processing/GST fees to receive nothing.",
    device: [
      "No malware; pure advance-fee scam.",
      "Repeated 'one more fee' asks until victim disengages.",
      "Personal data resold to other scam rings.",
    ],
    data: ["Aadhaar", "Bank details", "Address"],
    reasoning: "Advance-fee fraud has run for decades because payment psychology beats logic.",
  },
  tech_support: {
    what: "Fake Microsoft/Apple/Amazon 'your device is infected' pop-up or call.",
    device: [
      "Almost always installs remote-access software (AnyDesk, UltraViewer, LogMeIn).",
      "Attacker opens your net-banking and transfers funds in real time.",
      "May leave a backdoor scheduled task even after you disconnect.",
    ],
    data: ["Everything on the screen", "Saved passwords", "Bank accounts", "Files"],
    reasoning: "Tech-support scams have the highest average per-victim loss in the elderly demographic.",
  },
  impersonation: {
    what: "Impersonate a boss, relative, IT, HR, courier, or govt official.",
    device: [
      "Rarely malware — used to extract action (transfer/click/share).",
      "Voice deepfake calls now common: 'beta paisa bhej de'.",
    ],
    data: ["Whatever you send them", "Trust to run follow-on attacks on your contacts"],
    reasoning: "Deepfake voice + WhatsApp impersonation is the fastest-growing family scam in India.",
  },
  malware_attachment: {
    what: "Attached .doc/.pdf/.zip/.iso/.apk that installs malware when opened.",
    device: [
      "Can install a Remote Access Trojan (RAT) with full file/screen/webcam access.",
      "Keyloggers capture every password you type.",
      "Ransomware may encrypt personal files and demand payment.",
      "Some campaigns steal browser cookies to hijack already-logged-in sessions.",
    ],
    data: ["Files on device", "Browser saved passwords", "Session cookies", "Crypto wallets", "Webcam / microphone"],
    reasoning: "Attachment-borne malware remains the #1 initial-access vector for ransomware operators.",
  },
  extortion: {
    what: "Threat of releasing private info / images unless you pay.",
    device: [
      "Usually bluff — attacker has no real access.",
      "In real cases, RAT or leaked breach data may back the threat.",
    ],
    data: ["Money if paid", "Continued extortion demands"],
    reasoning: "Sextortion complaints to India's I4C jumped 200%+ YoY in 2024 — most are bluff, but pressure works.",
  },
  other: {
    what: "Suspicious pattern that doesn't match a known category.",
    device: [
      "Impact depends on what the attacker convinces you to do next.",
      "Never click, install, pay, or share OTP until independently verified.",
    ],
    data: ["Varies"],
    reasoning: "We surface the pattern even when we can't name it — better an unnamed warning than a missed scam.",
  },
};

export function impactFor(category?: string): ImpactCard {
  return DEVICE_IMPACT[category ?? "other"] ?? DEVICE_IMPACT.other;
}

// Deterministic SHA-256 hex of a normalized string (browser Web Crypto).
export async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function normalizeContent(sender: string, subject: string, body: string): string {
  return [sender, subject, body]
    .map((s) => (s ?? "").toLowerCase().replace(/\s+/g, " ").trim())
    .join("\n");
}
