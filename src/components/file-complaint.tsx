import { useMemo, useState } from "react";
import {
  FileWarning, Copy, Check, Mail as MailIcon, ExternalLink, Download, ShieldAlert, Phone,
} from "lucide-react";
import type { EmailAnalysis } from "@/lib/analyze-email.functions";

/**
 * FileComplaintPanel
 * Generates a professional cyber-crime complaint pre-populated with the scan data
 * and gives the victim 3 one-click paths to submit it to the responsible Indian
 * government agencies:
 *   1. National Cyber Crime Reporting Portal — https://cybercrime.gov.in  (I4C, MHA)
 *   2. CERT-In phishing intake — report@phishing.gov.in
 *   3. CERT-In incident intake — incident@cert-in.org.in
 * Every complaint is timestamped, structured, and includes the technical evidence
 * (verdict, risk score, indicators, suspicious URLs, attack category) so the
 * responsible officer can act without asking follow-up questions.
 */

export type ComplaintContext = {
  sender: string;
  subject: string;
  body: string;
  channel: "email" | "social";
  analysis: EmailAnalysis;
  reporterName?: string;
  reporterEmail?: string;
};

function buildComplaint(ctx: ComplaintContext): { subject: string; body: string } {
  const a = ctx.analysis;
  const now = new Date();
  const stamp = now.toLocaleString("en-IN", { timeZone: "Asia/Kolkata", hour12: false });
  const channelLabel = ctx.channel === "social" ? "Social-media / messaging" : "Email";
  const evidenceUrls = a.suspiciousLinks.map((l, i) => `  ${i + 1}. ${l.url}  [risk: ${l.risk}]  — ${l.reason}`).join("\n") || "  (none)";
  const indicators = a.indicators.map((i, k) => `  ${k + 1}. [${i.severity.toUpperCase()}] ${i.category} — ${i.detail}`).join("\n") || "  (none)";
  const recs = a.recommendations.map((r, i) => `  ${i + 1}. ${r}`).join("\n") || "  (none)";
  const bodyPreview = (ctx.body || "").slice(0, 1500);

  const subject =
    `Cyber-crime complaint — ${a.verdict.toUpperCase()} (${a.attackCategory}) — filed via MailGuard @ ${stamp} IST`;

  const body =
`To,
The Incident Response Officer,
Indian Computer Emergency Response Team (CERT-In) / I4C, Ministry of Home Affairs
Government of India

Subject: ${subject}

Sir / Madam,

I am filing this complaint regarding a suspected cyber-fraud / phishing attempt
that was received by me on ${channelLabel}. The message was analysed by
MailGuard (an AI-based phishing / fraud detection tool) and classified as
'${a.verdict.toUpperCase()}' with a risk score of ${a.riskScore}/100
and a confidence of ${a.confidence}%.
Kindly investigate and take appropriate action under the Information Technology
Act, 2000 and the Bharatiya Nyaya Sanhita, 2023 (sections dealing with
cheating, forgery and identity theft).

────────────────────────────────────────────
1. COMPLAINANT DETAILS
────────────────────────────────────────────
Name         : ${ctx.reporterName || "[to be filled by complainant]"}
Email        : ${ctx.reporterEmail || "[to be filled by complainant]"}
Date / time  : ${stamp} (IST)
Reporting    : Voluntary, via MailGuard cyber-defence assistant

────────────────────────────────────────────
2. ARTIFACT DETAILS
────────────────────────────────────────────
Channel      : ${channelLabel}
Sender / from: ${ctx.sender || "(not provided)"}
Subject      : ${ctx.subject || "(not provided)"}
Attack type  : ${a.attackCategory}

────────────────────────────────────────────
3. AI VERDICT (evidence)
────────────────────────────────────────────
Verdict      : ${a.verdict.toUpperCase()}
Risk score   : ${a.riskScore} / 100
Confidence   : ${a.confidence}%

Summary:
${a.summary}

────────────────────────────────────────────
4. TECHNICAL INDICATORS DETECTED
────────────────────────────────────────────
${indicators}

────────────────────────────────────────────
5. MALICIOUS / SUSPICIOUS URLs
────────────────────────────────────────────
${evidenceUrls}

────────────────────────────────────────────
6. RAW MESSAGE CONTENT (first 1500 chars)
────────────────────────────────────────────
${bodyPreview || "(no textual body — attachment-only content)"}

────────────────────────────────────────────
7. REQUESTED ACTION
────────────────────────────────────────────
${recs}

I request the honourable authority to:
  a) Block / take-down the URLs and sender identifiers listed above.
  b) Add these indicators of compromise to the national threat-intel feed
     so other citizens are protected.
  c) Investigate the perpetrator under the applicable provisions of the IT Act.

I confirm that the information furnished above is true and correct to the best
of my knowledge and I am aware that furnishing false information is punishable
under law.

Yours sincerely,
${ctx.reporterName || "[Complainant]"}
${ctx.reporterEmail || ""}

--
Generated automatically by MailGuard — https://mailguard.app
Timestamp: ${now.toISOString()}
`;
  return { subject, body };
}

export function FileComplaintPanel({ ctx }: { ctx: ComplaintContext }) {
  const [copied, setCopied] = useState(false);
  const { subject, body } = useMemo(() => buildComplaint(ctx), [ctx]);

  // Only file for real threats — safe mail should not spam government inboxes.
  if (ctx.analysis.verdict === "safe") return null;

  const mailto = `mailto:report@phishing.gov.in?cc=incident@cert-in.org.in&subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

  async function copyAndOpenPortal() {
    try { await navigator.clipboard.writeText(body); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { /* ignore */ }
    window.open("https://cybercrime.gov.in/Accept.aspx", "_blank", "noreferrer");
  }

  function downloadTxt() {
    const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyber-complaint-${Date.now()}.txt`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }

  async function copyOnly() {
    try { await navigator.clipboard.writeText(body); setCopied(true); setTimeout(() => setCopied(false), 2000); } catch { /* ignore */ }
  }

  return (
    <section className="mt-6 rounded-md border p-4"
             style={{ borderColor: "var(--danger)", background: "color-mix(in oklab, var(--danger) 8%, transparent)" }}>
      <header className="flex items-center gap-2 mb-2">
        <FileWarning className="h-4 w-4" style={{ color: "var(--danger)" }} />
        <h4 className="text-sm font-semibold">Auto-file a cyber-crime complaint</h4>
        <span className="ml-auto text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Govt. of India · I4C · CERT-In</span>
      </header>
      <p className="text-xs text-muted-foreground leading-relaxed">
        A structured, professional complaint has been drafted with every evidence field the officer needs
        (sender, subject, verdict, indicators, malicious URLs, timestamp). Submit it in one click to the
        National Cyber Crime Reporting Portal and CERT-In. Your data never leaves your device until you submit.
      </p>

      <div className="mt-3 flex flex-wrap gap-2">
        <a href={mailto}
           className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-2 rounded-md"
           style={{ background: "var(--danger)", color: "var(--primary-foreground)" }}>
          <MailIcon className="h-3.5 w-3.5" /> Email to CERT-In (report@phishing.gov.in)
        </a>
        <button onClick={copyAndOpenPortal}
                className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-2 rounded-md border"
                style={{ borderColor: "var(--danger)", color: "var(--danger)" }}>
          <ExternalLink className="h-3.5 w-3.5" /> Open cybercrime.gov.in (complaint copied)
        </button>
        <button onClick={downloadTxt}
                className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-2 rounded-md border border-border hover:bg-accent">
          <Download className="h-3.5 w-3.5" /> Download .txt
        </button>
        <button onClick={copyOnly}
                className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-2 rounded-md border border-border hover:bg-accent">
          {copied ? <Check className="h-3.5 w-3.5" style={{ color: "var(--safe)" }} /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy complaint"}
        </button>
      </div>

      <div className="mt-3 grid sm:grid-cols-3 gap-2 text-[11px]">
        <a href="tel:1930" className="flex items-center gap-1.5 rounded-md border border-border px-2.5 py-2 hover:bg-accent">
          <Phone className="h-3.5 w-3.5" style={{ color: "var(--danger)" }} />
          <span><span className="font-mono font-semibold">1930</span> · Cyber-crime helpline (24×7)</span>
        </a>
        <a href="tel:18001114949" className="flex items-center gap-1.5 rounded-md border border-border px-2.5 py-2 hover:bg-accent">
          <Phone className="h-3.5 w-3.5" style={{ color: "var(--danger)" }} />
          <span><span className="font-mono font-semibold">1800-11-4949</span> · CERT-In 24×7</span>
        </a>
        <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer"
           className="flex items-center gap-1.5 rounded-md border border-border px-2.5 py-2 hover:bg-accent">
          <ShieldAlert className="h-3.5 w-3.5" style={{ color: "var(--warn)" }} />
          <span>cybercrime.gov.in — I4C portal</span>
        </a>
      </div>

      <details className="mt-3">
        <summary className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground cursor-pointer">
          Preview complaint text
        </summary>
        <pre className="mt-2 rounded-md border border-border bg-background/50 p-3 text-[11px] font-mono whitespace-pre-wrap leading-relaxed max-h-72 overflow-auto">
{body}
        </pre>
      </details>
    </section>
  );
}
