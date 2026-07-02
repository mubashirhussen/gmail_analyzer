import { useMemo, useState } from "react";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertTriangle, ShieldCheck, ExternalLink, BookOpen, Database, Trash2,
  FileDown, FileText as FileTextIcon, ShieldAlert, Globe2, Phone, Mail as MailIcon,
  Lock, Loader2, KeyRound,
} from "lucide-react";
import type { HistoryItem } from "@/lib/secure-store";

/* ---------------- AI Recommendation modal ---------------- */

export type RecommendationContext = {
  recommendation: string;
  verdict: HistoryItem["verdict"];
  riskScore: number;
  topIndicators: { category: string; severity: string; detail: string }[];
  // text of the analyzed email (body) so we can highlight matched indicators
  emailText: string;
  // substrings to highlight inside emailText (URLs, sender, keywords from indicators)
  matches: string[];
};

export function RecommendationModal({
  open, onOpenChange, ctx,
}: { open: boolean; onOpenChange: (v: boolean) => void; ctx: RecommendationContext | null }) {
  if (!ctx) return null;
  const safeAction = nextSafeAction(ctx);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl bg-card border-border max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" style={{ color: "var(--safe)" }} />
            AI Recommendation
          </DialogTitle>
          <DialogDescription className="text-foreground/90 pt-1">{ctx.recommendation}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4 mt-2">
          <section>
            <h4 className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono mb-2">Why this matters</h4>
            <p className="text-sm text-foreground/90">
              The email scored <span className="font-mono font-semibold">{ctx.riskScore}/100</span> ({ctx.verdict.toUpperCase()}).
              {ctx.topIndicators.length > 0 && " The following signals drove this advice:"}
            </p>
            {ctx.topIndicators.length > 0 && (
              <ul className="mt-2 space-y-1.5">
                {ctx.topIndicators.slice(0, 4).map((i, idx) => (
                  <li key={idx} className="text-xs flex items-start gap-2">
                    <AlertTriangle className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" style={{ color: "var(--warn)" }} />
                    <span><span className="font-semibold">{i.category}</span> — {i.detail}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {ctx.emailText.trim().length > 0 && (
            <section>
              <h4 className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono mb-2">
                Matched signals in your email
              </h4>
              <pre className="rounded-md border border-border bg-background/50 p-3 text-xs font-mono whitespace-pre-wrap leading-relaxed max-h-64 overflow-auto">
                <Highlighted text={ctx.emailText} matches={ctx.matches} />
              </pre>
              {ctx.matches.length === 0 && (
                <p className="text-[11px] text-muted-foreground mt-1">No literal matches found — the verdict is based on higher-level patterns the AI detected.</p>
              )}
            </section>
          )}

          <section className="rounded-md border border-border p-3" style={{ background: "color-mix(in oklab, var(--safe) 10%, transparent)" }}>
            <h4 className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono mb-1">Safest next action</h4>
            <p className="text-sm font-medium">{safeAction}</p>
          </section>
        </div>

        <DialogFooter>
          <button onClick={() => onOpenChange(false)}
                  className="rounded-md px-4 py-2 text-sm font-semibold"
                  style={{ background: "var(--safe)", color: "var(--primary-foreground)" }}>
            Got it
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Highlighted({ text, matches }: { text: string; matches: string[] }) {
  if (matches.length === 0) return <>{text}</>;
  const escaped = matches
    .filter((m) => m && m.trim().length >= 3)
    .map((m) => m.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  if (escaped.length === 0) return <>{text}</>;
  const re = new RegExp(`(${escaped.join("|")})`, "gi");
  const parts = text.split(re);
  return (
    <>
      {parts.map((p, i) =>
        re.test(p)
          ? <mark key={i} style={{ background: "color-mix(in oklab, var(--critical) 35%, transparent)", color: "var(--foreground)", padding: "0 2px", borderRadius: 3 }}>{p}</mark>
          : <span key={i}>{p}</span>,
      )}
    </>
  );
}

function nextSafeAction(ctx: RecommendationContext): string {
  const r = ctx.recommendation.toLowerCase();
  if (r.includes("link") || r.includes("url") || r.includes("click")) return "Do not click any link. Type the official site URL into the browser manually.";
  if (r.includes("password") || r.includes("credential")) return "Change your password from the official site and enable 2-factor authentication.";
  if (r.includes("attachment") || r.includes("download")) return "Do not open the attachment. Delete the email and report it to your IT / abuse team.";
  if (r.includes("verify") || r.includes("identity")) return "Verify by calling the organization on a number from their official website — never the number in the email.";
  if (r.includes("report") || r.includes("forward")) return "Forward the email to report@phishing.gov.in (India CERT-In) and your mail provider's abuse address.";
  if (ctx.verdict === "safe") return "Looks clean. Still avoid clicking links you didn't expect.";
  return "Delete the email, do not reply, and report it to your IT team or India CERT-In (incident@cert-in.org.in).";
}

/* ---------------- Change passcode dialog ---------------- */

export function ChangePasscodeDialog({
  open, onOpenChange, onSubmit,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onSubmit: (current: string, next: string) => Promise<void>;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    if (next !== confirmPw) { setErr("New passcodes don't match."); return; }
    if (next.length < 6) { setErr("New passcode must be at least 6 characters."); return; }
    setBusy(true);
    try {
      await onSubmit(current, next);
      setDone(true);
      setTimeout(() => {
        setDone(false); setCurrent(""); setNext(""); setConfirmPw("");
        onOpenChange(false);
      }, 1100);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed.");
    } finally { setBusy(false); }
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!busy) { onOpenChange(v); if (!v) { setErr(null); setCurrent(""); setNext(""); setConfirmPw(""); } } }}>
      <DialogContent className="max-w-md bg-card border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4" style={{ color: "var(--safe)" }} />
            Change passcode
          </DialogTitle>
          <DialogDescription>
            Your encrypted mail history is re-encrypted with the new passcode immediately.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-3 mt-1">
          <PwField label="Current passcode" value={current} onChange={setCurrent} />
          <PwField label="New passcode (min 6 chars)" value={next} onChange={setNext} />
          <PwField label="Confirm new passcode" value={confirmPw} onChange={setConfirmPw} />
          {err && (
            <div className="text-xs rounded-md border px-3 py-2"
                 style={{ borderColor: "var(--critical)", color: "var(--critical)", background: "oklch(0.20 0.04 25 / 30%)" }}>
              {err}
            </div>
          )}
          {done && (
            <div className="text-xs rounded-md border px-3 py-2"
                 style={{ borderColor: "var(--safe)", color: "var(--safe)", background: "color-mix(in oklab, var(--safe) 10%, transparent)" }}>
              Passcode updated. History re-encrypted.
            </div>
          )}
          <DialogFooter>
            <button type="submit" disabled={busy}
                    className="inline-flex items-center justify-center gap-2 rounded-md px-4 py-2 text-sm font-semibold disabled:opacity-50"
                    style={{ background: "var(--safe)", color: "var(--primary-foreground)" }}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
              Update passcode
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function PwField({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <div>
      <label className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono">{label}</label>
      <input type="password" value={value} onChange={(e) => onChange(e.target.value)}
             className="mt-1 w-full rounded-md bg-input/60 border border-border px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-ring/60 focus:border-ring" />
    </div>
  );
}

/* ---------------- CERT-In awareness ---------------- */

export function CertInPanel() {
  return (
    <div className="panel p-5 space-y-3">
      <header className="flex items-center gap-2">
        <ShieldAlert className="h-4 w-4" style={{ color: "var(--warn)" }} />
        <h3 className="text-sm font-semibold">India CERT-In — Cyber Defence</h3>
      </header>
      <p className="text-xs text-muted-foreground leading-relaxed">
        The Indian Computer Emergency Response Team (CERT-In) under MeitY is India's national nodal agency
        for responding to cyber security incidents. Report phishing, fraud and malware to them.
      </p>
      <ul className="text-xs space-y-2">
        <li className="flex items-start gap-2"><MailIcon className="h-3.5 w-3.5 mt-0.5" style={{ color: "var(--safe)" }} />
          Phishing reports: <code className="font-mono">report@phishing.gov.in</code></li>
        <li className="flex items-start gap-2"><MailIcon className="h-3.5 w-3.5 mt-0.5" style={{ color: "var(--safe)" }} />
          Incidents: <code className="font-mono">incident@cert-in.org.in</code></li>
        <li className="flex items-start gap-2"><Phone className="h-3.5 w-3.5 mt-0.5" style={{ color: "var(--safe)" }} />
          Cyber-crime helpline: <code className="font-mono">1930</code> (24×7)</li>
        <li className="flex items-start gap-2"><Phone className="h-3.5 w-3.5 mt-0.5" style={{ color: "var(--danger)" }} />
          CERT-In direct emergency: <a className="font-mono underline" href="tel:+911122902657">+91-11-2290-2657</a></li>
        <li className="flex items-start gap-2"><Globe2 className="h-3.5 w-3.5 mt-0.5" style={{ color: "var(--safe)" }} />
          File a complaint:&nbsp;
          <a className="underline" href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">cybercrime.gov.in</a>
        </li>
        <li className="flex items-start gap-2"><ExternalLink className="h-3.5 w-3.5 mt-0.5" style={{ color: "var(--safe)" }} />
          Advisories: <a className="underline" href="https://www.cert-in.org.in" target="_blank" rel="noreferrer">cert-in.org.in</a>
        </li>
      </ul>
    </div>
  );
}

/* ---------------- Security tips ---------------- */

const TIPS: { title: string; body: string }[] = [
  { title: "Verify the sender domain", body: "Look for misspellings & swapped characters (paypa1.com, micros0ft.com). Hover the address — display name can lie." },
  { title: "Never trust urgency", body: "“Account suspended in 24 hours”, “last warning”, “immediate action” are pressure tactics used by fraudsters." },
  { title: "Type URLs manually", body: "Don't click login links from emails. Open a new tab and type the official URL yourself." },
  { title: "Enable 2-factor auth", body: "Even if a password leaks, 2FA (preferably an authenticator app or hardware key) blocks most takeovers." },
  { title: "Never share OTP / PIN", body: "Banks, UPI apps, RBI, income tax, courier services never ask for OTP, CVV or PIN over email/call." },
  { title: "Inspect attachments", body: "Be wary of .zip, .html, .iso, macro-enabled Office files. When in doubt, scan with VirusTotal before opening." },
  { title: "Keep software patched", body: "Update OS, browser, and antivirus. Most malware exploits known, already-patched flaws." },
  { title: "Use unique passwords", body: "A password manager (Bitwarden, 1Password) makes per-site unique passwords painless." },
  { title: "Report, don't just delete", body: "Forward phishing to report@phishing.gov.in and your provider's abuse address — it helps protect others." },
];

export function SecurityTipsPanel() {
  return (
    <div className="panel p-5">
      <header className="flex items-center gap-2 mb-3">
        <BookOpen className="h-4 w-4" style={{ color: "var(--safe)" }} />
        <h3 className="text-sm font-semibold">Stay safe — key awareness points</h3>
      </header>
      <ul className="grid sm:grid-cols-2 gap-3">
        {TIPS.map((t) => (
          <li key={t.title} className="rounded-md border border-border bg-card/50 p-3">
            <div className="text-sm font-semibold flex items-center gap-2">
              <ShieldCheck className="h-3.5 w-3.5" style={{ color: "var(--safe)" }} />
              {t.title}
            </div>
            <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{t.body}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ---------------- Data & privacy ---------------- */

export function DataPrivacyPanel({
  accountEmail, accountUsername, historyCount,
  onClearHistory, onDeleteAccount, onLockNow, onChangePasscode,
}: {
  accountEmail: string; accountUsername: string; historyCount: number;
  onClearHistory: () => void; onDeleteAccount: () => void;
  onLockNow: () => void; onChangePasscode: () => void;
}) {
  return (
    <div className="panel p-5 space-y-4">
      <header className="flex items-center gap-2">
        <Database className="h-4 w-4" style={{ color: "var(--safe)" }} />
        <h3 className="text-sm font-semibold">Data & Privacy</h3>
      </header>

      <div className="text-xs text-muted-foreground leading-relaxed">
        Everything below lives <span className="font-semibold text-foreground">only on this device</span>,
        inside your browser's local storage. It never leaves the browser.
      </div>

      <ul className="text-xs space-y-2">
        <li><span className="font-mono text-muted-foreground">account</span> · username + email (plain)
          — <span className="font-mono">{accountUsername}</span>, <span className="font-mono">{accountEmail}</span></li>
        <li><span className="font-mono text-muted-foreground">verifier</span> · AES-GCM-encrypted token used to validate your passcode</li>
        <li><span className="font-mono text-muted-foreground">history</span> · {historyCount} scanned email{historyCount === 1 ? "" : "s"} — AES-GCM encrypted with your passcode-derived key</li>
        <li><span className="font-mono text-muted-foreground">forwarded mail content</span> · only sent to the AI engine for the current scan, never stored on a server</li>
      </ul>

      <div className="rounded-md border border-border p-3 text-xs space-y-1">
        <div className="font-semibold">How encryption works here</div>
        <p className="text-muted-foreground">
          Your passcode is run through PBKDF2-SHA256 (150,000 iterations) to derive a 256-bit AES-GCM key.
          The key only lives in memory while you are unlocked. After <span className="font-semibold text-foreground">10 minutes of inactivity</span> the app
          auto-locks and the key is wiped — you must re-enter the passcode to view your history again. Forget the passcode and the data is mathematically unrecoverable.
        </p>
      </div>

      <div className="rounded-md border border-border p-3 text-xs space-y-1">
        <div className="font-semibold">Sign out from other devices</div>
        <p className="text-muted-foreground">
          MailGuard accounts are <span className="font-semibold text-foreground">per-device</span> — there is no central server,
          so other browsers / phones each hold their own encrypted copy. To revoke them:
        </p>
        <ol className="text-muted-foreground mt-1 list-decimal list-inside space-y-0.5">
          <li><span className="font-semibold text-foreground">Change your passcode</span> below — old exported history files can no longer be decrypted with the previous passcode.</li>
          <li>On the suspected device, open MailGuard → menu → <span className="font-semibold">Delete account + all data</span>.</li>
          <li>If you can't reach the device, clear its browser site-data for this app.</li>
        </ol>
      </div>

      <div className="flex flex-wrap gap-2 pt-1">
        <button onClick={onLockNow}
                className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-2 rounded-md border border-border hover:bg-accent">
          <Lock className="h-3.5 w-3.5" /> Lock now
        </button>
        <button onClick={onChangePasscode}
                className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-2 rounded-md border border-border hover:bg-accent">
          <KeyRound className="h-3.5 w-3.5" /> Change passcode
        </button>
        <button onClick={onClearHistory}
                className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-2 rounded-md border border-border hover:bg-accent">
          <Trash2 className="h-3.5 w-3.5" /> Clear scan history
        </button>
        <button onClick={onDeleteAccount}
                className="inline-flex items-center gap-1.5 text-xs font-semibold px-3 py-2 rounded-md"
                style={{ background: "var(--critical)", color: "var(--destructive-foreground)" }}>
          <Trash2 className="h-3.5 w-3.5" /> Delete account + all data
        </button>
      </div>
    </div>
  );
}

/* ---------------- History panel ---------------- */

export function HistoryPanel({ history, onExportCSV, onExportPDF }: {
  history: HistoryItem[];
  onExportCSV: () => void;
  onExportPDF: () => void;
}) {
  const [q, setQ] = useState("");
  const filtered = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (!t) return history;
    return history.filter((h) =>
      h.subject.toLowerCase().includes(t) ||
      h.sender.toLowerCase().includes(t) ||
      h.summary.toLowerCase().includes(t),
    );
  }, [q, history]);

  return (
    <div className="panel p-5">
      <header className="flex items-center justify-between gap-2 mb-3 flex-wrap">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <FileTextIcon className="h-4 w-4" /> Scan history ({history.length})
        </h3>
        <div className="flex gap-2">
          <button onClick={onExportCSV} disabled={history.length === 0}
                  className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-md border border-border hover:bg-accent disabled:opacity-40">
            <FileDown className="h-3.5 w-3.5" /> CSV
          </button>
          <button onClick={onExportPDF} disabled={history.length === 0}
                  className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-md border border-border hover:bg-accent disabled:opacity-40">
            <FileDown className="h-3.5 w-3.5" /> PDF
          </button>
        </div>
      </header>

      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search subject, sender, summary…"
             className="w-full mb-3 rounded-md bg-input/60 border border-border px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-ring/60" />

      {filtered.length === 0 ? (
        <p className="text-xs text-muted-foreground">No scans yet.</p>
      ) : (
        <ul className="space-y-2 max-h-[480px] overflow-auto">
          {filtered.map((h) => (
            <li key={h.id} className="rounded-md border border-border bg-card/50 px-3 py-2">
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-sm font-semibold truncate">{h.subject || "(no subject)"}</div>
                  <div className="text-[11px] text-muted-foreground font-mono truncate">{h.sender || "(no sender)"} · {new Date(h.at).toLocaleString()}</div>
                </div>
                <span className="text-xs font-mono font-semibold"
                      style={{ color: verdictColor(h.verdict) }}>{h.verdict.toUpperCase()} · {h.riskScore}</span>
              </div>
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{h.summary}</p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function verdictColor(v: HistoryItem["verdict"]) {
  return v === "safe" ? "var(--safe)" : v === "suspicious" ? "var(--warn)" : v === "phishing" ? "var(--danger)" : "var(--critical)";
}

/* ---------------- Export helpers ---------------- */

export function exportHistoryCSV(items: HistoryItem[], username: string) {
  const headers = ["timestamp", "verdict", "riskScore", "confidence", "sender", "subject", "summary", "indicators", "suspiciousLinks", "recommendations"];
  const esc = (s: string) => `"${(s || "").replace(/"/g, '""')}"`;
  const rows = items.map((h) => [
    new Date(h.at).toISOString(),
    h.verdict, String(h.riskScore), String(h.confidence),
    esc(h.sender), esc(h.subject), esc(h.summary),
    esc(h.indicators.map((i) => `[${i.severity}] ${i.category}: ${i.detail}`).join(" | ")),
    esc(h.suspiciousLinks.map((l) => `[${l.risk}] ${l.url} — ${l.reason}`).join(" | ")),
    esc(h.recommendations.join(" | ")),
  ].join(","));
  const csv = [headers.join(","), ...rows].join("\n");
  download(`mailguard-${username}-history.csv`, "text/csv;charset=utf-8", csv);
}

export function exportHistoryPDF(items: HistoryItem[], username: string) {
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>MailGuard history — ${escapeHTML(username)}</title>
  <style>
    body{font-family: ui-sans-serif, system-ui, sans-serif; color:#111; padding:24px; max-width: 800px; margin:auto;}
    h1{font-size:20px; margin:0 0 4px 0;}
    .meta{color:#555; font-size:12px; margin-bottom:24px;}
    .item{border:1px solid #ddd; border-radius:8px; padding:12px 14px; margin-bottom:10px; page-break-inside: avoid;}
    .row{display:flex; justify-content:space-between; gap:12px; align-items:flex-start;}
    .verdict{font-family: ui-monospace, monospace; font-weight:700; font-size:12px;}
    .safe{color:#0a7c43;} .suspicious{color:#a86b00;} .phishing{color:#c0392b;} .fraud{color:#7a0e1f;}
    .sub{font-size:11px; color:#555; font-family: ui-monospace, monospace; margin-top:2px;}
    .summary{font-size:13px; margin:8px 0 6px 0;}
    ul{margin:4px 0 0 18px; padding:0; font-size:12px;}
    h3{font-size:12px; text-transform:uppercase; letter-spacing:.06em; margin:8px 0 4px 0; color:#444;}
    @media print { .noprint{display:none;} }
  </style></head><body>
    <h1>MailGuard — Mail analysis history</h1>
    <div class="meta">Account: ${escapeHTML(username)} · Exported ${new Date().toLocaleString()} · ${items.length} scan(s)</div>
    ${items.map((h) => `
      <div class="item">
        <div class="row">
          <div>
            <div style="font-weight:600;">${escapeHTML(h.subject || "(no subject)")}</div>
            <div class="sub">${escapeHTML(h.sender || "(no sender)")} · ${new Date(h.at).toLocaleString()}</div>
          </div>
          <div class="verdict ${h.verdict}">${h.verdict.toUpperCase()} · ${h.riskScore}/100</div>
        </div>
        <div class="summary">${escapeHTML(h.summary)}</div>
        ${h.indicators.length ? `<h3>Indicators</h3><ul>${h.indicators.map((i) => `<li>[${escapeHTML(i.severity)}] ${escapeHTML(i.category)} — ${escapeHTML(i.detail)}</li>`).join("")}</ul>` : ""}
        ${h.suspiciousLinks.length ? `<h3>Suspicious links</h3><ul>${h.suspiciousLinks.map((l) => `<li>[${escapeHTML(l.risk)}] ${escapeHTML(l.url)} — ${escapeHTML(l.reason)}</li>`).join("")}</ul>` : ""}
        ${h.recommendations.length ? `<h3>Recommendations</h3><ul>${h.recommendations.map((r) => `<li>${escapeHTML(r)}</li>`).join("")}</ul>` : ""}
      </div>
    `).join("")}
    <div class="noprint" style="margin-top:24px;">
      <button onclick="window.print()" style="padding:8px 14px; font-size:13px;">Print / Save as PDF</button>
    </div>
    <script>setTimeout(()=>window.print(), 300);</script>
  </body></html>`;
  const w = window.open("", "_blank");
  if (!w) { alert("Allow pop-ups to export PDF."); return; }
  w.document.open(); w.document.write(html); w.document.close();
}

function escapeHTML(s: string) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

function download(filename: string, mime: string, content: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 0);
}
