import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useMemo, useState } from "react";
import {
  Shield, ShieldAlert, ShieldCheck, Mail, Link2, AlertTriangle, Activity, Lock,
  Eye, Loader2, Sparkles, Send, TrendingUp, Paperclip, X, FileText, Image as ImageIcon,
  MessageCircle, Target, Radar, ExternalLink, Users, Flag, Info,
} from "lucide-react";
import { analyzeEmail, type EmailAnalysis } from "@/lib/analyze-email.functions";
import { logScanEvent } from "@/lib/devices.functions";
import { enrichUrls, type ThreatIntelResult, type UrlIntel, type ProviderStatus } from "@/lib/threat-intel.functions";
import { reportScam, getReportCounts } from "@/lib/reports.functions";
import { impactFor, sha256Hex, normalizeContent } from "@/lib/device-impact";
import { useAuth } from "@/lib/auth-context";
import { AppMenu, type ViewKey } from "@/components/app-menu";
import { Link } from "@tanstack/react-router";
import {
  CertInPanel, ChangePasscodeDialog, DataPrivacyPanel, HistoryPanel, RecommendationModal, SecurityTipsPanel,
  exportHistoryCSV, exportHistoryPDF, type RecommendationContext,
} from "@/components/panels";
import { extractUrls, scoreLinks, type LinkScore } from "@/lib/link-intel";
import type { HistoryItem } from "@/lib/secure-store";


type Attachment = {
  name: string; mimeType: string; dataBase64: string; textContent?: string; size: number;
};

const MAX_FILE_BYTES = 6 * 1024 * 1024;
const TEXT_MIME_PREFIXES = ["text/", "application/json", "application/xml", "application/csv"];

async function fileToAttachment(file: File): Promise<Attachment> {
  const buf = await file.arrayBuffer();
  let binary = "";
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  const dataBase64 = btoa(binary);
  const att: Attachment = { name: file.name, mimeType: file.type || "application/octet-stream", dataBase64, size: file.size };
  const isTextLike =
    TEXT_MIME_PREFIXES.some((p) => att.mimeType.startsWith(p)) ||
    /\.(txt|md|csv|json|log|eml|html?)$/i.test(file.name);
  if (isTextLike) {
    try { att.textContent = new TextDecoder("utf-8", { fatal: false }).decode(bytes); } catch { /* keep base64 */ }
  }
  return att;
}

export const Route = createFileRoute("/_authenticated/")({
  head: () => ({
    meta: [
      { title: "MailGuard — AI Phishing & Fraud Email Analyzer" },
      { name: "description", content: "Forward any email to MailGuard to instantly detect phishing, fraud, malicious links, and social-engineering attacks." },
      { property: "og:title", content: "MailGuard — AI Phishing & Fraud Email Analyzer" },
      { property: "og:description", content: "Paste any email. Get an instant phishing & fraud verdict, risk score, and protection report." },
    ],
  }),
  component: Page,
});

function Page() {
  const { ready, session } = useAuth();
  if (!ready || !session) return <main className="min-h-screen" />;
  return <Dashboard />;
}


const SAMPLE = {
  sender: "security-alert@paypa1-support.com",
  subject: "URGENT: Your account will be suspended in 24 hours",
  body: `Dear Customer,

We detected unusual sign-in activity on your PayPal account from an unrecognized device in Lagos, Nigeria.
To avoid permanent suspension of your account within the next 24 hours, you MUST verify your identity immediately.

Click here to confirm your details: http://paypa1-verify.secure-login.ru/confirm?id=8821

Failure to act will result in account closure and all funds being frozen.

Sincerely,
PayPal Security Team`,
};

function verdictMeta(v: EmailAnalysis["verdict"]) {
  switch (v) {
    case "safe": return { label: "SAFE", color: "var(--safe)", Icon: ShieldCheck };
    case "suspicious": return { label: "SUSPICIOUS", color: "var(--warn)", Icon: ShieldAlert };
    case "phishing": return { label: "PHISHING", color: "var(--danger)", Icon: ShieldAlert };
    case "fraud": return { label: "FRAUD", color: "var(--critical)", Icon: ShieldAlert };
  }
}
function severityColor(s: string) {
  switch (s) {
    case "low": return "var(--safe)";
    case "medium": return "var(--warn)";
    case "high": return "var(--danger)";
    case "critical": return "var(--critical)";
    default: return "var(--muted-foreground)";
  }
}
function categoryLabel(c: string) {
  return c.replace(/_/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function Dashboard() {
  const { session, history, addHistory, clearHistory, deleteCurrentAccount, switchAccount, logout, lockNow, changePasscode } = useAuth();
  const analyze = useServerFn(analyzeEmail);
  const runEnrich = useServerFn(enrichUrls);
  const logScan = useServerFn(logScanEvent);
  const reportFn = useServerFn(reportScam);
  const countsFn = useServerFn(getReportCounts);
  const [view, setView] = useState<ViewKey>("dashboard");
  const [channel, setChannel] = useState<"email" | "social">("email");
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EmailAnalysis | null>(null);
  const [recCtx, setRecCtx] = useState<RecommendationContext | null>(null);
  const [pwOpen, setPwOpen] = useState(false);
  const [intel, setIntel] = useState<ThreatIntelResult | null>(null);
  const [intelLoading, setIntelLoading] = useState(false);
  const [intelError, setIntelError] = useState<string | null>(null);
  const [contentHash, setContentHash] = useState<string | null>(null);
  const [reportCount, setReportCount] = useState<number>(0);
  const [reporting, setReporting] = useState(false);
  const [reported, setReported] = useState(false);

  const account = session!.account;

  const protectionScore = useMemo(() => {
    if (history.length === 0) return 100;
    const avgRisk = history.reduce((s, h) => s + h.riskScore, 0) / history.length;
    return Math.max(0, Math.round(100 - avgRisk * 0.7));
  }, [history]);

  const stats = useMemo(() => {
    const threats = history.filter((h) => h.verdict !== "safe").length;
    const links = history.reduce((s, h) => s + h.suspiciousLinks.length, 0);
    return { scanned: history.length, threats, links };
  }, [history]);

  // Live link-intelligence on the pasted body (client-side, no AI call).
  const linkScores: LinkScore[] = useMemo(() => scoreLinks(extractUrls(body)), [body]);

  // Reset any previous live-intel result when the pasted URLs change.
  useMemo(() => { setIntel(null); setIntelError(null); }, [body]);

  async function runIntel() {
    const urls = linkScores.slice(0, 10).map((s) => s.url);
    if (urls.length === 0) return;
    setIntelLoading(true); setIntelError(null); setIntel(null);
    try {
      const res = await runEnrich({ data: { urls } });
      setIntel(res);
    } catch (err) {
      setIntelError(err instanceof Error ? err.message : "Live threat check failed.");
    } finally { setIntelLoading(false); }
  }



  async function onFilesPicked(files: FileList | null) {
    if (!files) return;
    setError(null);
    const next: Attachment[] = [];
    for (const f of Array.from(files)) {
      if (f.size > MAX_FILE_BYTES) { setError(`"${f.name}" is larger than 6 MB.`); continue; }
      try { next.push(await fileToAttachment(f)); } catch { setError(`Could not read "${f.name}".`); }
    }
    setAttachments((prev) => [...prev, ...next].slice(0, 5));
  }

  function removeAttachment(i: number) { setAttachments((prev) => prev.filter((_, idx) => idx !== i)); }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setLoading(true); setResult(null);
    setContentHash(null); setReportCount(0); setReported(false);
    try {
      const res = await analyze({
        data: {
          channel,
          sender, subject, body,
          attachments: attachments.map(({ name, mimeType, dataBase64, textContent }) => ({ name, mimeType, dataBase64, textContent })),
        },
      });
      setResult(res);
      const item: HistoryItem = {
        id: crypto.randomUUID(), at: Date.now(),
        sender, subject, bodyPreview: body.slice(0, 280),
        verdict: res.verdict, riskScore: res.riskScore, confidence: res.confidence,
        summary: res.summary, indicators: res.indicators,
        suspiciousLinks: res.suspiciousLinks, recommendations: res.recommendations,
        attackCategory: res.attackCategory, channel,
      };
      await addHistory(item);
      logScan({ data: { verdict: res.verdict, riskScore: res.riskScore, subject, sender } }).catch(() => {});
      // community-report lookup
      try {
        const hash = await sha256Hex(normalizeContent(sender, subject, body));
        setContentHash(hash);
        const { counts } = await countsFn({ data: { hashes: [hash] } });
        setReportCount(counts[hash] ?? 0);
      } catch { /* non-fatal */ }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally { setLoading(false); }
  }

  async function submitReport() {
    if (!contentHash || !result || reporting || reported) return;
    setReporting(true);
    try {
      const r = await reportFn({
        data: {
          hash: contentHash,
          kind: channel === "social" ? "social" : "email",
          category: result.attackCategory,
          verdict: result.verdict,
        },
      });
      setReportCount(r.reportCount);
      setReported(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Report failed.");
    } finally { setReporting(false); }
  }

  function loadSample() {
    if (channel === "social") {
      setSender("WhatsApp · +91 98••• •••21");
      setSubject("(chat)");
      setBody(`Hi beta, this is Aunty from Delhi. I sent ₹4,500 to your GPay by mistake trying to pay the maid. Please approve the collect request I just sent so it comes back to me — urgent! Don't tell mumma, she'll shout. Also here is my new UPI: aunty.rita@ybl bit.ly/gpay-refund`);
    } else {
      setSender(SAMPLE.sender); setSubject(SAMPLE.subject); setBody(SAMPLE.body);
    }
  }


  function openRec(rec: string) {
    if (!result) return;
    const topIndicators = [...result.indicators]
      .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
      .slice(0, 4);
    // Build the list of substrings to highlight inside the email body:
    // every suspicious URL + meaningful keywords from the indicator details
    // + the From address when it appears.
    const matches: string[] = [];
    for (const l of result.suspiciousLinks) if (l.url) matches.push(l.url);
    for (const ind of topIndicators) {
      for (const tok of ind.detail.split(/[\s,;:"'()\[\]<>]+/)) {
        if (tok.length >= 5 && /[a-z0-9]/i.test(tok)) matches.push(tok);
      }
    }
    if (sender) matches.push(sender);
    setRecCtx({
      recommendation: rec, verdict: result.verdict, riskScore: result.riskScore,
      topIndicators, emailText: body, matches: Array.from(new Set(matches)),
    });
  }

  function handleExportCSV() { exportHistoryCSV(history, account.username); }
  function handleExportPDF() { exportHistoryPDF(history, account.username); }

  function handleDeleteAccount() {
    if (!confirm("Permanently delete this account and all encrypted local data?")) return;
    deleteCurrentAccount();
  }
  async function handleClearHistory() {
    if (!confirm("Clear all scan history for this account?")) return;
    await clearHistory();
  }

  return (
    <main className="min-h-screen text-foreground">
      <header className="sticky top-0 z-20 border-b border-border/60 backdrop-blur-md bg-background/70">
        <div className="mx-auto max-w-7xl px-6 py-4 flex items-center justify-between gap-3">
          <button onClick={() => setView("dashboard")} className="flex items-center gap-3">
            <div className="relative">
              <div className="absolute inset-0 rounded-md blur-md" style={{ background: "var(--safe)", opacity: 0.4 }} />
              <div className="relative h-9 w-9 rounded-md border border-border flex items-center justify-center"
                   style={{ background: "linear-gradient(135deg, oklch(0.30 0.06 200), oklch(0.22 0.04 260))" }}>
                <Shield className="h-5 w-5" style={{ color: "var(--safe)" }} />
              </div>
            </div>
            <div className="text-left">
              <h1 className="text-base font-semibold tracking-tight">MailGuard</h1>
              <p className="text-xs text-muted-foreground font-mono">phishing · fraud · link analysis</p>
            </div>
          </button>
          <div className="flex items-center gap-2">
            <span className="hidden md:inline-flex chip" style={{ color: "var(--safe)" }}>
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: "var(--safe)", animation: "pulse-ring 1.6s ease-in-out infinite" }} />
              Engine online
            </span>
            <AppMenu
              username={account.username} email={account.email}
              onNavigate={setView}
              onExportCSV={handleExportCSV} onExportPDF={handleExportPDF}
              onSwitch={switchAccount} onSignOut={logout}
              onLockNow={lockNow} onChangePasscode={() => setPwOpen(true)}
            />
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-6 py-8">
        {view === "dashboard" && (
          <DashboardView
            protectionScore={protectionScore} stats={stats}
            channel={channel} setChannel={setChannel}
            sender={sender} setSender={setSender}
            subject={subject} setSubject={setSubject}
            body={body} setBody={setBody}
            attachments={attachments} onFilesPicked={onFilesPicked} removeAttachment={removeAttachment}
            error={error} loading={loading} onSubmit={onSubmit} loadSample={loadSample}
            result={result} openRec={openRec}
            history={history}
            linkScores={linkScores}
            intel={intel} intelLoading={intelLoading} intelError={intelError} onRunIntel={runIntel}
            reportCount={reportCount} reported={reported} reporting={reporting} onReport={submitReport}
          />
        )}

        {view === "history" && (
          <HistoryPanel history={history} onExportCSV={handleExportCSV} onExportPDF={handleExportPDF} />
        )}
        {view === "certin" && <CertInPanel />}
        {view === "tips" && <SecurityTipsPanel />}
        {view === "privacy" && (
          <DataPrivacyPanel
            accountEmail={account.email} accountUsername={account.username}
            historyCount={history.length}
            onClearHistory={handleClearHistory}
            onDeleteAccount={handleDeleteAccount}
            onLockNow={lockNow}
            onChangePasscode={() => setPwOpen(true)}
          />
        )}
      </div>

      <ChangePasscodeDialog open={pwOpen} onOpenChange={setPwOpen} onSubmit={changePasscode} />

      <RecommendationModal open={recCtx !== null} onOpenChange={(o) => !o && setRecCtx(null)} ctx={recCtx} />
    </main>
  );
}

function severityRank(s: string) {
  return s === "critical" ? 4 : s === "high" ? 3 : s === "medium" ? 2 : 1;
}

function DashboardView(props: {
  protectionScore: number;
  stats: { scanned: number; threats: number; links: number };
  channel: "email" | "social"; setChannel: (v: "email" | "social") => void;
  sender: string; setSender: (v: string) => void;
  subject: string; setSubject: (v: string) => void;
  body: string; setBody: (v: string) => void;
  attachments: Attachment[];
  onFilesPicked: (f: FileList | null) => void;
  removeAttachment: (i: number) => void;
  error: string | null; loading: boolean;
  onSubmit: (e: React.FormEvent) => void; loadSample: () => void;
  result: EmailAnalysis | null;
  openRec: (rec: string) => void;
  history: HistoryItem[];
  linkScores: LinkScore[];
  intel: ThreatIntelResult | null;
  intelLoading: boolean;
  intelError: string | null;
  onRunIntel: () => void;
  reportCount: number;
  reported: boolean;
  reporting: boolean;
  onReport: () => void;
}) {
  const {
    protectionScore, stats, channel, setChannel, sender, setSender, subject, setSubject, body, setBody,
    attachments, onFilesPicked, removeAttachment, error, loading, onSubmit, loadSample,
    result, openRec, history, linkScores,
    intel, intelLoading, intelError, onRunIntel,
    reportCount, reported, reporting, onReport,
  } = props;


  return (
    <div className="grid grid-cols-12 gap-6">
      <aside className="col-span-12 lg:col-span-3 space-y-4">
        <ProtectionMeter score={protectionScore} />
        <StatCard icon={Mail} label="Emails Scanned" value={stats.scanned} accent="var(--safe)" />
        <StatCard icon={AlertTriangle} label="Threats Blocked" value={stats.threats} accent="var(--danger)" />
        <StatCard icon={Link2} label="Suspicious Links" value={stats.links} accent="var(--warn)" />

        <div className="panel p-4">
          <h3 className="text-xs uppercase tracking-wider text-muted-foreground font-mono mb-3">Coverage</h3>
          <ul className="space-y-2 text-sm">
            {["Spoofed sender detection","Malicious URL & homoglyph scan","Credential harvesting patterns",
              "Social-engineering & urgency","Financial scam heuristics","Attachment risk profiling"].map((t) => (
              <li key={t} className="flex items-start gap-2 text-muted-foreground">
                <Lock className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" style={{ color: "var(--safe)" }} />
                <span>{t}</span>
              </li>
            ))}
          </ul>
        </div>
      </aside>

      <section className="col-span-12 lg:col-span-6 space-y-4">
        <div className="panel p-6 scanline">
          <div className="flex items-center justify-between mb-4 gap-3 flex-wrap">
            <div>
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <Sparkles className="h-4 w-4" style={{ color: "var(--safe)" }} />
                {channel === "social" ? "Analyze a message / DM" : "Analyze an email"}
              </h2>
              <p className="text-xs text-muted-foreground mt-1 font-mono">
                {channel === "social"
                  ? "Paste WhatsApp / Instagram / Telegram / SMS content. India-scam patterns applied."
                  : "Paste or forward. Stored locally, encrypted with your passcode."}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <div className="inline-flex rounded-md border border-border p-0.5 text-xs font-mono">
                <button type="button" onClick={() => setChannel("email")}
                  className={`px-2.5 py-1 rounded inline-flex items-center gap-1 ${channel === "email" ? "bg-accent" : "hover:bg-accent/50"}`}>
                  <Mail className="h-3 w-3" /> Email
                </button>
                <button type="button" onClick={() => setChannel("social")}
                  className={`px-2.5 py-1 rounded inline-flex items-center gap-1 ${channel === "social" ? "bg-accent" : "hover:bg-accent/50"}`}>
                  <MessageCircle className="h-3 w-3" /> Social / SMS
                </button>
              </div>
              <button type="button" onClick={loadSample}
                      className="text-xs font-mono px-2.5 py-1 rounded-md border border-border hover:bg-accent transition">
                Load sample
              </button>
            </div>
          </div>

          <form onSubmit={onSubmit} className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Field label={channel === "social" ? "Sender / channel" : "From"}
                     value={sender} onChange={setSender}
                     placeholder={channel === "social" ? "WhatsApp · +91 98••• •••21" : "alerts@bank-update.co"} />
              <Field label={channel === "social" ? "Context (optional)" : "Subject"}
                     value={subject} onChange={setSubject}
                     placeholder={channel === "social" ? "e.g. Telegram group DM" : "Verify your account now"} />
            </div>
            <div>
              <label className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono">
                {channel === "social" ? "Message content" : "Email body"}
              </label>
              <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={10}
                placeholder={channel === "social"
                  ? "Paste the WhatsApp / SMS / Telegram / Instagram message here…"
                  : "Paste the full email content here… (or attach a screenshot / PDF below)"}
                className="mt-1 w-full rounded-md bg-input/60 border border-border px-3 py-2.5 text-sm font-mono leading-relaxed outline-none focus:ring-2 focus:ring-ring/60 focus:border-ring resize-y" />
            </div>

            {linkScores.length > 0 && (
              <LinkIntelTable
                scores={linkScores}
                onRunIntel={onRunIntel}
                intelLoading={intelLoading}
                intelError={intelError}
                intel={intel}
              />
            )}

            <div>
              <div className="flex items-center justify-between">
                <label className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono">
                  Attachments <span className="opacity-60">(images, PDF, docs · up to 5 · 6 MB each)</span>
                </label>
                <label className="inline-flex items-center gap-1.5 text-xs font-mono px-2.5 py-1 rounded-md border border-border hover:bg-accent transition cursor-pointer">
                  <Paperclip className="h-3.5 w-3.5" /> Attach
                  <input type="file" multiple
                    accept="image/*,application/pdf,.txt,.md,.csv,.json,.log,.eml,.html,.htm,.doc,.docx"
                    className="hidden"
                    onChange={(e) => { onFilesPicked(e.target.files); e.target.value = ""; }} />
                </label>
              </div>
              {attachments.length > 0 && (
                <ul className="mt-2 flex flex-wrap gap-2">
                  {attachments.map((a, i) => {
                    const isImg = a.mimeType.startsWith("image/");
                    return (
                      <li key={i} className="inline-flex items-center gap-2 rounded-md border border-border bg-card/60 pl-2 pr-1 py-1 text-xs">
                        {isImg ? <ImageIcon className="h-3.5 w-3.5" style={{ color: "var(--safe)" }} />
                               : <FileText className="h-3.5 w-3.5" style={{ color: "var(--warn)" }} />}
                        <span className="font-mono max-w-[160px] truncate">{a.name}</span>
                        <span className="text-[10px] text-muted-foreground font-mono">{(a.size / 1024).toFixed(0)} KB</span>
                        <button type="button" onClick={() => removeAttachment(i)}
                                className="ml-0.5 p-0.5 rounded hover:bg-accent" aria-label={`Remove ${a.name}`}>
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            {error && (
              <div className="text-sm rounded-md border px-3 py-2"
                   style={{ borderColor: "var(--critical)", color: "var(--critical)", background: "oklch(0.20 0.04 25 / 30%)" }}>
                {error}
              </div>

            )}

            <button type="submit" disabled={loading || (!body.trim() && attachments.length === 0)}
                    className="w-full inline-flex items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-semibold transition disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{ background: "var(--safe)", color: "var(--primary-foreground)", boxShadow: "var(--shadow-glow-safe)" }}>
              {loading ? (<><Loader2 className="h-4 w-4 animate-spin" /> Scanning…</>) : (<><Send className="h-4 w-4" /> Run Threat Scan</>)}
            </button>
          </form>
        </div>

        {result && (
          <AnalysisReport
            result={result} openRec={openRec}
            reportCount={reportCount} reported={reported} reporting={reporting} onReport={onReport}
            channel={channel} sender={sender} subject={subject} body={body}
          />
        )}
      </section>

      <aside className="col-span-12 lg:col-span-3 space-y-4">
        <div className="panel p-4">
          <h3 className="text-xs uppercase tracking-wider text-muted-foreground font-mono mb-3 flex items-center gap-2">
            <Activity className="h-3.5 w-3.5" /> Recent Scans
          </h3>
          {history.length === 0 ? (
            <p className="text-xs text-muted-foreground">No scans yet. Run your first analysis to see results here.</p>
          ) : (
            <ul className="space-y-2">
              {history.slice(0, 8).map((h) => {
                const m = verdictMeta(h.verdict);
                return (
                  <li key={h.id} className="flex items-center justify-between gap-2 rounded-md border border-border/70 px-2.5 py-2 bg-card/50">
                    <div className="flex items-center gap-2 min-w-0">
                      <m.Icon className="h-4 w-4 flex-shrink-0" style={{ color: m.color }} />
                      <span className="text-xs truncate">{h.subject || h.summary}</span>
                    </div>
                    <span className="text-[10px] font-mono font-semibold" style={{ color: m.color }}>{h.riskScore}</span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        <CertInPanel />
      </aside>
    </div>
  );
}

function Field({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div>
      <label className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono">{label}</label>
      <input type="text" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
             className="mt-1 w-full rounded-md bg-input/60 border border-border px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-ring/60 focus:border-ring" />
    </div>
  );
}

function StatCard({ icon: Icon, label, value, accent }: { icon: typeof Mail; label: string; value: number; accent: string }) {
  return (
    <div className="panel p-4 flex items-center gap-3">
      <div className="h-10 w-10 rounded-md flex items-center justify-center border border-border"
           style={{ background: `color-mix(in oklab, ${accent} 12%, transparent)` }}>
        <Icon className="h-4 w-4" style={{ color: accent }} />
      </div>
      <div>
        <div className="text-2xl font-semibold font-mono">{value}</div>
        <div className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono">{label}</div>
      </div>
    </div>
  );
}

function ProtectionMeter({ score }: { score: number }) {
  const color = score >= 75 ? "var(--safe)" : score >= 45 ? "var(--warn)" : "var(--critical)";
  const r = 42; const c = 2 * Math.PI * r; const offset = c - (score / 100) * c;
  return (
    <div className="panel p-5 text-center">
      <h3 className="text-xs uppercase tracking-wider text-muted-foreground font-mono mb-3 flex items-center justify-center gap-2">
        <Eye className="h-3.5 w-3.5" /> Protection Score
      </h3>
      <div className="relative mx-auto h-32 w-32">
        <svg viewBox="0 0 100 100" className="h-full w-full -rotate-90">
          <circle cx="50" cy="50" r={r} fill="none" stroke="var(--border)" strokeWidth="8" />
          <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="8"
                  strokeLinecap="round" strokeDasharray={c} strokeDashoffset={offset}
                  style={{ transition: "stroke-dashoffset 800ms ease, stroke 400ms ease", filter: `drop-shadow(0 0 6px ${color})` }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-3xl font-bold font-mono" style={{ color }}>{score}</div>
          <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">/ 100</div>
        </div>
      </div>
      <p className="mt-3 text-xs text-muted-foreground">Your inbox protection level based on recent scans.</p>
    </div>
  );
}

function AnalysisReport({
  result, openRec, reportCount, reported, reporting, onReport,
  channel, sender, subject, body,
}: {
  result: EmailAnalysis;
  openRec: (r: string) => void;
  reportCount: number;
  reported: boolean;
  reporting: boolean;
  onReport: () => void;
  channel: "email" | "social";
  sender: string;
  subject: string;
  body: string;
}) {
  const { session } = useAuth();
  const m = verdictMeta(result.verdict);
  const isDanger = result.verdict === "phishing" || result.verdict === "fraud";
  return (
    <div className={`panel p-6 ${isDanger ? "glow-danger" : "glow-safe"}`}>
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <div className="h-12 w-12 rounded-md flex items-center justify-center border"
               style={{ borderColor: m.color, background: `color-mix(in oklab, ${m.color} 15%, transparent)` }}>
            <m.Icon className="h-6 w-6" style={{ color: m.color }} />
          </div>
          <div>
            <div className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Verdict</div>
            <div className="text-xl font-bold tracking-tight" style={{ color: m.color }}>{m.label}</div>
            <div className="mt-1.5">
              <AttackCategoryBadge value={result.attackCategory} />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="text-xs font-mono uppercase tracking-wider text-muted-foreground">Risk score</div>
            <div className="text-3xl font-bold font-mono" style={{ color: m.color }}>
              {result.riskScore}<span className="text-base text-muted-foreground">/100</span>
            </div>
          </div>
          <ConfidenceDial value={result.confidence} />
        </div>
      </div>

      <div className="mt-4">
        <div className="h-2 w-full rounded-full overflow-hidden bg-secondary/60 border border-border">
          <div className="h-full rounded-full transition-all duration-700"
               style={{ width: `${result.riskScore}%`, background: `linear-gradient(90deg, var(--safe), var(--warn), var(--danger), var(--critical))` }} />
        </div>
        <div className="flex justify-between text-[10px] font-mono text-muted-foreground mt-1 uppercase">
          <span>Safe</span><span>Suspicious</span><span>Phishing</span><span>Fraud</span>
        </div>
      </div>


      <p className="mt-5 text-sm leading-relaxed">{result.summary}</p>

      <CommunityReportRow
        reportCount={reportCount} reported={reported} reporting={reporting}
        onReport={onReport} verdict={result.verdict}
      />

      <VerdictExplainer result={result} />

      <DeviceImpactPanel category={result.attackCategory} verdict={result.verdict} />

      {result.indicators.length > 0 && (
        <section className="mt-6">
          <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-mono mb-2 flex items-center gap-2">
            <AlertTriangle className="h-3.5 w-3.5" /> Threat indicators ({result.indicators.length})
          </h4>
          <ul className="space-y-2">
            {result.indicators.map((ind, i) => (
              <li key={i} className="rounded-md border border-border bg-card/60 px-3 py-2.5 flex items-start gap-3">
                <span className="mt-0.5 chip text-[10px]"
                      style={{ color: severityColor(ind.severity), borderColor: severityColor(ind.severity) }}>
                  {ind.severity}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold">{categoryLabel(ind.category)}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{ind.detail}</div>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {result.suspiciousLinks.length > 0 && (
        <section className="mt-6">
          <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-mono mb-2 flex items-center gap-2">
            <Link2 className="h-3.5 w-3.5" /> Suspicious links ({result.suspiciousLinks.length})
          </h4>
          <ul className="space-y-2">
            {result.suspiciousLinks.map((l, i) => (
              <li key={i} className="rounded-md border border-border bg-card/60 px-3 py-2.5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="chip text-[10px]" style={{ color: severityColor(l.risk), borderColor: severityColor(l.risk) }}>
                    {l.risk}
                  </span>
                  <code className="text-xs font-mono break-all" style={{ color: "var(--warn)" }}>{l.url}</code>
                </div>
                <div className="text-xs text-muted-foreground mt-1">{l.reason}</div>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="mt-6">
        <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-mono mb-2 flex items-center gap-2">
          <TrendingUp className="h-3.5 w-3.5" /> Recommended actions
          <span className="text-[10px] text-muted-foreground normal-case tracking-normal">(click for details)</span>
        </h4>
        <ul className="space-y-1.5">
          {result.recommendations.map((r, i) => (
            <li key={i}>
              <button type="button" onClick={() => openRec(r)}
                      className="w-full text-left flex items-start gap-2 text-sm rounded-md px-2.5 py-2 hover:bg-accent/60 border border-transparent hover:border-border transition">
                <ShieldCheck className="h-4 w-4 mt-0.5 flex-shrink-0" style={{ color: "var(--safe)" }} />
                <span className="flex-1">{r}</span>
                <span className="text-[10px] font-mono text-muted-foreground mt-1">view ↗</span>
              </button>
            </li>
          ))}
        </ul>
      </section>

      <FileComplaintPanel ctx={{
        sender, subject, body, channel, analysis: result,
        reporterName: session?.username, reporterEmail: session?.email,
      }} />
    </div>
  );
}

/* ---------------- Attack category, Confidence dial, Link intel table ---------------- */

const CATEGORY_META: Record<string, { label: string; color: string }> = {
  credential_theft:   { label: "Credential Theft",     color: "var(--critical)" },
  upi_fraud:          { label: "UPI Fraud",            color: "var(--critical)" },
  bec:                { label: "Business Email Compromise", color: "var(--critical)" },
  job_scam:           { label: "Job / Task Scam",      color: "var(--danger)" },
  romance:            { label: "Romance Scam",         color: "var(--danger)" },
  crypto_investment:  { label: "Crypto / Investment",  color: "var(--danger)" },
  courier_delivery:   { label: "Courier / Delivery",   color: "var(--warn)" },
  fake_kyc:           { label: "Fake KYC / OTP",       color: "var(--critical)" },
  lottery_prize:      { label: "Lottery / Prize",      color: "var(--warn)" },
  tech_support:       { label: "Tech Support Scam",    color: "var(--danger)" },
  impersonation:      { label: "Impersonation",        color: "var(--danger)" },
  malware_attachment: { label: "Malware Attachment",   color: "var(--critical)" },
  extortion:          { label: "Extortion / Blackmail", color: "var(--critical)" },
  other:              { label: "Other",                color: "var(--muted-foreground)" },
};

function AttackCategoryBadge({ value }: { value?: string }) {
  const meta = CATEGORY_META[value ?? "other"] ?? CATEGORY_META.other;
  return (
    <span className="chip text-[10px] inline-flex items-center gap-1"
          style={{ color: meta.color, borderColor: meta.color, background: `color-mix(in oklab, ${meta.color} 10%, transparent)` }}>
      <Target className="h-3 w-3" /> {meta.label}
    </span>
  );
}

function ConfidenceDial({ value }: { value: number }) {
  const clamped = Math.max(0, Math.min(100, value));
  const color = clamped >= 75 ? "var(--safe)" : clamped >= 45 ? "var(--warn)" : "var(--danger)";
  const r = 26; const c = 2 * Math.PI * r; const offset = c - (clamped / 100) * c;
  return (
    <div className="relative h-20 w-20" title={`AI confidence: ${clamped}%`}>
      <svg viewBox="0 0 64 64" className="h-full w-full -rotate-90">
        <circle cx="32" cy="32" r={r} fill="none" stroke="var(--border)" strokeWidth="6" />
        <circle cx="32" cy="32" r={r} fill="none" stroke={color} strokeWidth="6"
                strokeLinecap="round" strokeDasharray={c} strokeDashoffset={offset}
                style={{ transition: "stroke-dashoffset 600ms ease, stroke 300ms ease", filter: `drop-shadow(0 0 4px ${color})` }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-sm font-bold font-mono" style={{ color }}>{clamped}%</div>
        <div className="text-[8px] font-mono uppercase tracking-wider text-muted-foreground">confidence</div>
      </div>
    </div>
  );
}

function LinkIntelTable({
  scores, onRunIntel, intelLoading, intelError, intel,
}: {
  scores: LinkScore[];
  onRunIntel: () => void;
  intelLoading: boolean;
  intelError: string | null;
  intel: ThreatIntelResult | null;
}) {
  const intelByUrl = useMemo(() => {
    const m = new Map<string, UrlIntel>();
    intel?.results.forEach((r) => m.set(r.url, r));
    return m;
  }, [intel]);

  return (
    <div className="rounded-md border border-border bg-card/40">
      <div className="flex items-center justify-between px-3 py-2 border-b border-border gap-2">
        <div className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono flex items-center gap-1.5">
          <Link2 className="h-3.5 w-3.5" /> Link intelligence
          <span className="normal-case tracking-normal opacity-70">
            {intel ? `· live · ${intel.feedsUsed.join(", ") || "no feeds"}` : "· heuristic first · run live check for RDAP, crt.sh, URLScan, DNS, phishing feeds"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono text-muted-foreground">{scores.length} URL{scores.length === 1 ? "" : "s"}</span>
          <button type="button" onClick={onRunIntel} disabled={intelLoading}
            className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-mono hover:bg-accent transition disabled:opacity-50">
            {intelLoading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Radar className="h-3 w-3" />}
            {intelLoading ? "Checking…" : intel ? "Re-check" : "Run live check"}
          </button>
        </div>
      </div>
      {intelError && (
        <div className="px-3 py-2 border-b border-border text-[11px] font-mono" style={{ color: "var(--danger)" }}>
          {intelError}
        </div>
      )}
      <ul className="divide-y divide-border">
        {scores.map((s, i) => {
          const color = severityColor(s.severity);
          const live = intelByUrl.get(s.url);
          return (
            <li key={i} className="px-3 py-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="chip text-[10px]" style={{ color, borderColor: color }}>{s.severity} · {s.score}</span>
                {live && (
                  <span className="chip text-[10px]"
                    style={{ color: severityColor(live.overallRisk === "unknown" ? "medium" : live.overallRisk), borderColor: severityColor(live.overallRisk === "unknown" ? "medium" : live.overallRisk) }}>
                    live · {live.overallRisk}
                  </span>
                )}
                <code className="text-xs font-mono break-all" style={{ color: s.score > 0 ? "var(--warn)" : "var(--muted-foreground)" }}>{s.url}</code>
              </div>
              <ul className="mt-1 text-[11px] text-muted-foreground space-y-0.5">
                {s.reasons.map((r, ri) => (
                  <li key={ri} className="flex items-start gap-1.5">
                    <span className="mt-1 h-1 w-1 rounded-full flex-shrink-0" style={{ background: r.weight > 0 ? color : "var(--muted-foreground)" }} />
                    <span>{r.label}{r.weight > 0 ? ` (+${r.weight})` : ""}</span>
                  </li>
                ))}
              </ul>
              {live && (
                <div className="mt-2 rounded-md border border-border/70 bg-background/50 p-2">
                  <div className="flex flex-wrap items-center gap-3 text-[10px] font-mono text-muted-foreground mb-1.5">
                    {live.domainAgeDays !== null && <span>domain age: <span className="text-foreground">{live.domainAgeDays}d</span></span>}
                    {live.publicScanCount !== null && <span>public scans: <span className="text-foreground">{live.publicScanCount}</span></span>}
                    {live.reportedPhishing && <span style={{ color: "var(--critical)" }}>reported phishing</span>}
                  </div>
                  <ul className="space-y-1">
                    {live.providers.map((p, pi) => (
                      <li key={pi} className="flex items-start gap-2 text-[11px]">
                        <span className="chip text-[9px] mt-0.5"
                          style={{ color: providerStatusColor(p.status), borderColor: providerStatusColor(p.status), minWidth: 58, justifyContent: "center" }}>
                          {p.status}
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{p.provider}</div>
                          <div className="text-[11px] break-words">
                            {p.detail}
                            {p.link && (
                              <a href={p.link} target="_blank" rel="noreferrer noopener"
                                 className="ml-1 inline-flex items-center gap-0.5 underline underline-offset-2 opacity-80 hover:opacity-100">
                                view <ExternalLink className="h-2.5 w-2.5" />
                              </a>
                            )}
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function providerStatusColor(s: ProviderStatus) {
  switch (s) {
    case "flagged": return "var(--critical)";
    case "clean": return "var(--safe)";
    case "unknown": return "var(--warn)";
    case "skipped": return "var(--muted-foreground)";
    case "error": return "var(--danger)";
    default: return "var(--muted-foreground)";
  }
}


/* ---------------- Community report row + Device-impact panel ---------------- */

function CommunityReportRow({
  reportCount, reported, reporting, onReport, verdict,
}: {
  reportCount: number; reported: boolean; reporting: boolean; onReport: () => void;
  verdict: EmailAnalysis["verdict"];
}) {
  const isThreat = verdict !== "safe";
  return (
    <div className="mt-5 rounded-md border border-border bg-card/50 px-3 py-2.5 flex items-center gap-3 flex-wrap">
      <div className="inline-flex items-center gap-2 text-sm">
        <Users className="h-4 w-4" style={{ color: "var(--warn)" }} />
        {reportCount > 0 ? (
          <span>
            <span className="font-mono font-semibold" style={{ color: "var(--warn)" }}>{reportCount}</span>
            {" "}MailGuard {reportCount === 1 ? "user has" : "users have"} reported this exact content as a scam.
          </span>
        ) : (
          <span className="text-muted-foreground">
            No other MailGuard user has reported this exact content yet.
          </span>
        )}
      </div>
      <div className="ml-auto flex items-center gap-2">
        {reported ? (
          <span className="chip text-[10px]" style={{ color: "var(--safe)", borderColor: "var(--safe)" }}>
            <ShieldCheck className="h-3 w-3" /> Reported — thank you
          </span>
        ) : (
          <button type="button" onClick={onReport} disabled={reporting || !isThreat}
            title={!isThreat ? "Reports are only meaningful for suspicious/phishing/fraud verdicts" : "Add your report to the community counter"}
            className="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1.5 rounded-md border transition disabled:opacity-40 disabled:cursor-not-allowed"
            style={{ borderColor: "var(--danger)", color: "var(--danger)" }}>
            {reporting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Flag className="h-3.5 w-3.5" />}
            Report as scam
          </button>
        )}
      </div>
    </div>
  );
}

function DeviceImpactPanel({ category, verdict }: { category?: string; verdict: EmailAnalysis["verdict"] }) {
  if (verdict === "safe") return null;
  const impact = impactFor(category);
  return (
    <section className="mt-6 rounded-md border border-border bg-card/40 p-4">
      <div className="flex items-center gap-2 mb-3">
        <Radar className="h-4 w-4" style={{ color: "var(--warn)" }} />
        <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-mono">
          What this scam can do to your device & data
        </h4>
      </div>
      <p className="text-sm mb-3"><span className="font-semibold">Attacker's goal: </span>{impact.what}</p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono mb-1.5 flex items-center gap-1.5">
            <Shield className="h-3 w-3" /> Effect on your device
          </div>
          <ul className="space-y-1 text-xs">
            {impact.device.map((d, i) => (
              <li key={i} className="flex gap-2"><span style={{ color: "var(--danger)" }}>▸</span><span>{d}</span></li>
            ))}
          </ul>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono mb-1.5 flex items-center gap-1.5">
            <Eye className="h-3 w-3" /> Data an attacker can obtain
          </div>
          <ul className="flex flex-wrap gap-1.5">
            {impact.data.map((d, i) => (
              <li key={i} className="chip text-[10px]" style={{ color: "var(--warn)", borderColor: "var(--warn)" }}>{d}</li>
            ))}
          </ul>
        </div>
      </div>

      <div className="mt-3 flex items-start gap-2 text-[11px] text-muted-foreground border-t border-border pt-2.5">
        <Info className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
        <span><span className="font-semibold text-foreground">Why we tell you this: </span>{impact.reasoning}</span>
      </div>
    </section>
  );
}

/* ---------------- Verdict explainer: mail protection %, why high/low risk ---------------- */

function VerdictExplainer({ result }: { result: EmailAnalysis }) {
  const protection = Math.max(0, Math.min(100, 100 - result.riskScore));
  const isHigh = result.riskScore >= 51;
  const isMid = result.riskScore >= 21 && result.riskScore < 51;
  const isSafe = result.riskScore < 21;

  const barColor =
    protection >= 80 ? "var(--safe)" :
    protection >= 50 ? "var(--warn)" :
    protection >= 25 ? "var(--danger)" : "var(--critical)";

  // Extract concrete "malicious data" the message is holding.
  const maliciousArtifacts: { label: string; detail: string }[] = [];
  for (const l of result.suspiciousLinks.slice(0, 6)) {
    maliciousArtifacts.push({ label: `Link · ${l.risk}`, detail: `${l.url} — ${l.reason}` });
  }
  const highSevIndicators = result.indicators.filter(
    (i) => i.severity === "high" || i.severity === "critical",
  );
  for (const ind of highSevIndicators.slice(0, 6)) {
    maliciousArtifacts.push({
      label: `${categoryLabel(ind.category)} · ${ind.severity}`,
      detail: ind.detail,
    });
  }

  const safeReasons: string[] = [];
  if (isSafe) {
    if (result.suspiciousLinks.length === 0) safeReasons.push("No suspicious URLs, shorteners, or IP-address links detected in the body.");
    if (result.indicators.length === 0) safeReasons.push("No credential-harvest, urgency, or brand-impersonation cues fired.");
    safeReasons.push("Sender pattern and message tone match legitimate correspondence — no spoofing or lookalike domain.");
    safeReasons.push("Nothing in the content maps to the six known 2025-2026 attack families we screen for.");
    safeReasons.push("Even so, verify any money / OTP request out-of-band — safe today doesn't mean safe forever.");
  }

  return (
    <section className="mt-6 rounded-md border border-border bg-card/40 p-4">
      <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4" style={{ color: barColor }} />
          <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-mono">
            Mail protection level & why this verdict
          </h4>
        </div>
        <span className="text-xs font-mono" style={{ color: barColor }}>
          <span className="text-lg font-bold">{protection}%</span> protected
        </span>
      </div>

      <div className="h-2 w-full rounded-full overflow-hidden bg-secondary/60 border border-border mb-1">
        <div className="h-full rounded-full transition-all duration-700"
             style={{ width: `${protection}%`, background: barColor, boxShadow: `0 0 8px ${barColor}` }} />
      </div>
      <div className="flex justify-between text-[10px] font-mono text-muted-foreground uppercase mb-4">
        <span>Compromised</span><span>At risk</span><span>Guarded</span><span>Fully safe</span>
      </div>

      {isHigh && (
        <div>
          <div className="text-sm font-semibold mb-1" style={{ color: "var(--danger)" }}>
            Why this mail is high risk
          </div>
          <p className="text-xs text-muted-foreground mb-2">
            The AI verdict + heuristic scoring both crossed the {result.riskScore < 81 ? "phishing" : "fraud"} threshold ({result.riskScore}/100).
            Below is the actual malicious content the message is carrying — this is not a guess, it's what the analyzer found inside your text and links.
          </p>
          <div className="text-[10px] uppercase tracking-wider font-mono text-muted-foreground mb-1">
            Malicious data this message is holding
          </div>
          {maliciousArtifacts.length === 0 ? (
            <p className="text-xs text-muted-foreground">No individual artifacts extracted — but the overall pattern (tone, intent, structure) matches known scam playbooks.</p>
          ) : (
            <ul className="space-y-1.5">
              {maliciousArtifacts.map((a, i) => (
                <li key={i} className="rounded-md border border-border bg-background/50 px-2.5 py-1.5">
                  <div className="text-[10px] font-mono uppercase tracking-wider" style={{ color: "var(--danger)" }}>{a.label}</div>
                  <div className="text-xs break-words">{a.detail}</div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {isMid && (
        <div>
          <div className="text-sm font-semibold mb-1" style={{ color: "var(--warn)" }}>
            Why this mail is suspicious (not conclusive)
          </div>
          <p className="text-xs text-muted-foreground mb-2">
            Some indicators fired ({result.indicators.length}), but not enough to call it phishing outright.
            Treat it like a stranger at your door — polite scepticism, no clicks until verified.
          </p>
          {maliciousArtifacts.length > 0 && (
            <ul className="space-y-1.5">
              {maliciousArtifacts.map((a, i) => (
                <li key={i} className="rounded-md border border-border bg-background/50 px-2.5 py-1.5">
                  <div className="text-[10px] font-mono uppercase tracking-wider" style={{ color: "var(--warn)" }}>{a.label}</div>
                  <div className="text-xs break-words">{a.detail}</div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {isSafe && (
        <div>
          <div className="text-sm font-semibold mb-1" style={{ color: "var(--safe)" }}>
            Why this mail is low risk & unlikely to defraud you
          </div>
          <ul className="space-y-1.5 text-xs">
            {safeReasons.map((r, i) => (
              <li key={i} className="flex gap-2">
                <ShieldCheck className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" style={{ color: "var(--safe)" }} />
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-3 flex items-start gap-2 text-[11px] text-muted-foreground border-t border-border pt-2.5">
        <Info className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
        <span>
          <span className="font-semibold text-foreground">How we scored this: </span>
          Mail protection % = 100 − risk score. Risk score combines the AI verdict, per-link intelligence (Safe Browsing / VirusTotal / PhishTank / RDAP),
          heuristic indicators (spoofing, urgency, brand impersonation, credential capture), and the six real-world attack families tracked in
          <Link to="/threats" className="ml-1 underline underline-offset-2 text-foreground">Top 6 threats · 2025/26</Link>.
        </span>
      </div>
    </section>
  );
}
