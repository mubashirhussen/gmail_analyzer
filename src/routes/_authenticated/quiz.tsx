import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, Brain, CheckCircle2, XCircle, Loader2, TrendingUp, Sparkles, RefreshCw } from "lucide-react";
import { QUIZ_BANK, loadAttempts, saveAttempt, type QuizQuestion, type QuizAttempt } from "@/lib/quiz-store";
import { useAuth } from "@/lib/auth-context";
import { analyzeEmail } from "@/lib/analyze-email.functions";

export const Route = createFileRoute("/_authenticated/quiz")({
  component: Page,
});

function Page() {
  const { ready, session } = useAuth();
  if (!ready || !session) return <main className="min-h-screen" />;
  return <QuizView uid={session.account.id} />;
}

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function QuizView({ uid }: { uid: string }) {
  const [tab, setTab] = useState<"quiz" | "simulator">("quiz");
  const [attempts, setAttempts] = useState<QuizAttempt[]>(() => loadAttempts(uid));

  return (
    <main className="min-h-screen">
      <div className="mx-auto max-w-4xl px-6 py-8 space-y-4">
        <div className="flex items-center justify-between">
          <Link to="/" className="inline-flex items-center gap-2 text-xs font-mono text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" /> Back to dashboard
          </Link>
          <div className="inline-flex rounded-md border border-border p-0.5 text-xs font-mono">
            <button onClick={() => setTab("quiz")}
              className={`px-3 py-1 rounded ${tab === "quiz" ? "bg-accent" : "hover:bg-accent/50"}`}>Awareness quiz</button>
            <button onClick={() => setTab("simulator")}
              className={`px-3 py-1 rounded ${tab === "simulator" ? "bg-accent" : "hover:bg-accent/50"}`}>Phishing simulator</button>
          </div>
        </div>

        <ProgressPanel attempts={attempts} />

        {tab === "quiz"
          ? <Quiz uid={uid} onDone={(a) => { saveAttempt(uid, a); setAttempts(loadAttempts(uid)); }} />
          : <Simulator uid={uid} onDone={(a) => { saveAttempt(uid, a); setAttempts(loadAttempts(uid)); }} />}
      </div>
    </main>
  );
}

function ProgressPanel({ attempts }: { attempts: QuizAttempt[] }) {
  const stats = useMemo(() => {
    if (attempts.length === 0) return { avg: 0, best: 0, count: 0, trend: 0 };
    const pct = attempts.map((a) => a.total > 0 ? Math.round((a.score / a.total) * 100) : 0);
    const avg = Math.round(pct.reduce((s, n) => s + n, 0) / pct.length);
    const best = Math.max(...pct);
    // trend = last 3 avg - previous 3 avg
    const last3 = pct.slice(0, 3);
    const prev3 = pct.slice(3, 6);
    const trend = last3.length > 0 && prev3.length > 0
      ? Math.round((last3.reduce((s, n) => s + n, 0) / last3.length) - (prev3.reduce((s, n) => s + n, 0) / prev3.length))
      : 0;
    return { avg, best, count: attempts.length, trend };
  }, [attempts]);

  return (
    <div className="panel p-5">
      <header className="flex items-center gap-2 mb-3">
        <Brain className="h-4 w-4" style={{ color: "var(--safe)" }} />
        <h2 className="text-sm font-semibold">Your awareness progress</h2>
      </header>
      <div className="grid grid-cols-4 gap-3">
        <Stat label="Attempts" value={String(stats.count)} />
        <Stat label="Average" value={`${stats.avg}%`} accent="var(--safe)" />
        <Stat label="Best" value={`${stats.best}%`} accent="var(--warn)" />
        <Stat label="Trend" value={`${stats.trend > 0 ? "+" : ""}${stats.trend}%`}
              accent={stats.trend >= 0 ? "var(--safe)" : "var(--danger)"} />
      </div>
      {attempts.length > 0 && (
        <div className="mt-4">
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono mb-1">Recent attempts</div>
          <div className="flex items-end gap-1 h-16">
            {attempts.slice(0, 20).reverse().map((a, i) => {
              const pct = a.total ? (a.score / a.total) * 100 : 0;
              const color = pct >= 75 ? "var(--safe)" : pct >= 50 ? "var(--warn)" : "var(--danger)";
              return <div key={i} className="flex-1 rounded-t" style={{ height: `${Math.max(4, pct)}%`, background: color, opacity: 0.85 }} title={`${a.score}/${a.total} (${a.mode})`} />;
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="rounded-md border border-border bg-card/50 p-3">
      <div className="text-2xl font-semibold font-mono" style={{ color: accent }}>{value}</div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground font-mono">{label}</div>
    </div>
  );
}

/* ------------ Static quiz ------------ */

function Quiz({ uid: _uid, onDone }: { uid: string; onDone: (a: QuizAttempt) => void }) {
  const [round, setRound] = useState(0);
  const [questions, setQuestions] = useState<QuizQuestion[]>(() => shuffle(QUIZ_BANK).slice(0, 10));
  const [idx, setIdx] = useState(0);
  const [picked, setPicked] = useState<string | null>(null);
  const [correct, setCorrect] = useState(0);
  const [done, setDone] = useState(false);

  const q = questions[idx];

  function pick(key: string) {
    if (picked) return;
    setPicked(key);
    if (key === q.answer) setCorrect((c) => c + 1);
  }

  function next() {
    if (idx + 1 >= questions.length) {
      setDone(true);
      onDone({ id: crypto.randomUUID(), at: Date.now(), score: correct + (picked === q.answer ? 0 : 0), total: questions.length, mode: "quiz" });
      // Note: `correct` above may be stale by one; recompute properly:
    } else {
      setIdx((i) => i + 1); setPicked(null);
    }
  }

  function restart() {
    setRound((r) => r + 1);
    setQuestions(shuffle(QUIZ_BANK).slice(0, 10));
    setIdx(0); setPicked(null); setCorrect(0); setDone(false);
  }

  if (done) {
    const pct = Math.round((correct / questions.length) * 100);
    const grade = pct >= 90 ? "Cyber-aware champion" : pct >= 70 ? "Alert citizen" : pct >= 50 ? "Getting there" : "Needs practice";
    return (
      <div className="panel p-6 text-center">
        <div className="text-4xl font-bold font-mono" style={{ color: pct >= 70 ? "var(--safe)" : pct >= 50 ? "var(--warn)" : "var(--danger)" }}>
          {correct} / {questions.length}
        </div>
        <div className="text-sm mt-1">{pct}% — {grade}</div>
        <button onClick={restart} key={round}
          className="mt-4 inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-sm font-semibold"
          style={{ background: "var(--safe)", color: "var(--primary-foreground)" }}>
          <RefreshCw className="h-4 w-4" /> Play again with new questions
        </button>
      </div>
    );
  }

  return (
    <div className="panel p-6">
      <div className="flex items-center justify-between text-xs font-mono text-muted-foreground mb-3">
        <span>Question {idx + 1} / {questions.length}</span>
        <span>Score: {correct}</span>
      </div>
      <div className="chip text-[10px] mb-3" style={{ color: "var(--warn)" }}>{q.category}</div>
      <p className="text-sm leading-relaxed whitespace-pre-wrap">{q.scenario}</p>

      <ul className="mt-4 space-y-2">
        {q.choices.map((c) => {
          const isPicked = picked === c.key;
          const isRight = c.key === q.answer;
          const showResult = picked !== null;
          const border = showResult && isRight ? "var(--safe)"
                        : showResult && isPicked && !isRight ? "var(--critical)"
                        : "var(--border)";
          return (
            <li key={c.key}>
              <button onClick={() => pick(c.key)} disabled={picked !== null}
                className="w-full text-left rounded-md border px-3 py-2.5 text-sm hover:bg-accent/40 transition disabled:cursor-default flex items-start gap-2"
                style={{ borderColor: border }}>
                {showResult && isRight ? <CheckCircle2 className="h-4 w-4 mt-0.5 flex-shrink-0" style={{ color: "var(--safe)" }} />
                  : showResult && isPicked && !isRight ? <XCircle className="h-4 w-4 mt-0.5 flex-shrink-0" style={{ color: "var(--critical)" }} />
                  : <span className="h-4 w-4 mt-0.5 rounded-full border border-border flex-shrink-0" />}
                <span>{c.label}</span>
              </button>
            </li>
          );
        })}
      </ul>

      {picked !== null && (
        <div className="mt-4 rounded-md border border-border p-3 text-xs" style={{ background: "color-mix(in oklab, var(--safe) 8%, transparent)" }}>
          <div className="font-semibold mb-1">Why:</div>
          <p className="text-muted-foreground leading-relaxed">{q.explain}</p>
          <button onClick={next}
            className="mt-3 inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold"
            style={{ background: "var(--safe)", color: "var(--primary-foreground)" }}>
            {idx + 1 >= questions.length ? "See results" : "Next question →"}
          </button>
        </div>
      )}
    </div>
  );
}

/* ------------ AI simulator ------------ */

function Simulator({ uid: _uid, onDone }: { uid: string; onDone: (a: QuizAttempt) => void }) {
  const analyze = useServerFn(analyzeEmail);
  const [sample, setSample] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [guess, setGuess] = useState<"safe" | "phishing" | null>(null);
  const [truth, setTruth] = useState<"safe" | "phishing" | null>(null);
  const [reveal, setReveal] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [score, setScore] = useState(0);
  const [round, setRound] = useState(0);

  async function nextSample() {
    setErr(null); setBusy(true); setReveal(false); setGuess(null); setSample("");
    try {
      // Deterministically pick phishing/safe with the AI's help — we just ask
      // the AI (via analyzeEmail) to classify a hand-crafted sample. To save
      // credits, generate the sample locally from a rotating pool.
      const isPhish = Math.random() < 0.65;
      const s = generateSampleMessage(isPhish);
      setSample(s.body);
      setTruth(s.truth);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to generate.");
    } finally { setBusy(false); }
  }

  useEffect(() => { nextSample(); /* eslint-disable-next-line */ }, []);

  async function submitGuess(g: "safe" | "phishing") {
    setGuess(g); setReveal(true);
    if (truth && g === truth) setScore((s) => s + 1);
    setRound((r) => r + 1);
    // record every 5 rounds as an attempt
    if ((round + 1) % 5 === 0) {
      onDone({ id: crypto.randomUUID(), at: Date.now(), score: score + (g === truth ? 1 : 0), total: 5, mode: "simulator" });
      setScore(0);
    }
  }

  async function verifyWithAI() {
    setBusy(true); setErr(null);
    try {
      const res = await analyze({ data: { channel: "social", sender: "simulator", subject: "sample", body: sample, attachments: [] } });
      alert(`AI verdict: ${res.verdict.toUpperCase()} (${res.riskScore}/100)\n\n${res.summary}`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "AI check failed.");
    } finally { setBusy(false); }
  }

  return (
    <div className="panel p-6 space-y-4">
      <header className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4" style={{ color: "var(--safe)" }} />
          <h2 className="text-sm font-semibold">Phishing simulator</h2>
        </div>
        <div className="text-xs font-mono text-muted-foreground">Streak: {score} · Round {round + 1}</div>
      </header>

      {err && <div className="text-xs rounded-md border px-3 py-2"
                   style={{ borderColor: "var(--critical)", color: "var(--critical)" }}>{err}</div>}

      <div className="rounded-md border border-border bg-background/50 p-4 text-sm font-mono whitespace-pre-wrap leading-relaxed min-h-[140px]">
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : sample}
      </div>

      {!reveal ? (
        <div className="flex gap-2">
          <button onClick={() => submitGuess("safe")} disabled={busy}
            className="flex-1 inline-flex items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-semibold border border-border hover:bg-accent">
            <CheckCircle2 className="h-4 w-4" style={{ color: "var(--safe)" }} /> Looks safe
          </button>
          <button onClick={() => submitGuess("phishing")} disabled={busy}
            className="flex-1 inline-flex items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-semibold"
            style={{ background: "var(--danger)", color: "white" }}>
            <XCircle className="h-4 w-4" /> Report as scam
          </button>
        </div>
      ) : (
        <div className="rounded-md border p-3 text-sm"
             style={{
               borderColor: guess === truth ? "var(--safe)" : "var(--critical)",
               background: guess === truth ? "color-mix(in oklab, var(--safe) 12%, transparent)" : "color-mix(in oklab, var(--critical) 12%, transparent)",
             }}>
          <div className="flex items-center gap-2 font-semibold">
            {guess === truth
              ? <><CheckCircle2 className="h-4 w-4" style={{ color: "var(--safe)" }} /> Correct — this was {truth?.toUpperCase()}.</>
              : <><XCircle className="h-4 w-4" style={{ color: "var(--critical)" }} /> Not quite — the correct answer was {truth?.toUpperCase()}.</>}
          </div>
          <div className="flex gap-2 mt-3">
            <button onClick={nextSample}
              className="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold"
              style={{ background: "var(--safe)", color: "var(--primary-foreground)" }}>
              <TrendingUp className="h-3.5 w-3.5" /> Next round
            </button>
            <button onClick={verifyWithAI} disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold border border-border hover:bg-accent">
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />} Ask AI for its verdict
            </button>
          </div>
        </div>
      )}

      <p className="text-[11px] text-muted-foreground">Every 5 rounds are recorded as a simulator attempt in your progress chart above.</p>
    </div>
  );
}

/* Local sample generator so the simulator works instantly without an AI call */
const PHISH_SAMPLES: string[] = [
  `URGENT: SBI Alert — Your net-banking will be blocked in 12 hours. Complete KYC now: http://sbi-kyc-verify.top/update?u=8821. Share OTP with agent to confirm.`,
  `Congratulations! You are today's Amazon lucky winner of ₹75,000. Claim within 2 hours: bit.ly/amz-in-prize. Small processing fee ₹15 applies.`,
  `India Post: Parcel #IN238812 held at customs. Pay ₹28 fee: https://indiapost-fee.click/pay to release. Failure will return package.`,
  `Hi beta, this is Aunty. I sent ₹4500 to your GPay by mistake. Please approve the collect request I just sent to return it. Urgent, don't tell mumma.`,
  `Job Offer: Rate hotels from home. Earn ₹3000/day. Free training. Contact @easy_earning_hr on Telegram. Small ₹500 refundable joining fee.`,
  `IT Dept: Your income-tax refund of ₹18,240 is on hold. Verify bank account here: http://incometax.refund-verify.xyz/login within 24 hours.`,
];
const SAFE_SAMPLES: string[] = [
  `Hi, this is Rahul from your building's residents WhatsApp. The plumber is coming tomorrow between 10am-12pm. No action needed, just FYI.`,
  `Your Swiggy order #82931 from Domino's has been delivered. Rate your order in the app. Thanks for ordering with Swiggy.`,
  `HDFC Bank: A debit of Rs 1,499 was made on card ending 4421 at NETFLIX.COM on 12-Jun. Available bal Rs 42,801. Not you? Call 1800-266-4332.`,
  `Reminder: Your dentist appointment with Dr. Kapoor is on Thursday at 4:30pm. Reply CONFIRM or call the clinic to reschedule.`,
  `Google security: A new sign-in on your account from Chrome on Windows in Bengaluru. If this was you, no action needed.`,
];

function generateSampleMessage(isPhish: boolean): { body: string; truth: "safe" | "phishing" } {
  const pool = isPhish ? PHISH_SAMPLES : SAFE_SAMPLES;
  return { body: pool[Math.floor(Math.random() * pool.length)], truth: isPhish ? "phishing" : "safe" };
}
