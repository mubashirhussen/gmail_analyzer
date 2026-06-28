import { useState } from "react";
import { Shield, UserPlus, LogIn, Loader2, Trash2 } from "lucide-react";
import { useAuth } from "@/lib/auth-context";
import { deleteAccount as removeAccount, getCurrentAccountId } from "@/lib/secure-store";

export function AuthGate() {
  const { accounts, signUp, login, refreshAccounts } = useAuth();
  const last = getCurrentAccountId();
  const initialMode = accounts.length === 0 ? "signup" : "login";
  const [mode, setMode] = useState<"signup" | "login">(initialMode);
  const [selectedId, setSelectedId] = useState<string>(last ?? accounts[0]?.id ?? "");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [passcode, setPasscode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      if (mode === "signup") {
        await signUp({ username, email, passcode });
      } else {
        await login(selectedId, passcode);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed.");
    } finally { setBusy(false); }
  }

  function removeOne(id: string) {
    if (!confirm("Delete this account and all its encrypted local data?")) return;
    removeAccount(id);
    refreshAccounts();
    const remaining = accounts.filter((a) => a.id !== id);
    if (remaining.length === 0) setMode("signup");
    else setSelectedId(remaining[0].id);
  }

  return (
    <main className="min-h-screen flex items-center justify-center px-4">
      <div className="panel p-8 w-full max-w-md">
        <div className="flex items-center gap-3 mb-6">
          <div className="h-10 w-10 rounded-md border border-border flex items-center justify-center"
               style={{ background: "linear-gradient(135deg, oklch(0.30 0.06 200), oklch(0.22 0.04 260))" }}>
            <Shield className="h-5 w-5" style={{ color: "var(--safe)" }} />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">MailGuard</h1>
            <p className="text-xs text-muted-foreground font-mono">
              {mode === "signup" ? "Create your secure account" : "Unlock your account"}
            </p>
          </div>
        </div>

        <div className="flex gap-2 mb-5">
          <button
            type="button"
            onClick={() => { setMode("login"); setErr(null); }}
            disabled={accounts.length === 0}
            className={`flex-1 text-xs font-mono uppercase tracking-wider px-3 py-2 rounded-md border transition disabled:opacity-40 ${mode === "login" ? "border-ring text-foreground" : "border-border text-muted-foreground"}`}
            style={mode === "login" ? { background: "color-mix(in oklab, var(--safe) 12%, transparent)" } : undefined}
          >
            <LogIn className="inline h-3.5 w-3.5 mr-1" /> Sign in
          </button>
          <button
            type="button"
            onClick={() => { setMode("signup"); setErr(null); }}
            className={`flex-1 text-xs font-mono uppercase tracking-wider px-3 py-2 rounded-md border transition ${mode === "signup" ? "border-ring text-foreground" : "border-border text-muted-foreground"}`}
            style={mode === "signup" ? { background: "color-mix(in oklab, var(--safe) 12%, transparent)" } : undefined}
          >
            <UserPlus className="inline h-3.5 w-3.5 mr-1" /> New account
          </button>
        </div>

        <form onSubmit={submit} className="space-y-3">
          {mode === "login" ? (
            <div>
              <label className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono">Account</label>
              <ul className="mt-1 space-y-1.5 max-h-44 overflow-auto">
                {accounts.map((a) => (
                  <li key={a.id}
                      className={`flex items-center justify-between gap-2 rounded-md border px-2.5 py-2 cursor-pointer ${selectedId === a.id ? "border-ring bg-accent/30" : "border-border bg-card/40"}`}
                      onClick={() => setSelectedId(a.id)}>
                    <div className="min-w-0">
                      <div className="text-sm font-semibold truncate">{a.username}</div>
                      <div className="text-[11px] text-muted-foreground font-mono truncate">{a.email}</div>
                    </div>
                    <button type="button" onClick={(e) => { e.stopPropagation(); removeOne(a.id); }}
                            className="p-1 rounded hover:bg-accent text-muted-foreground" aria-label="Remove">
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <>
              <Field label="Username" value={username} onChange={setUsername} placeholder="aarav.k" />
              <Field label="Email" value={email} onChange={setEmail} placeholder="you@example.com" type="email" />
            </>
          )}

          <Field label="Passcode (min 6 chars)" value={passcode} onChange={setPasscode} placeholder="••••••••" type="password" />

          {err && (
            <div className="text-xs rounded-md border px-3 py-2"
                 style={{ borderColor: "var(--critical)", color: "var(--critical)", background: "oklch(0.20 0.04 25 / 30%)" }}>
              {err}
            </div>
          )}

          <button type="submit" disabled={busy}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-semibold transition disabled:opacity-50"
                  style={{ background: "var(--safe)", color: "var(--primary-foreground)", boxShadow: "var(--shadow-glow-safe)" }}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : mode === "signup" ? <UserPlus className="h-4 w-4" /> : <LogIn className="h-4 w-4" />}
            {mode === "signup" ? "Create account & unlock" : "Unlock"}
          </button>
        </form>

        <p className="mt-5 text-[11px] text-muted-foreground leading-relaxed">
          Your passcode never leaves this device. It derives an AES-GCM key (PBKDF2, 150k iters) that
          encrypts your mail history in local storage. Forget the passcode → data is unrecoverable.
        </p>
      </div>
    </main>
  );
}

function Field({ label, value, onChange, placeholder, type = "text" }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string; type?: string;
}) {
  return (
    <div>
      <label className="text-[11px] uppercase tracking-wider text-muted-foreground font-mono">{label}</label>
      <input type={type} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
             autoComplete={type === "password" ? "current-password" : "off"}
             className="mt-1 w-full rounded-md bg-input/60 border border-border px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-ring/60 focus:border-ring" />
    </div>
  );
}
