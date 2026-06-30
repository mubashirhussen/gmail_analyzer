import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shield, Loader2, LogIn, UserPlus, Mail } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { lovable } from "@/integrations/lovable";

export const Route = createFileRoute("/auth")({
  head: () => ({ meta: [{ title: "Sign in — MailGuard" }] }),
  component: AuthPage,
});

function AuthPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) navigate({ to: "/", replace: true });
    });
  }, [navigate]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      if (mode === "signup") {
        const { error } = await supabase.auth.signUp({
          email, password,
          options: {
            data: { username: username || email.split("@")[0] },
            emailRedirectTo: window.location.origin + "/auth",
          },
        });
        if (error) throw new Error(error.message);
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw new Error(error.message);
      }
      navigate({ to: "/", replace: true });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Something went wrong.");
    } finally { setBusy(false); }
  }

  async function google() {
    setErr(null); setBusy(true);
    try {
      const res = await lovable.auth.signInWithOAuth("google", { redirect_uri: window.location.origin + "/auth" });
      if (res.error) throw res.error;
      if (!res.redirected) navigate({ to: "/", replace: true });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Google sign-in failed.");
      setBusy(false);
    }
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
              {mode === "signup" ? "Create your secure account" : "Sign in to your dashboard"}
            </p>
          </div>
        </div>

        <button type="button" onClick={google} disabled={busy}
                className="w-full inline-flex items-center justify-center gap-2 rounded-md border border-border px-4 py-2.5 text-sm font-semibold mb-3 hover:bg-accent transition disabled:opacity-50">
          <GoogleIcon /> Continue with Google
        </button>

        <div className="flex items-center gap-2 my-3 text-[10px] uppercase tracking-wider text-muted-foreground font-mono">
          <div className="flex-1 h-px bg-border" /> or <div className="flex-1 h-px bg-border" />
        </div>

        <div className="flex gap-2 mb-4">
          <button type="button" onClick={() => { setMode("signin"); setErr(null); }}
                  className={`flex-1 text-xs font-mono uppercase tracking-wider px-3 py-2 rounded-md border ${mode === "signin" ? "border-ring" : "border-border text-muted-foreground"}`}>
            <LogIn className="inline h-3.5 w-3.5 mr-1" /> Sign in
          </button>
          <button type="button" onClick={() => { setMode("signup"); setErr(null); }}
                  className={`flex-1 text-xs font-mono uppercase tracking-wider px-3 py-2 rounded-md border ${mode === "signup" ? "border-ring" : "border-border text-muted-foreground"}`}>
            <UserPlus className="inline h-3.5 w-3.5 mr-1" /> New account
          </button>
        </div>

        <form onSubmit={submit} className="space-y-3">
          {mode === "signup" && (
            <Field label="Username" value={username} onChange={setUsername} placeholder="aarav.k" />
          )}
          <Field label="Email" value={email} onChange={setEmail} placeholder="you@example.com" type="email" />
          <Field label="Password (min 8 chars)" value={password} onChange={setPassword} placeholder="••••••••" type="password" />

          {err && (
            <div className="text-xs rounded-md border px-3 py-2"
                 style={{ borderColor: "var(--critical)", color: "var(--critical)", background: "oklch(0.20 0.04 25 / 30%)" }}>{err}</div>
          )}

          <button type="submit" disabled={busy}
                  className="w-full inline-flex items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-semibold disabled:opacity-50"
                  style={{ background: "var(--safe)", color: "var(--primary-foreground)", boxShadow: "var(--shadow-glow-safe)" }}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Mail className="h-4 w-4" />}
            {mode === "signup" ? "Create account" : "Sign in"}
          </button>
        </form>

        <p className="mt-5 text-[11px] text-muted-foreground leading-relaxed">
          Your account is stored securely in MailGuard Cloud. Mail scan history is cached on this device
          for fast access and is wiped when you sign out.
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
             className="mt-1 w-full rounded-md bg-input/60 border border-border px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-ring/60 focus:border-ring" />
    </div>
  );
}

function GoogleIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden>
      <path fill="#EA4335" d="M12 11.8v3.6h5.1c-.22 1.2-1.5 3.5-5.1 3.5-3.07 0-5.57-2.54-5.57-5.7s2.5-5.7 5.57-5.7c1.74 0 2.9.74 3.57 1.38l2.43-2.36C16.6 4.9 14.5 4 12 4 6.98 4 3 7.98 3 13s3.98 9 9 9c5.2 0 8.64-3.66 8.64-8.8 0-.6-.06-1.04-.14-1.5H12z"/>
    </svg>
  );
}
