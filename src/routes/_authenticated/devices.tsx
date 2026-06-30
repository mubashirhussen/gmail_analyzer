import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { MonitorSmartphone, Smartphone, ShieldCheck, LogOut, Trash2, AlertOctagon, Loader2, ArrowLeft, ShieldAlert } from "lucide-react";
import { listDevices, revokeDevice, removeDevice, reportSuspicious, revokeAllOtherDevices } from "@/lib/devices.functions";
import { getOrCreateSessionToken } from "@/lib/device-fingerprint";
import { supabase } from "@/integrations/supabase/client";

export const Route = createFileRoute("/_authenticated/devices")({
  head: () => ({ meta: [{ title: "Trusted devices — MailGuard" }] }),
  component: DevicesPage,
});

type Device = {
  id: string; fingerprint_hash: string; label: string | null;
  os: string | null; browser: string | null; ip: string | null;
  city: string | null; country: string | null; trusted: boolean;
  first_seen: string; last_seen: string;
};
type SessionRow = { device_id: string; session_token: string; last_active: string; expires_at: string; revoked_at: string | null };

function DevicesPage() {
  const list = useServerFn(listDevices);
  const revoke = useServerFn(revokeDevice);
  const remove = useServerFn(removeDevice);
  const report = useServerFn(reportSuspicious);
  const revokeAll = useServerFn(revokeAllOtherDevices);
  const navigate = useNavigate();

  const [devices, setDevices] = useState<Device[]>([]);
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);

  const currentToken = typeof window !== "undefined" ? getOrCreateSessionToken() : "";

  async function refresh() {
    setLoading(true);
    try {
      const res = await list();
      setDevices(res.devices as Device[]);
      setSessions(res.sessions as SessionRow[]);
    } finally { setLoading(false); }
  }
  useEffect(() => { refresh(); }, []);

  function isCurrent(d: Device) {
    return sessions.some((s) => s.device_id === d.id && s.session_token === currentToken && !s.revoked_at);
  }
  function activeSession(d: Device) {
    return sessions.find((s) => s.device_id === d.id && !s.revoked_at && new Date(s.expires_at) > new Date());
  }

  async function onRevoke(d: Device) { setBusy(d.id); try { await revoke({ data: { deviceId: d.id } }); await refresh(); } finally { setBusy(null); } }
  async function onRemove(d: Device) {
    if (!confirm(`Remove "${d.label}" from trusted devices?`)) return;
    setBusy(d.id); try { await remove({ data: { deviceId: d.id } }); await refresh(); } finally { setBusy(null); }
  }
  async function onReport(d: Device) {
    setBusy(d.id); try { await report({ data: { deviceId: d.id } }); alert("Reported. We logged this device as suspicious in your security timeline."); await refresh(); } finally { setBusy(null); }
  }
  async function onRevokeAll() {
    if (!confirm("Sign out of every other device immediately?")) return;
    await revokeAll({ data: { keepSessionToken: currentToken } });
    await refresh();
  }

  return (
    <main className="min-h-screen text-foreground">
      <header className="border-b border-border/60 backdrop-blur-md bg-background/70">
        <div className="mx-auto max-w-5xl px-6 py-4 flex items-center justify-between">
          <Link to="/" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4" /> Back to dashboard
          </Link>
          <button onClick={onRevokeAll} className="text-xs font-mono px-3 py-1.5 rounded-md border border-border hover:bg-accent inline-flex items-center gap-1.5">
            <ShieldAlert className="h-3.5 w-3.5" style={{ color: "var(--danger)" }} /> Sign out everywhere else
          </button>
        </div>
      </header>

      <div className="mx-auto max-w-5xl px-6 py-8">
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <MonitorSmartphone className="h-5 w-5" style={{ color: "var(--safe)" }} /> Trusted devices
        </h1>
        <p className="text-sm text-muted-foreground mt-1">Devices that have signed into your MailGuard account. Revoke any device you don't recognise.</p>

        {loading ? (
          <div className="mt-8 flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : devices.length === 0 ? (
          <div className="mt-8 panel p-6 text-sm text-muted-foreground">No devices recorded yet.</div>
        ) : (
          <ul className="mt-6 space-y-3">
            {devices.map((d) => {
              const current = isCurrent(d);
              const sess = activeSession(d);
              const active = Boolean(sess);
              return (
                <li key={d.id} className="panel p-4">
                  <div className="flex items-start gap-4">
                    <div className="h-10 w-10 rounded-md border border-border flex items-center justify-center"
                         style={{ background: "color-mix(in oklab, var(--safe) 12%, transparent)" }}>
                      {(/Android|iOS|iPhone|iPad/i.test(d.os || "")) ? <Smartphone className="h-5 w-5" style={{ color: "var(--safe)" }} /> : <MonitorSmartphone className="h-5 w-5" style={{ color: "var(--safe)" }} />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold">{d.label || "Unknown device"}</span>
                        {current && <span className="chip text-[10px]" style={{ color: "var(--safe)", borderColor: "var(--safe)" }}>this device</span>}
                        {active ? (
                          <span className="chip text-[10px]" style={{ color: "var(--safe)", borderColor: "var(--safe)" }}>active</span>
                        ) : (
                          <span className="chip text-[10px]" style={{ color: "var(--muted-foreground)", borderColor: "var(--border)" }}>signed out</span>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono mt-1">
                        {d.os} · {d.browser} · last active {new Date(d.last_seen).toLocaleString()}
                      </div>
                    </div>
                    <div className="flex flex-col sm:flex-row gap-2">
                      {active && !current && (
                        <button onClick={() => onRevoke(d)} disabled={busy === d.id}
                                className="text-xs font-mono px-2.5 py-1.5 rounded-md border border-border hover:bg-accent inline-flex items-center gap-1.5">
                          <LogOut className="h-3.5 w-3.5" /> Logout
                        </button>
                      )}
                      {!current && (
                        <button onClick={() => onRemove(d)} disabled={busy === d.id}
                                className="text-xs font-mono px-2.5 py-1.5 rounded-md border border-border hover:bg-accent inline-flex items-center gap-1.5">
                          <Trash2 className="h-3.5 w-3.5" /> Remove
                        </button>
                      )}
                      {!current && (
                        <button onClick={() => onReport(d)} disabled={busy === d.id}
                                className="text-xs font-mono px-2.5 py-1.5 rounded-md border hover:bg-accent inline-flex items-center gap-1.5"
                                style={{ borderColor: "var(--danger)", color: "var(--danger)" }}>
                          <AlertOctagon className="h-3.5 w-3.5" /> Report
                        </button>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        )}

        <div className="mt-8 panel p-4 text-xs text-muted-foreground">
          <ShieldCheck className="inline h-3.5 w-3.5 mr-1" style={{ color: "var(--safe)" }} />
          Devices are identified by a privacy-preserving browser fingerprint (UA + screen + timezone + canvas hash). Removing
          a device revokes its session — that device is signed out the next time it pings MailGuard (within 60 seconds).
        </div>
      </div>
    </main>
  );
}
