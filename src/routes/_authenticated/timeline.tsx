import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { Activity, ArrowLeft, ShieldAlert, ShieldCheck, ShieldX, Loader2, LogIn, LogOut, Trash2, AlertOctagon } from "lucide-react";
import { listSecurityEvents } from "@/lib/devices.functions";

export const Route = createFileRoute("/_authenticated/timeline")({
  head: () => ({ meta: [{ title: "Security timeline — MailGuard" }] }),
  component: TimelinePage,
});

type Event = {
  id: string; kind: string; severity: string; summary: string;
  meta: Record<string, unknown>; created_at: string;
};

function iconFor(kind: string, severity: string) {
  if (kind.startsWith("scan_safe")) return { Icon: ShieldCheck, color: "var(--safe)" };
  if (kind.startsWith("scan_suspicious")) return { Icon: ShieldAlert, color: "var(--warn)" };
  if (kind.startsWith("scan_phishing") || kind.startsWith("scan_fraud")) return { Icon: ShieldX, color: "var(--critical)" };
  if (kind === "device_signed_in") return { Icon: LogIn, color: "var(--safe)" };
  if (kind === "device_signed_out" || kind === "global_signout") return { Icon: LogOut, color: "var(--warn)" };
  if (kind === "device_removed") return { Icon: Trash2, color: "var(--warn)" };
  if (kind === "suspicious_device_reported") return { Icon: AlertOctagon, color: "var(--critical)" };
  return { Icon: Activity, color: severity === "critical" ? "var(--critical)" : "var(--muted-foreground)" };
}

function groupByDay(events: Event[]) {
  const groups: Record<string, Event[]> = {};
  for (const e of events) {
    const d = new Date(e.created_at);
    const key = d.toDateString();
    (groups[key] ||= []).push(e);
  }
  return groups;
}

function TimelinePage() {
  const fn = useServerFn(listSecurityEvents);
  const [events, setEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { fn().then((d) => setEvents(d as Event[])).finally(() => setLoading(false)); }, [fn]);

  const grouped = groupByDay(events);
  const dayKeys = Object.keys(grouped);

  return (
    <main className="min-h-screen text-foreground">
      <header className="border-b border-border/60 backdrop-blur-md bg-background/70">
        <div className="mx-auto max-w-3xl px-6 py-4">
          <Link to="/" className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-4 w-4" /> Back to dashboard
          </Link>
        </div>
      </header>
      <div className="mx-auto max-w-3xl px-6 py-8">
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <Activity className="h-5 w-5" style={{ color: "var(--safe)" }} /> Security timeline
        </h1>
        <p className="text-sm text-muted-foreground mt-1">Every important security event on your MailGuard account.</p>

        {loading ? (
          <div className="mt-8 flex items-center gap-2 text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : dayKeys.length === 0 ? (
          <div className="mt-8 panel p-6 text-sm text-muted-foreground">No events yet. Run a scan or sign in from another device.</div>
        ) : (
          <div className="mt-6 space-y-8">
            {dayKeys.map((day) => (
              <section key={day}>
                <h2 className="text-xs uppercase tracking-wider text-muted-foreground font-mono mb-3">{day}</h2>
                <ol className="relative border-l border-border ml-2 space-y-3">
                  {grouped[day].map((e) => {
                    const { Icon, color } = iconFor(e.kind, e.severity);
                    return (
                      <li key={e.id} className="ml-4">
                        <div className="absolute -left-[7px] mt-1.5 h-3 w-3 rounded-full border-2"
                             style={{ background: "var(--background)", borderColor: color }} />
                        <div className="panel p-3 flex items-start gap-3">
                          <Icon className="h-4 w-4 mt-0.5 flex-shrink-0" style={{ color }} />
                          <div className="min-w-0 flex-1">
                            <div className="text-sm">{e.summary}</div>
                            <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                              {new Date(e.created_at).toLocaleTimeString()} · {e.kind}
                            </div>
                          </div>
                        </div>
                      </li>
                    );
                  })}
                </ol>
              </section>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
