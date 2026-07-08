import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, ShieldAlert, TrendingUp, Target, Radar, Info, ExternalLink } from "lucide-react";
import { THREAT_CATALOG, type ThreatCard } from "@/lib/threat-catalog";
import { useAuth } from "@/lib/auth-context";

export const Route = createFileRoute("/_authenticated/threats")({
  head: () => ({
    meta: [
      { title: "Top Email Threats 2025-2026 — MailGuard" },
      { name: "description", content: "The six most damaging email, link, and QR-code attacks of 2025-2026, with detection signals and user actions." },
      { property: "og:title", content: "Top Email Threats 2025-2026" },
      { property: "og:description", content: "Real-world 2025-2026 losses, techniques, and how MailGuard detects each." },
    ],
  }),
  component: Page,
});

function color(c: ThreatCard["color"]) {
  return c === "critical" ? "var(--critical)" : c === "danger" ? "var(--danger)" : "var(--warn)";
}

function Page() {
  const { ready, session } = useAuth();
  if (!ready || !session) return <main className="min-h-screen" />;
  return (
    <main className="min-h-screen">
      <div className="mx-auto max-w-5xl px-6 py-8 space-y-5">
        <Link to="/" className="inline-flex items-center gap-2 text-xs font-mono text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-3.5 w-3.5" /> Back to dashboard
        </Link>

        <header className="panel p-5">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5" style={{ color: "var(--danger)" }} />
            <h1 className="text-xl font-semibold">Top 6 Real-World Threats · 2025 / 2026</h1>
          </div>
          <p className="text-sm text-muted-foreground mt-2">
            Curated from FBI IC3 2025, Verizon DBIR 2025, Europol IOCTA 2026, Google Advisory (Jun 2026),
            UK Action Fraud, and Keepnet Labs. For each threat we show how it works, the exact signals
            MailGuard uses to catch it, and the action you should take.
          </p>
        </header>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {THREAT_CATALOG.map((t) => {
            const col = color(t.color);
            return (
              <article key={t.id} className="panel p-5 flex flex-col gap-3"
                       style={{ borderColor: `color-mix(in oklab, ${col} 35%, var(--border))` }}>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <Target className="h-4 w-4" style={{ color: col }} />
                    <h2 className="text-base font-semibold">{t.title}</h2>
                  </div>
                  <p className="text-sm text-muted-foreground">{t.tagline}</p>
                </div>

                <div className="grid grid-cols-1 gap-2 text-xs">
                  <div className="rounded-md border border-border px-2.5 py-1.5 bg-card/50">
                    <span className="font-mono uppercase tracking-wider text-[10px] text-muted-foreground">Impact · </span>
                    <span style={{ color: col }} className="font-semibold">{t.loss}</span>
                  </div>
                  <div className="flex items-start gap-1.5 text-muted-foreground">
                    <TrendingUp className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
                    <span>{t.trend}</span>
                  </div>
                </div>

                <Block title="How the attack works" color={col} items={t.techniques} />
                <Block title="What MailGuard detects" color="var(--safe)" items={t.detection} icon={<Radar className="h-3 w-3" />} />
                <Block title="What you should do" color="var(--safe)" items={t.userAction} />

                <div className="mt-auto pt-2 border-t border-border flex items-center justify-between gap-2 text-[10px] font-mono text-muted-foreground">
                  <span className="inline-flex items-center gap-1">
                    <Info className="h-3 w-3" /> Handled by: <code className="text-foreground">{t.mapsTo}</code>
                  </span>
                  <span>{t.sources.join(" · ")}</span>
                </div>
              </article>
            );
          })}
        </div>

        <footer className="panel p-4 text-xs text-muted-foreground flex items-start gap-2">
          <ExternalLink className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
          <span>
            Every scan you run in MailGuard is checked against all six of these vectors. When you see a
            verdict, the <span className="text-foreground font-semibold">"Why this verdict"</span> panel
            explains which of these threat families fired and what the attacker could obtain if you acted on the message.
          </span>
        </footer>
      </div>
    </main>
  );
}

function Block({ title, color, items, icon }: { title: string; color: string; items: string[]; icon?: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider font-mono mb-1 flex items-center gap-1.5" style={{ color }}>
        {icon} {title}
      </div>
      <ul className="space-y-1 text-xs">
        {items.map((s, i) => (
          <li key={i} className="flex gap-2"><span style={{ color }}>▸</span><span>{s}</span></li>
        ))}
      </ul>
    </div>
  );
}
