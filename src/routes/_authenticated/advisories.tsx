import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useState } from "react";
import { RefreshCw, ShieldAlert, ExternalLink, Loader2, ArrowLeft, Radio } from "lucide-react";
import { getAdvisories, type Advisory } from "@/lib/advisories.functions";
import { useAuth } from "@/lib/auth-context";

export const Route = createFileRoute("/_authenticated/advisories")({
  component: Page,
});

function Page() {
  const { ready, session } = useAuth();
  const fetchAdvisories = useServerFn(getAdvisories);
  const [items, setItems] = useState<Advisory[]>([]);
  const [source, setSource] = useState<"live" | "fallback" | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [fetchedAt, setFetchedAt] = useState<number>(0);

  const load = async () => {
    setLoading(true); setErr(null);
    try {
      const res = await fetchAdvisories();
      setItems(res.items); setSource(res.source); setFetchedAt(res.fetchedAt);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load advisories.");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  if (!ready || !session) return <main className="min-h-screen" />;

  return (
    <main className="min-h-screen">
      <div className="mx-auto max-w-4xl px-6 py-8 space-y-4">
        <div className="flex items-center justify-between">
          <Link to="/" className="inline-flex items-center gap-2 text-xs font-mono text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" /> Back to dashboard
          </Link>
          <button onClick={load} disabled={loading}
                  className="inline-flex items-center gap-1.5 text-xs font-mono px-2.5 py-1.5 rounded-md border border-border hover:bg-accent disabled:opacity-50">
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Refresh
          </button>
        </div>

        <div className="panel p-5">
          <header className="flex items-center gap-2 mb-1">
            <ShieldAlert className="h-4 w-4" style={{ color: "var(--warn)" }} />
            <h1 className="text-lg font-semibold">Live CERT-In advisories</h1>
            <span className="chip text-[10px] ml-auto" style={{ color: source === "live" ? "var(--safe)" : "var(--warn)" }}>
              <Radio className="h-3 w-3" /> {source === "live" ? "Live feed" : source === "fallback" ? "Curated feed" : "…"}
            </span>
          </header>
          <p className="text-xs text-muted-foreground mb-3">
            Latest India-specific cyber threats & what to watch for.
            {fetchedAt > 0 && <> Updated {new Date(fetchedAt).toLocaleString()}.</>}
          </p>

          {err && <div className="text-xs rounded-md border px-3 py-2 mb-3"
                       style={{ borderColor: "var(--critical)", color: "var(--critical)" }}>{err}</div>}

          {loading && items.length === 0 ? (
            <p className="text-xs text-muted-foreground">Loading advisories…</p>
          ) : (
            <ul className="space-y-3">
              {items.map((a, i) => (
                <li key={i} className="rounded-md border border-border bg-card/50 p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <a href={a.link} target="_blank" rel="noreferrer"
                         className="text-sm font-semibold hover:underline inline-flex items-center gap-1.5">
                        {a.title} <ExternalLink className="h-3 w-3 opacity-60" />
                      </a>
                      <div className="text-[11px] text-muted-foreground font-mono mt-0.5">{a.pubDate}</div>
                    </div>
                  </div>
                  {a.summary && <p className="text-xs text-muted-foreground mt-2 leading-relaxed">{a.summary}</p>}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="panel p-4 text-xs text-muted-foreground">
          Source: <a className="underline" href="https://www.cert-in.org.in" target="_blank" rel="noreferrer">cert-in.org.in</a>.
          When the live feed is unreachable, MailGuard shows a curated list of the most common India-specific scam themes.
        </div>
      </div>
    </main>
  );
}
