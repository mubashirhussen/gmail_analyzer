// Live URL threat-intelligence — NO API KEYS REQUIRED.
// Uses only free public endpoints:
//   • RDAP (rdap.org)                — real domain age, registrar, creation date
//   • crt.sh                          — SSL certificate transparency (first-seen date)
//   • URLScan.io public /search       — how many public scans exist for the host + latest verdicts
//   • PhishTank + OpenPhish feeds     — confirmed phishing URL membership
//   • Cloudflare DoH                  — resolves the host, catches NXDOMAIN / dead domains
//
// Every provider is called in parallel per URL, each with a short timeout, and each
// degrades independently — a single provider failure never breaks the result.

import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const InputSchema = z.object({
  urls: z.array(z.string().min(3).max(2000)).min(1).max(10),
});

export type ProviderStatus = "ok" | "clean" | "flagged" | "unknown" | "error" | "skipped";

export type ProviderResult = {
  provider: string;
  status: ProviderStatus;
  detail: string;
  link?: string;
};

export type UrlIntel = {
  url: string;
  host: string;
  overallRisk: "low" | "medium" | "high" | "critical" | "unknown";
  domainAgeDays: number | null;
  publicScanCount: number | null;
  reportedPhishing: boolean;
  providers: ProviderResult[];
};

export type ThreatIntelResult = {
  results: UrlIntel[];
  fetchedAt: number;
  feedsUsed: string[];
};

// -------------------- utilities --------------------

function safeHost(url: string): string | null {
  try {
    const u = new URL(url.startsWith("http") ? url : `http://${url}`);
    return u.hostname.toLowerCase();
  } catch { return null; }
}

function registrableDomain(host: string): string {
  // naive eTLD+1 — good enough for RDAP / crt.sh lookups
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const twoPartTlds = new Set(["co.uk", "co.in", "org.in", "gov.in", "ac.in", "com.au", "com.br"]);
  const last2 = parts.slice(-2).join(".");
  const last3 = parts.slice(-3).join(".");
  return twoPartTlds.has(last2) ? last3 : last2;
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return await Promise.race([
    p,
    new Promise<T>((_, rej) => setTimeout(() => rej(new Error(`timeout ${ms}ms`)), ms)),
  ]);
}

async function fetchJson(url: string, ms = 6000, init?: RequestInit): Promise<unknown> {
  const res = await withTimeout(
    fetch(url, { ...init, headers: { accept: "application/json", ...(init?.headers ?? {}) } }),
    ms,
  );
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return await res.json();
}

async function fetchText(url: string, ms = 6000): Promise<string> {
  const res = await withTimeout(fetch(url), ms);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return await res.text();
}

// -------------------- shared phishing feeds (per-worker cache) --------------------

type FeedCache = { at: number; hosts: Set<string>; urls: Set<string>; sources: string[] };
let FEED_CACHE: FeedCache | null = null;
const FEED_TTL_MS = 60 * 60 * 1000; // 1h

async function loadPhishFeeds(): Promise<FeedCache> {
  if (FEED_CACHE && Date.now() - FEED_CACHE.at < FEED_TTL_MS) return FEED_CACHE;

  const hosts = new Set<string>();
  const urls = new Set<string>();
  const sources: string[] = [];

  // OpenPhish — plain text feed of confirmed phishing URLs (community).
  try {
    const txt = await fetchText("https://openphish.com/feed.txt", 8000);
    for (const line of txt.split(/\r?\n/)) {
      const u = line.trim();
      if (!u || u.startsWith("#")) continue;
      urls.add(u);
      const h = safeHost(u);
      if (h) hosts.add(h);
    }
    sources.push("OpenPhish");
  } catch { /* ignore */ }

  // PhishTank — public JSON feed, no key required for the online-valid feed.
  try {
    const data = (await fetchJson("https://data.phishtank.com/data/online-valid.json", 10000)) as
      Array<{ url?: string }>;
    if (Array.isArray(data)) {
      for (const row of data) {
        if (!row?.url) continue;
        urls.add(row.url);
        const h = safeHost(row.url);
        if (h) hosts.add(h);
      }
      sources.push("PhishTank");
    }
  } catch { /* ignore */ }

  FEED_CACHE = { at: Date.now(), hosts, urls, sources };
  return FEED_CACHE;
}

// -------------------- providers --------------------

async function checkRdap(host: string): Promise<ProviderResult & { ageDays?: number }> {
  const domain = registrableDomain(host);
  try {
    const data = (await fetchJson(`https://rdap.org/domain/${domain}`, 7000)) as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{ roles?: string[]; vcardArray?: unknown }>;
    };
    const reg = data.events?.find((e) => /registration/i.test(e.eventAction ?? ""));
    if (!reg?.eventDate) {
      return { provider: "RDAP (domain age)", status: "unknown", detail: `No registration date for ${domain}` };
    }
    const created = new Date(reg.eventDate);
    const ageDays = Math.floor((Date.now() - created.getTime()) / 86_400_000);
    const detail = `${domain} registered ${created.toISOString().slice(0, 10)} (${ageDays} days old)`;
    const status: ProviderStatus =
      ageDays < 30 ? "flagged" : ageDays < 180 ? "unknown" : "clean";
    return { provider: "RDAP (domain age)", status, detail, ageDays };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // rdap.org returns 404 for unknown / dead domains — that's a signal, not an error.
    if (/->\s*404/.test(msg)) {
      return {
        provider: "RDAP (domain age)",
        status: "flagged",
        detail: `No RDAP record for ${domain} — domain may not exist or use a private TLD`,
      };
    }
    return { provider: "RDAP (domain age)", status: "error", detail: msg };
  }
}

async function checkCrtSh(host: string): Promise<ProviderResult> {
  const domain = registrableDomain(host);
  try {
    const rows = (await fetchJson(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, 8000)) as
      Array<{ not_before?: string }>;
    if (!Array.isArray(rows) || rows.length === 0) {
      return {
        provider: "crt.sh (SSL history)",
        status: "flagged",
        detail: `No SSL certificate ever issued for ${domain}`,
        link: `https://crt.sh/?q=${encodeURIComponent(domain)}`,
      };
    }
    let earliest = Infinity;
    for (const r of rows) {
      const t = r.not_before ? Date.parse(r.not_before) : NaN;
      if (Number.isFinite(t) && t < earliest) earliest = t;
    }
    if (!Number.isFinite(earliest)) {
      return { provider: "crt.sh (SSL history)", status: "unknown", detail: `${rows.length} certs found for ${domain}` };
    }
    const ageDays = Math.floor((Date.now() - earliest) / 86_400_000);
    const status: ProviderStatus = ageDays < 30 ? "flagged" : ageDays < 180 ? "unknown" : "clean";
    return {
      provider: "crt.sh (SSL history)",
      status,
      detail: `${rows.length} certs · first issued ${new Date(earliest).toISOString().slice(0, 10)} (${ageDays}d ago)`,
      link: `https://crt.sh/?q=${encodeURIComponent(domain)}`,
    };
  } catch (err) {
    return { provider: "crt.sh (SSL history)", status: "error", detail: err instanceof Error ? err.message : String(err) };
  }
}

async function checkUrlscan(host: string): Promise<ProviderResult & { count?: number }> {
  try {
    const data = (await fetchJson(
      `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`domain:${host}`)}&size=5`,
      7000,
    )) as {
      total?: number;
      results?: Array<{ verdicts?: { overall?: { malicious?: boolean; score?: number } }; task?: { url?: string } }>;
    };
    const total = data.total ?? 0;
    const malicious = (data.results ?? []).filter((r) => r.verdicts?.overall?.malicious).length;
    let status: ProviderStatus = "clean";
    let detail = `${total} public scan${total === 1 ? "" : "s"} of ${host}`;
    if (malicious > 0) {
      status = "flagged";
      detail = `${malicious} of ${data.results?.length ?? 0} recent scans flagged malicious (${total} total scans)`;
    } else if (total === 0) {
      status = "unknown";
      detail = `Never publicly scanned before — no reputation data on ${host}`;
    }
    return {
      provider: "URLScan.io",
      status,
      detail,
      link: `https://urlscan.io/search/#domain:${encodeURIComponent(host)}`,
      count: total,
    };
  } catch (err) {
    return { provider: "URLScan.io", status: "error", detail: err instanceof Error ? err.message : String(err) };
  }
}

async function checkDoH(host: string): Promise<ProviderResult> {
  try {
    const data = (await fetchJson(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
      5000,
      { headers: { accept: "application/dns-json" } },
    )) as { Status?: number; Answer?: Array<{ data?: string }> };
    if (data.Status === 3) {
      return { provider: "DNS (Cloudflare)", status: "flagged", detail: `NXDOMAIN — ${host} does not resolve` };
    }
    const ips = (data.Answer ?? []).map((a) => a.data).filter(Boolean);
    if (ips.length === 0) {
      return { provider: "DNS (Cloudflare)", status: "unknown", detail: `${host} has no A records` };
    }
    return { provider: "DNS (Cloudflare)", status: "clean", detail: `Resolves to ${ips.slice(0, 3).join(", ")}` };
  } catch (err) {
    return { provider: "DNS (Cloudflare)", status: "error", detail: err instanceof Error ? err.message : String(err) };
  }
}

function checkFeeds(url: string, host: string, feeds: FeedCache): ProviderResult {
  const inUrls = feeds.urls.has(url) || feeds.urls.has(url.replace(/\/$/, ""));
  const inHosts = feeds.hosts.has(host);
  if (inUrls) {
    return {
      provider: "Community phishing feeds",
      status: "flagged",
      detail: `Exact URL is on ${feeds.sources.join(" / ") || "phishing"} block-list`,
    };
  }
  if (inHosts) {
    return {
      provider: "Community phishing feeds",
      status: "flagged",
      detail: `Host is on ${feeds.sources.join(" / ") || "phishing"} block-list`,
    };
  }
  if (feeds.sources.length === 0) {
    return { provider: "Community phishing feeds", status: "skipped", detail: "Feeds unavailable right now" };
  }
  return {
    provider: "Community phishing feeds",
    status: "clean",
    detail: `Not on ${feeds.sources.join(" / ")} (${feeds.urls.size.toLocaleString()} URLs checked)`,
  };
}

// -------------------- orchestration --------------------

function summarizeRisk(providers: ProviderResult[]): UrlIntel["overallRisk"] {
  const flagged = providers.filter((p) => p.status === "flagged").length;
  const clean = providers.filter((p) => p.status === "clean").length;
  if (flagged >= 3) return "critical";
  if (flagged === 2) return "high";
  if (flagged === 1) return "medium";
  if (clean >= 2) return "low";
  return "unknown";
}

export const enrichUrls = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => InputSchema.parse(input))
  .handler(async ({ data }): Promise<ThreatIntelResult> => {
    const feeds = await loadPhishFeeds();

    const results = await Promise.all(
      data.urls.map(async (url): Promise<UrlIntel> => {
        const host = safeHost(url);
        if (!host) {
          return {
            url, host: url, overallRisk: "unknown",
            domainAgeDays: null, publicScanCount: null, reportedPhishing: false,
            providers: [{ provider: "URL parser", status: "error", detail: "Could not parse URL" }],
          };
        }

        const [rdap, crt, urlscan, doh] = await Promise.all([
          checkRdap(host).catch((e) => ({ provider: "RDAP (domain age)", status: "error" as const, detail: String(e) })),
          checkCrtSh(host).catch((e) => ({ provider: "crt.sh (SSL history)", status: "error" as const, detail: String(e) })),
          checkUrlscan(host).catch((e) => ({ provider: "URLScan.io", status: "error" as const, detail: String(e) })),
          checkDoH(host).catch((e) => ({ provider: "DNS (Cloudflare)", status: "error" as const, detail: String(e) })),
        ]);
        const feed = checkFeeds(url, host, feeds);

        const providers: ProviderResult[] = [feed, rdap, crt, urlscan, doh];
        const domainAgeDays = "ageDays" in rdap && typeof rdap.ageDays === "number" ? rdap.ageDays : null;
        const publicScanCount = "count" in urlscan && typeof urlscan.count === "number" ? urlscan.count : null;
        const reportedPhishing = feed.status === "flagged";

        return {
          url, host,
          overallRisk: summarizeRisk(providers),
          domainAgeDays, publicScanCount, reportedPhishing,
          providers,
        };
      }),
    );

    return { results, fetchedAt: Date.now(), feedsUsed: feeds.sources };
  });
