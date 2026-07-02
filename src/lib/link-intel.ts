// Client-side URL intelligence. Pure functions — no network calls.
// Scores each URL for shorteners, typosquats, homoglyphs, suspicious TLDs, IP literals, entropy.

export type LinkSeverity = "low" | "medium" | "high" | "critical";
export type LinkReason = { code: string; label: string; weight: number };

export type LinkScore = {
  url: string;
  host: string;
  severity: LinkSeverity;
  score: number; // 0-100
  reasons: LinkReason[];
};

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd", "cutt.ly",
  "rebrand.ly", "shorturl.at", "rb.gy", "s.id", "lnkd.in", "tiny.cc", "shorte.st",
  "adf.ly", "bit.do", "mcaf.ee", "surl.li", "chilp.it", "clck.ru",
]);

const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "xyz", "top", "click", "link", "country", "tk", "ml", "ga", "cf", "gq",
  "kim", "work", "rest", "quest", "loan", "review", "monster", "beauty", "cyou", "buzz",
  "icu", "bar", "cam", "date", "science", "party", "trade", "webcam", "download", "stream",
  "ru", "su", "cn", "info", "biz",
]);

// Top Indian & global brands most impersonated
const TOP_BRANDS = [
  "google", "youtube", "gmail", "microsoft", "office365", "outlook", "apple", "icloud",
  "facebook", "instagram", "whatsapp", "linkedin", "twitter",
  "amazon", "flipkart", "myntra", "meesho",
  "paytm", "phonepe", "gpay", "googlepay", "bhim", "upi", "razorpay",
  "sbi", "hdfcbank", "icicibank", "axisbank", "kotak", "pnb", "bank",
  "rbi", "npci", "incometax", "irs",
  "netflix", "spotify", "linkedin", "paypal", "stripe",
  "dhl", "fedex", "bluedart", "dtdc", "indiapost", "usps",
  "airtel", "jio", "vodafone", "vi", "bsnl",
];

const HOMOGLYPH_MAP: Record<string, string> = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", // cyrillic look-alikes
};

function normalizeForHomoglyph(s: string): string {
  return [...s.toLowerCase()].map((c) => HOMOGLYPH_MAP[c] ?? c).join("");
}

// Damerau-Levenshtein (bounded, small strings)
function editDistance(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return 99;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + cost);
      }
    }
  }
  return dp[m][n];
}

function shannonEntropy(s: string): number {
  const map: Record<string, number> = {};
  for (const c of s) map[c] = (map[c] ?? 0) + 1;
  let h = 0; const n = s.length;
  for (const k in map) { const p = map[k] / n; h -= p * Math.log2(p); }
  return h;
}

const URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"'()]+)/gi;

export function extractUrls(text: string): string[] {
  if (!text) return [];
  const raw = text.match(URL_RE) ?? [];
  const cleaned = raw.map((u) => u.replace(/[.,;:!?)\]]+$/, ""));
  return Array.from(new Set(cleaned));
}

function parseHost(url: string): string | null {
  try {
    const u = new URL(url.startsWith("http") ? url : `http://${url}`);
    return u.hostname.toLowerCase();
  } catch { return null; }
}

export function scoreLink(url: string): LinkScore {
  const host = parseHost(url) ?? url;
  const reasons: LinkReason[] = [];
  let score = 0;

  const parts = host.split(".");
  const tld = parts[parts.length - 1] ?? "";
  const sld = parts.length >= 2 ? parts[parts.length - 2] : host;

  // IP literal
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    reasons.push({ code: "ip", label: "Uses raw IP address instead of a domain", weight: 45 });
    score += 45;
  }

  // Punycode
  if (host.includes("xn--")) {
    reasons.push({ code: "punycode", label: "Punycode domain (may hide non-Latin look-alikes)", weight: 30 });
    score += 30;
  }

  // Shortener
  if (SHORTENERS.has(host) || SHORTENERS.has(parts.slice(-2).join("."))) {
    reasons.push({ code: "shortener", label: "URL shortener — hides the real destination", weight: 35 });
    score += 35;
  }

  // Suspicious TLD
  if (SUSPICIOUS_TLDS.has(tld)) {
    reasons.push({ code: "tld", label: `Suspicious top-level domain .${tld}`, weight: 25 });
    score += 25;
  }

  // Homoglyph normalization -> brand match
  const norm = normalizeForHomoglyph(sld);
  if (norm !== sld) {
    for (const brand of TOP_BRANDS) {
      if (norm === brand) {
        reasons.push({ code: "homoglyph", label: `Homoglyph impersonation of "${brand}"`, weight: 55 });
        score += 55;
        break;
      }
    }
  }

  // Typosquat: distance 1-2 from a top brand (but not exact)
  for (const brand of TOP_BRANDS) {
    if (sld === brand) break; // legitimate
    const d = editDistance(sld, brand);
    if (d >= 1 && d <= 2 && Math.abs(sld.length - brand.length) <= 2 && brand.length >= 5) {
      reasons.push({ code: "typosquat", label: `Looks like a typo of "${brand}" (edit distance ${d})`, weight: 50 });
      score += 50;
      break;
    }
  }

  // Brand name in subdomain but not the registrable domain (e.g. sbi.login-verify.xyz)
  const subdomains = parts.slice(0, -2).join(".");
  for (const brand of TOP_BRANDS) {
    if (subdomains.includes(brand) && sld !== brand) {
      reasons.push({ code: "brand-in-subdomain", label: `Brand "${brand}" in subdomain — real domain is ${sld}.${tld}`, weight: 40 });
      score += 40;
      break;
    }
  }

  // Excessive hyphens / length
  if ((sld.match(/-/g)?.length ?? 0) >= 3) {
    reasons.push({ code: "hyphens", label: "Many hyphens in domain (common in scam URLs)", weight: 12 });
    score += 12;
  }
  if (host.length >= 45) {
    reasons.push({ code: "long", label: "Unusually long hostname", weight: 8 });
    score += 8;
  }

  // Entropy — random-looking domains
  if (sld.length >= 8 && shannonEntropy(sld) >= 3.6) {
    reasons.push({ code: "entropy", label: "High-entropy (random-looking) domain", weight: 15 });
    score += 15;
  }

  // Credential-baiting path
  if (/(login|verify|secure|account|update|confirm|signin|otp|kyc|reset)/i.test(url) && score > 0) {
    reasons.push({ code: "keywords", label: "Contains credential-baiting keywords", weight: 10 });
    score += 10;
  }

  score = Math.min(100, score);
  const severity: LinkSeverity =
    score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";

  if (reasons.length === 0) {
    reasons.push({ code: "clean", label: "No local heuristic red flags detected", weight: 0 });
  }

  return { url, host, severity, score, reasons };
}

export function scoreLinks(urls: string[]): LinkScore[] {
  return urls.map(scoreLink).sort((a, b) => b.score - a.score);
}
