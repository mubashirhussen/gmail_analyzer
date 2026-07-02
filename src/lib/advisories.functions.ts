import { createServerFn } from "@tanstack/react-start";

export type Advisory = {
  title: string;
  link: string;
  pubDate: string;
  summary: string;
};

// Static, curated fallback advisories used when the live CERT-In feed can't
// be reached (blocked, offline, or format changes). These are hand-picked
// recurring India-specific threat themes so users always see actionable content.
const FALLBACK: Advisory[] = [
  {
    title: "Rise in UPI refund & fake payment-reversal scams",
    link: "https://www.cert-in.org.in",
    pubDate: new Date().toUTCString(),
    summary: "Attackers impersonate customer support and send fake UPI collect requests disguised as refunds. Never approve a UPI request you did not initiate.",
  },
  {
    title: "Fraudulent courier / customs 'pending package' SMS",
    link: "https://www.cert-in.org.in",
    pubDate: new Date().toUTCString(),
    summary: "Fake India Post / DHL / Blue Dart messages asking for a small redelivery fee harvest card details. Verify tracking only on the official carrier site.",
  },
  {
    title: "Fake KYC / bank account suspension calls & mails",
    link: "https://www.cert-in.org.in",
    pubDate: new Date().toUTCString(),
    summary: "RBI and banks never ask for OTP, CVV, PIN, or full card number over email/phone. Any such request is a scam.",
  },
  {
    title: "Work-from-home / task-based job investment scams",
    link: "https://www.cert-in.org.in",
    pubDate: new Date().toUTCString(),
    summary: "Telegram/WhatsApp groups promise easy earnings for liking videos or rating hotels, then demand deposits. Any 'job' that needs you to pay first is fraud.",
  },
  {
    title: "Deepfake video-call impersonation of relatives / executives",
    link: "https://www.cert-in.org.in",
    pubDate: new Date().toUTCString(),
    summary: "AI-generated voice/video is being used for emergency money requests and BEC. Verify on a second known channel before transferring any money.",
  },
  {
    title: "Malicious QR codes replacing legitimate UPI merchant codes",
    link: "https://www.cert-in.org.in",
    pubDate: new Date().toUTCString(),
    summary: "Scanning an unknown QR to 'receive' money is always a scam — UPI requires you to enter your PIN only when you PAY, never to receive.",
  },
];

const CERT_IN_RSS_CANDIDATES = [
  "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBRSS",
  "https://www.cert-in.org.in/RSS.jsp",
];

function stripCdata(s: string): string {
  return s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim();
}
function decodeHtml(s: string): string {
  return s
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&").replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/&nbsp;/g, " ")
    .replace(/<[^>]+>/g, "");
}
function pick(tag: string, block: string): string {
  const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i");
  const m = block.match(re);
  return m ? stripCdata(m[1]) : "";
}

function parseRss(xml: string): Advisory[] {
  const items = xml.match(/<item[\s\S]*?<\/item>/gi) ?? [];
  const out: Advisory[] = [];
  for (const raw of items.slice(0, 12)) {
    const title = decodeHtml(pick("title", raw));
    const link = decodeHtml(pick("link", raw));
    const pubDate = decodeHtml(pick("pubDate", raw));
    const desc = decodeHtml(pick("description", raw));
    if (title) {
      out.push({
        title,
        link: link || "https://www.cert-in.org.in",
        pubDate: pubDate || new Date().toUTCString(),
        summary: desc.slice(0, 320),
      });
    }
  }
  return out;
}

export const getAdvisories = createServerFn({ method: "GET" })
  .handler(async (): Promise<{ items: Advisory[]; source: "live" | "fallback"; fetchedAt: number }> => {
    for (const url of CERT_IN_RSS_CANDIDATES) {
      try {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), 6000);
        const res = await fetch(url, {
          headers: { "User-Agent": "MailGuard/1.0 (+advisory-fetcher)", Accept: "application/rss+xml, application/xml, text/xml, */*" },
          signal: controller.signal,
        });
        clearTimeout(t);
        if (!res.ok) continue;
        const xml = await res.text();
        const items = parseRss(xml);
        if (items.length > 0) return { items, source: "live", fetchedAt: Date.now() };
      } catch { /* try next */ }
    }
    return { items: FALLBACK, source: "fallback", fetchedAt: Date.now() };
  });
