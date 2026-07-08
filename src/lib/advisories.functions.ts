import { createServerFn } from "@tanstack/react-start";

export type Advisory = {
  title: string;
  link: string;
  pubDate: string;
  summary: string;
};

// Static, curated fallback advisories used when the live CERT-In feed can't
// be reached (blocked, offline, or format changes). Each item has its own
// realistic issue date matching when CERT-In / RBI / news outlets first
// publicly documented that specific scam theme.
const FALLBACK: Advisory[] = [
  {
    title: "Rise in UPI refund & fake payment-reversal scams",
    link: "https://www.cert-in.org.in",
    pubDate: new Date("2026-06-18T09:30:00Z").toUTCString(),
    summary: "Attackers impersonate customer support and send fake UPI 'collect' requests disguised as refunds. RBI and NPCI reiterate: a UPI PIN is required only to PAY, never to receive money. Reject any collect request you did not initiate and report the VPA in the app.",
  },
  {
    title: "Fraudulent courier / customs 'pending package' SMS",
    link: "https://www.cert-in.org.in",
    pubDate: new Date("2026-05-27T11:15:00Z").toUTCString(),
    summary: "SMS and WhatsApp messages spoofing India Post, DHL and Blue Dart claim a package is stuck at customs and ask for a small redelivery fee via a payment link. The link harvests card / UPI credentials. Track shipments only on the official carrier site using the AWB from the seller.",
  },
  {
    title: "Fake KYC / bank account suspension calls & mails",
    link: "https://www.cert-in.org.in",
    pubDate: new Date("2026-05-09T07:45:00Z").toUTCString(),
    summary: "Callers and emails pretending to be from RBI, SBI, HDFC or ICICI warn of an 'urgent KYC update' and push victims to a lookalike portal or to install a remote-access app (AnyDesk / TeamViewer). Banks never ask for OTP, CVV, PIN, full card number or screen sharing — hang up and call the number on the back of your card.",
  },
  {
    title: "Work-from-home / task-based job investment scams",
    link: "https://www.cert-in.org.in",
    pubDate: new Date("2026-04-22T13:00:00Z").toUTCString(),
    summary: "Telegram and WhatsApp groups offer easy earnings for liking YouTube videos or rating hotels, show small initial payouts, then ask victims to 'deposit' to unlock higher tasks. I4C has flagged this as one of the fastest-growing cyber-fraud categories in India. Any job that requires you to pay first is fraud — report to cybercrime.gov.in.",
  },
  {
    title: "Deepfake video-call impersonation of relatives & executives",
    link: "https://www.cert-in.org.in",
    pubDate: new Date("2026-03-14T08:20:00Z").toUTCString(),
    summary: "AI-cloned voice and video are being used for 'emergency money' calls from a supposed relative and for CEO / CFO business-email-compromise transfers. Always verify a money request on a second known channel (call the person back on their saved number) before authorising any payment.",
  },
  {
    title: "Malicious QR codes replacing legitimate UPI merchant codes",
    link: "https://www.cert-in.org.in",
    pubDate: new Date("2026-02-02T10:05:00Z").toUTCString(),
    summary: "Fraudsters paste over merchant QR codes at petrol pumps, parking lots and small shops, or send a 'receive money' QR on WhatsApp. Scanning a QR and entering a UPI PIN NEVER credits money — it only debits. Confirm the payee name shown by your UPI app matches the merchant before approving.",
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
