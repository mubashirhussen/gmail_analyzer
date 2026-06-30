// Best-effort browser fingerprint + session token.
// No fingerprintjs-pro — small heuristic hash that's stable per browser+device.

export type DeviceInfo = {
  fingerprint: string;
  label: string;
  os: string;
  browser: string;
  tz: string;
};

function parseUA(ua: string): { os: string; browser: string } {
  const os =
    /Windows NT 10/.test(ua) ? "Windows 10/11"
    : /Windows/.test(ua) ? "Windows"
    : /Mac OS X/.test(ua) ? "macOS"
    : /Android/.test(ua) ? "Android"
    : /iPhone|iPad|iOS/.test(ua) ? "iOS"
    : /Linux/.test(ua) ? "Linux"
    : "Unknown OS";
  const browser =
    /Edg\//.test(ua) ? "Edge"
    : /OPR\//.test(ua) ? "Opera"
    : /Chrome\//.test(ua) ? "Chrome"
    : /Firefox\//.test(ua) ? "Firefox"
    : /Safari\//.test(ua) ? "Safari"
    : "Unknown";
  return { os, browser };
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  const arr = Array.from(new Uint8Array(buf));
  return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function canvasSignal(): string {
  try {
    const c = document.createElement("canvas");
    c.width = 200; c.height = 40;
    const ctx = c.getContext("2d");
    if (!ctx) return "no-canvas";
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillStyle = "#069";
    ctx.fillText("MailGuard-fp-🛡", 2, 2);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillRect(80, 1, 60, 20);
    return c.toDataURL().slice(-64);
  } catch { return "canvas-err"; }
}

export async function getDeviceInfo(): Promise<DeviceInfo> {
  const ua = navigator.userAgent;
  const { os, browser } = parseUA(ua);
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const screenSig = `${screen.width}x${screen.height}x${screen.colorDepth}`;
  const langs = (navigator.languages || [navigator.language]).join(",");
  const raw = [ua, screenSig, tz, langs, navigator.hardwareConcurrency, canvasSignal()].join("|");
  const fingerprint = await sha256Hex(raw);
  const label = `${browser} on ${os}`;
  return { fingerprint, label, os, browser, tz };
}

const SESSION_KEY = "mg.session_token.v1";
export function getOrCreateSessionToken(): string {
  let t = localStorage.getItem(SESSION_KEY);
  if (!t) {
    t = crypto.randomUUID();
    localStorage.setItem(SESSION_KEY, t);
  }
  return t;
}
export function clearSessionToken() { localStorage.removeItem(SESSION_KEY); }
