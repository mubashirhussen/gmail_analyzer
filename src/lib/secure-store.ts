// Local encrypted storage for MailGuard.
// PBKDF2(passcode) -> AES-GCM key. History blobs are encrypted at rest.

const VERIFIER_PLAINTEXT = "MG_OK_v1";
const PBKDF2_ITERS = 150_000;

export type StoredAccount = {
  id: string;
  username: string;
  email: string;
  createdAt: number;
  // passcode verifier (encrypted known plaintext)
  saltB64: string;
  ivB64: string;
  ctB64: string;
  lastLoginAt?: number;
};

export type HistoryItem = {
  id: string;
  at: number;
  sender: string;
  subject: string;
  bodyPreview: string;
  verdict: "safe" | "suspicious" | "phishing" | "fraud";
  riskScore: number;
  confidence: number;
  summary: string;
  indicators: { category: string; severity: string; detail: string }[];
  suspiciousLinks: { url: string; reason: string; risk: string }[];
  recommendations: string[];
};

const ACCOUNTS_KEY = "mg.accounts.v1";
const CURRENT_KEY = "mg.current.v1";
const HISTORY_KEY = (uid: string) => `mg.history.v1.${uid}`;

// --- base64 helpers ---
function b64encode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- crypto ---
async function deriveKey(passcode: string, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passcode),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptJSON(key: CryptoKey, value: unknown): Promise<{ ivB64: string; ctB64: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(value));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, data as BufferSource);
  return { ivB64: b64encode(iv), ctB64: b64encode(ct) };
}
async function decryptJSON<T>(key: CryptoKey, ivB64: string, ctB64: string): Promise<T> {
  const iv = b64decode(ivB64);
  const ct = b64decode(ctB64);
  const buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, ct as BufferSource);
  return JSON.parse(new TextDecoder().decode(buf)) as T;
}

// --- storage helpers ---
function ls(): Storage | null {
  if (typeof window === "undefined") return null;
  return window.localStorage;
}

export function listAccounts(): StoredAccount[] {
  const store = ls();
  if (!store) return [];
  try {
    return JSON.parse(store.getItem(ACCOUNTS_KEY) || "[]") as StoredAccount[];
  } catch { return []; }
}
function saveAccounts(list: StoredAccount[]) {
  ls()?.setItem(ACCOUNTS_KEY, JSON.stringify(list));
}
export function getCurrentAccountId(): string | null {
  return ls()?.getItem(CURRENT_KEY) ?? null;
}
export function setCurrentAccountId(id: string | null) {
  const s = ls(); if (!s) return;
  if (id) s.setItem(CURRENT_KEY, id); else s.removeItem(CURRENT_KEY);
}

// --- public API ---
export async function createAccount(args: {
  username: string; email: string; passcode: string;
}): Promise<StoredAccount> {
  const username = args.username.trim();
  const email = args.email.trim().toLowerCase();
  if (!username) throw new Error("Username required.");
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error("Enter a valid email.");
  if (args.passcode.length < 6) throw new Error("Passcode must be at least 6 characters.");
  const accounts = listAccounts();
  if (accounts.some((a) => a.email === email)) throw new Error("An account with that email already exists.");

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(args.passcode, salt);
  const { ivB64, ctB64 } = await encryptJSON(key, VERIFIER_PLAINTEXT);

  const acc: StoredAccount = {
    id: crypto.randomUUID(),
    username, email,
    createdAt: Date.now(),
    saltB64: b64encode(salt),
    ivB64, ctB64,
  };
  saveAccounts([...accounts, acc]);
  return acc;
}

export async function unlockAccount(accountId: string, passcode: string): Promise<{ account: StoredAccount; key: CryptoKey }> {
  const accounts = listAccounts();
  const acc = accounts.find((a) => a.id === accountId);
  if (!acc) throw new Error("Account not found.");
  const salt = b64decode(acc.saltB64);
  const key = await deriveKey(passcode, salt);
  try {
    const verified = await decryptJSON<string>(key, acc.ivB64, acc.ctB64);
    if (verified !== VERIFIER_PLAINTEXT) throw new Error("bad");
  } catch {
    throw new Error("Incorrect passcode.");
  }
  acc.lastLoginAt = Date.now();
  saveAccounts(accounts.map((a) => (a.id === acc.id ? acc : a)));
  return { account: acc, key };
}

export async function loadHistory(accountId: string, key: CryptoKey): Promise<HistoryItem[]> {
  const raw = ls()?.getItem(HISTORY_KEY(accountId));
  if (!raw) return [];
  try {
    const { ivB64, ctB64 } = JSON.parse(raw);
    return await decryptJSON<HistoryItem[]>(key, ivB64, ctB64);
  } catch { return []; }
}

export async function saveHistory(accountId: string, key: CryptoKey, items: HistoryItem[]): Promise<void> {
  const blob = await encryptJSON(key, items);
  ls()?.setItem(HISTORY_KEY(accountId), JSON.stringify(blob));
}

export function deleteHistory(accountId: string): void {
  ls()?.removeItem(HISTORY_KEY(accountId));
}

export function deleteAccount(accountId: string): void {
  const remaining = listAccounts().filter((a) => a.id !== accountId);
  saveAccounts(remaining);
  deleteHistory(accountId);
  if (getCurrentAccountId() === accountId) setCurrentAccountId(null);
}
