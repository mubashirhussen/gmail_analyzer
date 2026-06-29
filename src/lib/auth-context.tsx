import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  changePasscode as changePasscodeStore,
  createAccount,
  deleteAccount as removeAccount,
  deleteHistory,
  getCurrentAccountId,
  listAccounts,
  loadHistory,
  saveHistory,
  setCurrentAccountId,
  unlockAccount,
  type HistoryItem,
  type StoredAccount,
} from "./secure-store";

// CryptoKey lives ONLY in this module-scoped map — never in React state.
// React state would expose it to platform instrumentation that walks the tree
// and tries to clone/inspect props; a derived AES-GCM key being introspected
// triggered "Failed to execute 'exportKey' on 'SubtleCrypto': key is not
// extractable" in the auth gate.
const KEYRING = new Map<string, CryptoKey>();
const AUTO_LOCK_MS = 10 * 60 * 1000; // 10 minutes of inactivity

type Session = { account: StoredAccount } | null;

type AuthCtx = {
  ready: boolean;
  accounts: StoredAccount[];
  session: Session;
  history: HistoryItem[];
  signUp: (a: { username: string; email: string; passcode: string }) => Promise<void>;
  login: (accountId: string, passcode: string) => Promise<void>;
  logout: () => void;
  switchAccount: () => void;
  lockNow: () => void;
  changePasscode: (current: string, next: string) => Promise<void>;
  addHistory: (item: HistoryItem) => Promise<void>;
  clearHistory: () => Promise<void>;
  deleteCurrentAccount: () => void;
  refreshAccounts: () => void;
};

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [accounts, setAccounts] = useState<StoredAccount[]>([]);
  const [session, setSession] = useState<Session>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const idleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setAccounts(listAccounts());
    setReady(true);
  }, []);

  const refreshAccounts = useCallback(() => setAccounts(listAccounts()), []);

  const lockNow = useCallback(() => {
    if (session) KEYRING.delete(session.account.id);
    setSession(null);
    setHistory([]);
    setCurrentAccountId(null);
  }, [session]);

  // inactivity auto-lock
  useEffect(() => {
    if (!session) return;
    const reset = () => {
      if (idleTimer.current) clearTimeout(idleTimer.current);
      idleTimer.current = setTimeout(() => lockNow(), AUTO_LOCK_MS);
    };
    const events: (keyof WindowEventMap)[] = ["mousemove", "keydown", "click", "scroll", "touchstart"];
    events.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    reset();
    return () => {
      if (idleTimer.current) clearTimeout(idleTimer.current);
      events.forEach((e) => window.removeEventListener(e, reset));
    };
  }, [session, lockNow]);

  const signUp: AuthCtx["signUp"] = useCallback(async (a) => {
    const acc = await createAccount(a);
    const { account, key } = await unlockAccount(acc.id, a.passcode);
    KEYRING.set(account.id, key);
    setCurrentAccountId(account.id);
    const hist = await loadHistory(account.id, key);
    setAccounts(listAccounts());
    setSession({ account });
    setHistory(hist);
  }, []);

  const login: AuthCtx["login"] = useCallback(async (id, passcode) => {
    const { account, key } = await unlockAccount(id, passcode);
    KEYRING.set(account.id, key);
    setCurrentAccountId(account.id);
    const hist = await loadHistory(account.id, key);
    setSession({ account });
    setHistory(hist);
    setAccounts(listAccounts());
  }, []);

  const logout = useCallback(() => {
    if (session) KEYRING.delete(session.account.id);
    setCurrentAccountId(null);
    setSession(null);
    setHistory([]);
  }, [session]);

  const switchAccount = useCallback(() => {
    if (session) KEYRING.delete(session.account.id);
    setSession(null);
    setHistory([]);
    setCurrentAccountId(null);
  }, [session]);

  const changePasscode: AuthCtx["changePasscode"] = useCallback(async (current, next) => {
    if (!session) throw new Error("Not signed in.");
    const { account, key } = await changePasscodeStore({
      accountId: session.account.id,
      currentPasscode: current,
      newPasscode: next,
    });
    KEYRING.set(account.id, key);
    setSession({ account });
    setAccounts(listAccounts());
  }, [session]);

  const addHistory: AuthCtx["addHistory"] = useCallback(async (item) => {
    if (!session) return;
    const key = KEYRING.get(session.account.id);
    if (!key) return;
    const next = [item, ...history].slice(0, 200);
    setHistory(next);
    await saveHistory(session.account.id, key, next);
  }, [session, history]);

  const clearHistory: AuthCtx["clearHistory"] = useCallback(async () => {
    if (!session) return;
    setHistory([]);
    deleteHistory(session.account.id);
  }, [session]);

  const deleteCurrentAccount = useCallback(() => {
    if (!session) return;
    KEYRING.delete(session.account.id);
    removeAccount(session.account.id);
    setSession(null);
    setHistory([]);
    setAccounts(listAccounts());
  }, [session]);

  const value = useMemo<AuthCtx>(() => ({
    ready, accounts, session, history,
    signUp, login, logout, switchAccount, lockNow, changePasscode,
    addHistory, clearHistory, deleteCurrentAccount, refreshAccounts,
  }), [ready, accounts, session, history, signUp, login, logout, switchAccount, lockNow, changePasscode, addHistory, clearHistory, deleteCurrentAccount, refreshAccounts]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used within AuthProvider");
  return v;
}
