import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
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

type Session = { account: StoredAccount; key: CryptoKey } | null;

type AuthCtx = {
  ready: boolean;
  accounts: StoredAccount[];
  session: Session;
  history: HistoryItem[];
  signUp: (a: { username: string; email: string; passcode: string }) => Promise<void>;
  login: (accountId: string, passcode: string) => Promise<void>;
  logout: () => void;
  switchAccount: () => void; // lock + show account picker
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

  useEffect(() => {
    setAccounts(listAccounts());
    setReady(true);
  }, []);

  const refreshAccounts = useCallback(() => setAccounts(listAccounts()), []);

  const signUp: AuthCtx["signUp"] = useCallback(async (a) => {
    const acc = await createAccount(a);
    setAccounts(listAccounts());
    // auto-login after signup
    const { account, key } = await unlockAccount(acc.id, a.passcode);
    setCurrentAccountId(account.id);
    const hist = await loadHistory(account.id, key);
    setSession({ account, key });
    setHistory(hist);
  }, []);

  const login: AuthCtx["login"] = useCallback(async (id, passcode) => {
    const { account, key } = await unlockAccount(id, passcode);
    setCurrentAccountId(account.id);
    const hist = await loadHistory(account.id, key);
    setSession({ account, key });
    setHistory(hist);
    setAccounts(listAccounts());
  }, []);

  const logout = useCallback(() => {
    setCurrentAccountId(null);
    setSession(null);
    setHistory([]);
  }, []);

  const switchAccount = useCallback(() => {
    // keep current id stored, but drop key from memory so passcode is needed
    setSession(null);
    setHistory([]);
    setCurrentAccountId(null);
  }, []);

  const addHistory: AuthCtx["addHistory"] = useCallback(async (item) => {
    if (!session) return;
    const next = [item, ...history].slice(0, 200);
    setHistory(next);
    await saveHistory(session.account.id, session.key, next);
  }, [session, history]);

  const clearHistory: AuthCtx["clearHistory"] = useCallback(async () => {
    if (!session) return;
    setHistory([]);
    deleteHistory(session.account.id);
  }, [session]);

  const deleteCurrentAccount = useCallback(() => {
    if (!session) return;
    removeAccount(session.account.id);
    setSession(null);
    setHistory([]);
    setAccounts(listAccounts());
  }, [session]);

  // persisted "last current id" hint — if present, auth-gate pre-selects it
  useEffect(() => {
    if (!ready) return;
    const last = getCurrentAccountId();
    if (last && session && last !== session.account.id) {
      setCurrentAccountId(session.account.id);
    }
  }, [ready, session]);

  const value = useMemo<AuthCtx>(() => ({
    ready, accounts, session, history,
    signUp, login, logout, switchAccount, addHistory, clearHistory,
    deleteCurrentAccount, refreshAccounts,
  }), [ready, accounts, session, history, signUp, login, logout, switchAccount, addHistory, clearHistory, deleteCurrentAccount, refreshAccounts]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used within AuthProvider");
  return v;
}
