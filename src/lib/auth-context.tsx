import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { supabase } from "@/integrations/supabase/client";
import type { Session as SbSession, User } from "@supabase/supabase-js";
import type { HistoryItem } from "./secure-store";

export type { HistoryItem };

type Account = { id: string; username: string; email: string };
type Session = { account: Account } | null;

type AuthCtx = {
  ready: boolean;
  session: Session;
  history: HistoryItem[];
  signOut: () => Promise<void>;
  switchAccount: () => Promise<void>;
  lockNow: () => Promise<void>;
  changePasscode: (current: string, next: string) => Promise<void>;
  addHistory: (item: HistoryItem) => Promise<void>;
  clearHistory: () => Promise<void>;
  deleteCurrentAccount: () => Promise<void>;
  // legacy alias kept for the existing Dashboard layout
  logout: () => Promise<void>;
};

const Ctx = createContext<AuthCtx | null>(null);

const HISTORY_KEY = (uid: string) => `mg.history.v2.${uid}`;

function loadHistory(uid: string): HistoryItem[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY(uid));
    return raw ? (JSON.parse(raw) as HistoryItem[]) : [];
  } catch { return []; }
}
function saveHistory(uid: string, items: HistoryItem[]) {
  localStorage.setItem(HISTORY_KEY(uid), JSON.stringify(items));
}

function toAccount(u: User): Account {
  const meta = (u.user_metadata ?? {}) as Record<string, unknown>;
  const username =
    (meta.username as string) ||
    (meta.full_name as string) ||
    (meta.name as string) ||
    (u.email ? u.email.split("@")[0] : "user");
  return { id: u.id, username, email: u.email ?? "" };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [session, setSession] = useState<Session>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  useEffect(() => {
    let mounted = true;

    const apply = (sb: SbSession | null) => {
      if (!mounted) return;
      if (sb?.user) {
        const acc = toAccount(sb.user);
        setSession({ account: acc });
        setHistory(loadHistory(acc.id));
      } else {
        setSession(null);
        setHistory([]);
      }
    };

    supabase.auth.getSession().then(({ data }) => {
      apply(data.session);
      setReady(true);
    });

    const { data: sub } = supabase.auth.onAuthStateChange((event, sb) => {
      if (event === "SIGNED_IN" || event === "SIGNED_OUT" || event === "USER_UPDATED" || event === "INITIAL_SESSION") {
        apply(sb);
      }
    });
    return () => { mounted = false; sub.subscription.unsubscribe(); };
  }, []);

  const signOut = useCallback(async () => {
    await supabase.auth.signOut();
    setSession(null);
    setHistory([]);
  }, []);

  const addHistory = useCallback(async (item: HistoryItem) => {
    if (!session) return;
    const next = [item, ...history].slice(0, 200);
    setHistory(next);
    saveHistory(session.account.id, next);
  }, [session, history]);

  const clearHistory = useCallback(async () => {
    if (!session) return;
    setHistory([]);
    localStorage.removeItem(HISTORY_KEY(session.account.id));
  }, [session]);

  const changePasscode = useCallback(async (_current: string, next: string) => {
    if (next.length < 8) throw new Error("Password must be at least 8 characters.");
    const { error } = await supabase.auth.updateUser({ password: next });
    if (error) throw new Error(error.message);
  }, []);

  const deleteCurrentAccount = useCallback(async () => {
    if (!session) return;
    localStorage.removeItem(HISTORY_KEY(session.account.id));
    await supabase.auth.signOut();
    setSession(null);
    setHistory([]);
    alert("Local data cleared and you've been signed out. To permanently delete your account, contact support.");
  }, [session]);

  const value = useMemo<AuthCtx>(() => ({
    ready, session, history,
    signOut, switchAccount: signOut, lockNow: signOut, logout: signOut,
    changePasscode, addHistory, clearHistory, deleteCurrentAccount,
  }), [ready, session, history, signOut, changePasscode, addHistory, clearHistory, deleteCurrentAccount]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth must be used within AuthProvider");
  return v;
}
