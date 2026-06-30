import { createFileRoute, Outlet, redirect, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef } from "react";
import { useServerFn } from "@tanstack/react-start";
import { supabase } from "@/integrations/supabase/client";
import { getDeviceInfo, getOrCreateSessionToken, clearSessionToken } from "@/lib/device-fingerprint";
import { registerDevice, checkSessionActive } from "@/lib/devices.functions";

export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async () => {
    const { data, error } = await supabase.auth.getUser();
    if (error || !data.user) throw redirect({ to: "/auth" });
    return { user: data.user };
  },
  component: AuthedLayout,
});

function AuthedLayout() {
  const register = useServerFn(registerDevice);
  const check = useServerFn(checkSessionActive);
  const navigate = useNavigate();
  const registered = useRef(false);

  useEffect(() => {
    if (registered.current) return;
    registered.current = true;
    (async () => {
      try {
        const info = await getDeviceInfo();
        const token = getOrCreateSessionToken();
        await register({ data: { fingerprint: info.fingerprint, label: info.label, os: info.os, browser: info.browser, sessionToken: token } });
      } catch (e) { console.warn("device register failed", e); }
    })();

    // poll session validity for remote-revocation
    const id = setInterval(async () => {
      try {
        const token = getOrCreateSessionToken();
        const res = await check({ data: { sessionToken: token } });
        if (!res.active) {
          clearSessionToken();
          await supabase.auth.signOut();
          navigate({ to: "/auth", replace: true });
        }
      } catch { /* network blip, ignore */ }
    }, 60_000);
    return () => clearInterval(id);
  }, [register, check, navigate]);

  return <Outlet />;
}
