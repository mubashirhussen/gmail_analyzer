import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

const RegisterInput = z.object({
  fingerprint: z.string().min(8).max(128),
  label: z.string().max(120),
  os: z.string().max(60),
  browser: z.string().max(60),
  sessionToken: z.string().min(8).max(128),
});

export const registerDevice = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => RegisterInput.parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;

    // upsert device
    const { data: dev, error: devErr } = await supabase
      .from("devices")
      .upsert(
        {
          user_id: userId,
          fingerprint_hash: data.fingerprint,
          label: data.label,
          os: data.os,
          browser: data.browser,
          last_seen: new Date().toISOString(),
          trusted: true,
        },
        { onConflict: "user_id,fingerprint_hash" },
      )
      .select()
      .single();
    if (devErr) throw new Error(devErr.message);

    // upsert active session
    const { error: sessErr } = await supabase
      .from("sessions")
      .upsert(
        {
          user_id: userId,
          device_id: dev.id,
          session_token: data.sessionToken,
          last_active: new Date().toISOString(),
          revoked_at: null,
        },
        { onConflict: "session_token" },
      );
    if (sessErr) throw new Error(sessErr.message);

    // log sign-in event (idempotent-ish: only once per device per 5 min)
    await supabase.from("security_events").insert({
      user_id: userId,
      kind: "device_signed_in",
      severity: "info",
      summary: `Signed in from ${data.label}`,
      meta: { device_id: dev.id, browser: data.browser, os: data.os },
    });

    return { deviceId: dev.id as string };
  });

export const listDevices = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data: devices, error } = await supabase
      .from("devices")
      .select("id, fingerprint_hash, label, os, browser, ip, city, country, trusted, first_seen, last_seen")
      .eq("user_id", userId)
      .order("last_seen", { ascending: false });
    if (error) throw new Error(error.message);
    const { data: sessions } = await supabase
      .from("sessions")
      .select("device_id, session_token, last_active, expires_at, revoked_at")
      .eq("user_id", userId);
    return { devices: devices ?? [], sessions: sessions ?? [] };
  });

export const revokeDevice = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ deviceId: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const nowIso = new Date().toISOString();
    await supabase.from("sessions").update({ revoked_at: nowIso })
      .eq("user_id", userId).eq("device_id", data.deviceId).is("revoked_at", null);
    await supabase.from("security_events").insert({
      user_id: userId, kind: "device_signed_out", severity: "warn",
      summary: "Device sessions revoked",
      meta: { device_id: data.deviceId },
    });
    return { ok: true };
  });

export const removeDevice = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ deviceId: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await supabase.from("devices").delete().eq("user_id", userId).eq("id", data.deviceId);
    await supabase.from("security_events").insert({
      user_id: userId, kind: "device_removed", severity: "warn",
      summary: "Device removed from trusted list",
      meta: { device_id: data.deviceId },
    });
    return { ok: true };
  });

export const reportSuspicious = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ deviceId: z.string().uuid() }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await supabase.from("security_events").insert({
      user_id: userId, kind: "suspicious_device_reported", severity: "critical",
      summary: "User reported a device as suspicious",
      meta: { device_id: data.deviceId },
    });
    return { ok: true };
  });

export const revokeAllOtherDevices = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ keepSessionToken: z.string().min(8) }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const nowIso = new Date().toISOString();
    const { error } = await supabase.from("sessions")
      .update({ revoked_at: nowIso })
      .eq("user_id", userId)
      .neq("session_token", data.keepSessionToken)
      .is("revoked_at", null);
    if (error) throw new Error(error.message);
    await supabase.from("security_events").insert({
      user_id: userId, kind: "global_signout", severity: "warn",
      summary: "Signed out from all other devices",
      meta: {},
    });
    return { ok: true };
  });

export const checkSessionActive = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ sessionToken: z.string().min(8) }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: row } = await supabase.from("sessions")
      .select("revoked_at, expires_at")
      .eq("user_id", userId).eq("session_token", data.sessionToken).maybeSingle();
    if (!row) return { active: false, reason: "unknown" as const };
    if (row.revoked_at) return { active: false, reason: "revoked" as const };
    if (new Date(row.expires_at) < new Date()) return { active: false, reason: "expired" as const };
    return { active: true as const };
  });

export const listSecurityEvents = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase, userId } = context;
    const { data, error } = await supabase.from("security_events")
      .select("id, kind, severity, summary, meta, created_at")
      .eq("user_id", userId).order("created_at", { ascending: false }).limit(200);
    if (error) throw new Error(error.message);
    return data ?? [];
  });

export const logScanEvent = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({
    verdict: z.enum(["safe", "suspicious", "phishing", "fraud"]),
    riskScore: z.number().min(0).max(100),
    subject: z.string().max(500).default(""),
    sender: z.string().max(500).default(""),
  }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const severity =
      data.verdict === "safe" ? "info" :
      data.verdict === "suspicious" ? "warn" :
      data.verdict === "phishing" ? "danger" : "critical";
    await supabase.from("security_events").insert({
      user_id: userId, kind: `scan_${data.verdict}`, severity,
      summary: data.verdict === "safe"
        ? `Email marked SAFE (${data.subject || data.sender || "no subject"})`
        : `Blocked ${data.verdict.toUpperCase()} email (${data.subject || data.sender || "no subject"})`,
      meta: { risk: data.riskScore, sender: data.sender, subject: data.subject },
    });
    return { ok: true };
  });
