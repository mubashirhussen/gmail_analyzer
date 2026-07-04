import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

const ReportInput = z.object({
  hash: z.string().min(16).max(128),
  kind: z.enum(["email", "social", "url"]),
  category: z.string().max(60).optional(),
  verdict: z.string().max(30).optional(),
});

export const reportScam = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => ReportInput.parse(d))
  .handler(async ({ data, context }) => {
    const { supabase } = context;
    const { data: rows, error } = await supabase.rpc("report_scam", {
      _hash: data.hash,
      _kind: data.kind,
      _category: data.category ?? null,
      _verdict: data.verdict ?? null,
    });
    if (error) throw new Error(error.message);
    const row = Array.isArray(rows) ? rows[0] : rows;
    return {
      reportCount: (row?.report_count as number) ?? 0,
      newlyReported: (row?.newly_reported as boolean) ?? false,
    };
  });

export const getReportCounts = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => z.object({ hashes: z.array(z.string().min(16).max(128)).max(50) }).parse(d))
  .handler(async ({ data, context }) => {
    const { supabase } = context;
    if (data.hashes.length === 0) return { counts: {} as Record<string, number> };
    const { data: rows, error } = await supabase.rpc("get_report_counts", { _hashes: data.hashes });
    if (error) throw new Error(error.message);
    const counts: Record<string, number> = {};
    for (const r of (rows ?? []) as Array<{ hash: string; report_count: number }>) {
      counts[r.hash] = r.report_count;
    }
    return { counts };
  });
