
CREATE TABLE public.scam_reports (
  hash text PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('email','social','url')),
  category text,
  last_verdict text,
  report_count integer NOT NULL DEFAULT 0,
  first_reported_at timestamptz NOT NULL DEFAULT now(),
  last_reported_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON public.scam_reports TO authenticated;
GRANT ALL ON public.scam_reports TO service_role;
ALTER TABLE public.scam_reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY "read scam counts" ON public.scam_reports FOR SELECT TO authenticated USING (true);

CREATE TABLE public.scam_report_users (
  hash text NOT NULL,
  user_id uuid NOT NULL,
  reported_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (hash, user_id)
);
GRANT SELECT, INSERT ON public.scam_report_users TO authenticated;
GRANT ALL ON public.scam_report_users TO service_role;
ALTER TABLE public.scam_report_users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own report rows" ON public.scam_report_users FOR ALL TO authenticated
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION public.report_scam(_hash text, _kind text, _category text, _verdict text)
RETURNS TABLE(report_count integer, newly_reported boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  inserted boolean := false;
  cnt integer;
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'auth required'; END IF;
  IF _kind NOT IN ('email','social','url') THEN RAISE EXCEPTION 'bad kind'; END IF;

  BEGIN
    INSERT INTO public.scam_report_users(hash, user_id) VALUES (_hash, auth.uid());
    inserted := true;
  EXCEPTION WHEN unique_violation THEN
    inserted := false;
  END;

  IF inserted THEN
    INSERT INTO public.scam_reports(hash, kind, category, last_verdict, report_count, last_reported_at)
    VALUES (_hash, _kind, _category, _verdict, 1, now())
    ON CONFLICT (hash) DO UPDATE
      SET report_count = public.scam_reports.report_count + 1,
          last_verdict = EXCLUDED.last_verdict,
          category     = COALESCE(EXCLUDED.category, public.scam_reports.category),
          last_reported_at = now();
  END IF;

  SELECT r.report_count INTO cnt FROM public.scam_reports r WHERE r.hash = _hash;
  RETURN QUERY SELECT COALESCE(cnt,0), inserted;
END;
$$;

CREATE OR REPLACE FUNCTION public.get_report_counts(_hashes text[])
RETURNS TABLE(hash text, report_count integer, category text, last_verdict text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT r.hash, r.report_count, r.category, r.last_verdict
  FROM public.scam_reports r
  WHERE r.hash = ANY(_hashes);
$$;

GRANT EXECUTE ON FUNCTION public.report_scam(text,text,text,text) TO authenticated;
GRANT EXECUTE ON FUNCTION public.get_report_counts(text[]) TO authenticated;
