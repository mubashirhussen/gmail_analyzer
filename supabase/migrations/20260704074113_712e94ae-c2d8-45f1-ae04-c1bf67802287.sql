
REVOKE EXECUTE ON FUNCTION public.report_scam(text,text,text,text) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.get_report_counts(text[]) FROM PUBLIC, anon;
