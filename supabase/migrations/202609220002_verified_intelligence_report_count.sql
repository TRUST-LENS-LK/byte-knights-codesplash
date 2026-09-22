-- Fix: verified_intelligence was missing report_count, a column
-- services/api/src/services/reportingService.mjs has always written on every
-- insert (both the citizen-report-approval path and the moderator
-- direct-add path). Every insert into this table has therefore been
-- silently failing against the real database (PGRST204: column not found)
-- and falling back to each server process's in-memory store, meaning
-- confirmed threats never actually persisted to Supabase.
alter table public.verified_intelligence
  add column if not exists report_count integer not null default 1;
