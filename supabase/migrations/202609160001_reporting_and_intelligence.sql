-- Migration: 202609160001_reporting_and_intelligence.sql
-- Member 5: Verified Intelligence and Moderation Audit Logs

-- 1. Verified Intelligence Table
-- Stores sanitized scam indicators and verified safe entities extracted from approved reports.
create table if not exists public.verified_intelligence (
  id uuid primary key default gen_random_uuid(),
  source_report_id uuid references public.user_reports(id) on delete set null,
  indicator_type text not null check (indicator_type in ('domain', 'content_hash', 'phone', 'url')),
  indicator_value text not null,
  defanged_value text not null,
  risk_level text not null check (risk_level in ('CONFIRMED_SCAM', 'VERIFIED_SAFE')),
  category text,
  confidence numeric not null default 1.0 check (confidence >= 0 and confidence <= 1),
  notes text,
  active boolean not null default true,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now())
);

create index if not exists verified_intel_indicator_idx on public.verified_intelligence (indicator_type, indicator_value);
create index if not exists verified_intel_active_idx on public.verified_intelligence (active) where active = true;

-- 2. Moderation Audit Logs Table
-- Tracks every moderator action (APPROVE, REJECT, RETIRE) for complete accountability.
create table if not exists public.moderation_audit_logs (
  id bigint generated always as identity primary key,
  report_id uuid not null references public.user_reports(id) on delete cascade,
  action text not null check (action in ('APPROVE', 'REJECT', 'RETIRE')),
  moderator_notes text check (moderator_notes is null or char_length(moderator_notes) <= 1000),
  actor_role text not null default 'moderator',
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists moderation_audit_report_idx on public.moderation_audit_logs (report_id);
create index if not exists moderation_audit_created_idx on public.moderation_audit_logs (created_at desc);

-- 3. Row Level Security (RLS) Policies
alter table public.verified_intelligence enable row level security;
alter table public.moderation_audit_logs enable row level security;

-- Public can read active verified intelligence (used by analysis checker to flag known scams)
create policy "public reads active verified intelligence"
  on public.verified_intelligence
  for select
  to anon, authenticated
  using (active = true);

-- Service role manages all verified intelligence entries
create policy "service role manages verified intelligence"
  on public.verified_intelligence
  for all
  to service_role
  using (true)
  with check (true);

-- Only service role (and authorized moderators) can read and insert audit logs
create policy "service role manages moderation audit logs"
  on public.moderation_audit_logs
  for all
  to service_role
  using (true)
  with check (true);
