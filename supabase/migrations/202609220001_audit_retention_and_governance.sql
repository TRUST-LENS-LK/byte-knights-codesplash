-- Migration: 202609220001_audit_retention_and_governance.sql
-- Member 5: Audit Log Enrichment and 90-Day Rolling Retention Governance

-- 1. Alter moderation_audit_logs to support richer metadata & retention TTL
alter table if exists public.moderation_audit_logs
  alter column report_id drop not null;

-- Drop old action constraint and create an expanded one
alter table if exists public.moderation_audit_logs
  drop constraint if exists moderation_audit_logs_action_check;

alter table if exists public.moderation_audit_logs
  add constraint moderation_audit_logs_action_check
  check (action in ('APPROVE', 'REJECT', 'RETIRE', 'TOGGLE_STATUS', 'UPDATE_SETTINGS', 'PURGE_EXPIRED'));

-- Add additive columns for compliance, attribution, and time-to-live
alter table if exists public.moderation_audit_logs
  add column if not exists target_indicator text,
  add column if not exists threat_category text,
  add column if not exists actor_email text,
  add column if not exists confidence numeric check (confidence is null or (confidence >= 0 and confidence <= 1)),
  add column if not exists expires_at timestamptz not null default (timezone('utc', now()) + interval '90 days');

-- 2. Indexes for fast retention pruning and filtering
create index if not exists moderation_audit_expires_idx on public.moderation_audit_logs (expires_at);
create index if not exists moderation_audit_action_idx on public.moderation_audit_logs (action);
create index if not exists moderation_audit_actor_idx on public.moderation_audit_logs (actor_email);
