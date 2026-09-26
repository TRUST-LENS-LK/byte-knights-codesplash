-- Migration: 202609230001_audit_tamper_evidence_and_integrity.sql
-- Member 5: Enterprise Audit Immutability, SHA-256 Cryptographic Hash Chaining & Complete Event Coverage

-- 1. Preserve Forensic Audit Records When Source Reports are Pruned or Deleted
-- Drop old cascading foreign key if present, replace with on delete set null
alter table if exists public.moderation_audit_logs
  drop constraint if exists moderation_audit_logs_report_id_fkey;

alter table if exists public.moderation_audit_logs
  add constraint moderation_audit_logs_report_id_fkey
  foreign key (report_id) references public.user_reports(id) on delete set null;

-- 2. Expand Action Constraint to Cover All Security, Authentication, and Governance Events
alter table if exists public.moderation_audit_logs
  drop constraint if exists moderation_audit_logs_action_check;

alter table if exists public.moderation_audit_logs
  add constraint moderation_audit_logs_action_check
  check (action in (
    'APPROVE',
    'REJECT',
    'RETIRE',
    'TOGGLE_STATUS',
    'UPDATE_SETTINGS',
    'PURGE_EXPIRED',
    'AUTH_LOGIN',
    'AUTH_FAILED',
    'DOMAIN_CREATE',
    'DOMAIN_UPDATE',
    'DOMAIN_DELETE',
    'MANUAL_INTEL'
  ));

-- 3. Add Cryptographic Hash Chaining and Client Attribution Columns (Strictly Additive)
alter table if exists public.moderation_audit_logs
  add column if not exists entry_hash text,
  add column if not exists prev_hash text,
  add column if not exists client_ip text,
  add column if not exists user_agent text;

-- Indexes for hash lookup and actor/IP analysis
create index if not exists moderation_audit_entry_hash_idx on public.moderation_audit_logs (entry_hash);
create index if not exists moderation_audit_prev_hash_idx on public.moderation_audit_logs (prev_hash);
create index if not exists moderation_audit_client_ip_idx on public.moderation_audit_logs (client_ip);

-- 4. PostgreSQL Immutability Trigger (Prevents Direct Modifications of Audit Records)
create or replace function public.prevent_audit_log_modification()
returns trigger as $$
begin
  raise exception 'Integrity Violation: moderation_audit_logs entries are immutable and cannot be updated.';
end;
$$ language plpgsql;

drop trigger if exists trg_protect_moderation_audit_logs on public.moderation_audit_logs;

create trigger trg_protect_moderation_audit_logs
before update on public.moderation_audit_logs
for each row execute function public.prevent_audit_log_modification();
