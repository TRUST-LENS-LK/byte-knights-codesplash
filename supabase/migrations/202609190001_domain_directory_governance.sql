-- Migration: 202609190001_domain_directory_governance.sql
-- Member 3: Governance columns for the official domain directory
--
-- Adds reviewer, next_review_date, status, and review_notes to
-- approved_organizations, per the 90-day revalidation rule described in the
-- project proposal. This does not rename the table, per the recommendation in
-- docs/decisions.md, since it is already seeded and wired into working code.

alter table public.approved_organizations
  add column if not exists reviewer text,
  add column if not exists next_review_date date,
  add column if not exists status text not null default 'ACTIVE'
    check (status in ('ACTIVE', 'STALE', 'RETIRED')),
  add column if not exists review_notes text
    check (review_notes is null or char_length(review_notes) <= 1000);

-- Backfill next_review_date for rows that existed before this migration, so
-- the staleness rule has something to compare against immediately. New rows
-- should set this explicitly at insert time going forward.
update public.approved_organizations
set next_review_date = (coalesce(verified_at, created_at, timezone('utc', now())) + interval '90 days')::date
where next_review_date is null;

create index if not exists approved_organizations_next_review_idx
  on public.approved_organizations (next_review_date);
