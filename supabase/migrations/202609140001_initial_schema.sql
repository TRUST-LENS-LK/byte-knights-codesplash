create extension if not exists pgcrypto;

create table if not exists public.submissions (
  id uuid primary key default gen_random_uuid(),
  submission_type text not null check (submission_type in ('message', 'url', 'screenshot')),
  content_sha256 text not null,
  raw_text text,
  language_hint text check (language_hint in ('en', 'si', 'singlish', 'mixed')),
  retention_consent boolean not null default false,
  risk_band text not null check (risk_band in ('LOW', 'MEDIUM', 'HIGH', 'UNKNOWN')),
  recommendation text not null check (recommendation in ('PROCEED_CAUTIOUSLY', 'VERIFY_INDEPENDENTLY', 'STOP_AND_AVOID', 'UNABLE_TO_VERIFY')),
  policy_version text not null,
  created_at timestamptz not null default timezone('utc', now()),
  expires_at timestamptz,
  constraint raw_text_requires_consent check (raw_text is null or retention_consent = true)
);

create index if not exists submissions_hash_idx on public.submissions (content_sha256);
create index if not exists submissions_created_idx on public.submissions (created_at desc);

create table if not exists public.extracted_entities (
  id bigint generated always as identity primary key,
  submission_id uuid not null references public.submissions(id) on delete cascade,
  entity_type text not null check (entity_type in ('url', 'domain', 'phone', 'email', 'amount', 'organization')),
  value text not null,
  normalized_value text,
  confidence numeric check (confidence is null or (confidence >= 0 and confidence <= 1)),
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists extracted_entities_submission_idx on public.extracted_entities (submission_id);

create table if not exists public.findings (
  id bigint generated always as identity primary key,
  submission_id uuid not null references public.submissions(id) on delete cascade,
  canonical_signal text not null,
  category text not null,
  evidence text not null,
  source text not null check (source in ('RULE', 'LLM', 'DOMAIN_DIRECTORY', 'SCANNER', 'APPROVED_REPORT')),
  strength numeric not null check (strength >= 0 and strength <= 1),
  confidence numeric check (confidence is null or (confidence >= 0 and confidence <= 1)),
  limitation text,
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists findings_submission_idx on public.findings (submission_id);

create table if not exists public.approved_organizations (
  id bigint generated always as identity primary key,
  name text not null,
  official_domain text not null unique,
  category text,
  source_url text,
  verified_at timestamptz,
  active boolean not null default true,
  created_at timestamptz not null default timezone('utc', now())
);

create table if not exists public.user_reports (
  id uuid primary key default gen_random_uuid(),
  report_type text not null check (report_type in ('suspicious', 'false_positive', 'false_negative')),
  content_sha256 text not null,
  reported_domain text,
  notes text check (notes is null or char_length(notes) <= 2000),
  status text not null default 'PENDING' check (status in ('PENDING', 'REVIEWED', 'REJECTED', 'APPROVED')),
  created_at timestamptz not null default timezone('utc', now())
);

alter table public.submissions enable row level security;
alter table public.extracted_entities enable row level security;
alter table public.findings enable row level security;
alter table public.approved_organizations enable row level security;
alter table public.user_reports enable row level security;

create policy "service role manages submissions" on public.submissions for all to service_role using (true) with check (true);
create policy "service role manages entities" on public.extracted_entities for all to service_role using (true) with check (true);
create policy "service role manages findings" on public.findings for all to service_role using (true) with check (true);
create policy "public reads active organizations" on public.approved_organizations for select to anon, authenticated using (active = true);
create policy "public creates reports" on public.user_reports for insert to anon, authenticated with check (status = 'PENDING');
create policy "service role manages reports" on public.user_reports for all to service_role using (true) with check (true);
