-- Migration: 202609220001_global_trusted_domains.sql
-- Member 3: Tier 3 global domain reputation cache (L2, the full-size tier)
--
-- Backs the "known global domain" check for domains that are not in our own
-- curated official_domains directory but are still extremely well known
-- worldwide (google.com, github.com, and so on). Populated from the Tranco
-- research-oriented top-sites list (tranco-list.eu), not scraped or guessed.
-- The in-memory L1 cache (top ~20k, packages/domain) is checked first on
-- every request; this table is only queried on an L1 miss, and is refreshed
-- periodically (weekly is enough, see the load script), not on every request.

create table if not exists public.global_trusted_domains (
  domain text primary key,
  rank integer not null,
  source text not null default 'tranco',
  imported_at timestamptz not null default timezone('utc', now())
);

create index if not exists global_trusted_domains_rank_idx on public.global_trusted_domains (rank);

alter table public.global_trusted_domains enable row level security;

-- Public read access: this is a reputation list, not sensitive data, and the
-- frontend or other members may want to query it directly. Only the service
-- role (used by the load script and the API) can write to it.
create policy "public reads global trusted domains"
  on public.global_trusted_domains
  for select
  to anon, authenticated
  using (true);

create policy "service role manages global trusted domains"
  on public.global_trusted_domains
  for all
  to service_role
  using (true)
  with check (true);
