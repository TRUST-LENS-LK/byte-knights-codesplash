-- Seed: 002_expand_domain_directory.sql
-- Member 3: expand the official domain directory beyond the original 2 rows.
--
-- Covers banking, telecom, government, education, and job-platform categories,
-- plus a real employer domain (Virtusa) that the fake-job demo scenario can
-- impersonate to demonstrate a MISMATCH result. Domains here reflect general
-- knowledge at the time of writing; a teammate should spot-check each
-- source_url before relying on this list for the live demo, which is exactly
-- why the reviewer and verified_at governance columns exist.

insert into public.approved_organizations
  (name, official_domain, category, source_url, verified_at, reviewer, next_review_date, status)
values
  -- Banking
  ('Bank of Ceylon', 'boc.lk', 'Banking', 'https://www.boc.lk', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),
  ('Commercial Bank of Ceylon', 'combank.lk', 'Banking', 'https://www.combank.lk', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),
  ('Sampath Bank', 'sampath.lk', 'Banking', 'https://www.sampath.lk', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),
  ('Hatton National Bank', 'hnb.net', 'Banking', 'https://www.hnb.net', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),
  ('People''s Bank', 'peoplesbank.lk', 'Banking', 'https://www.peoplesbank.lk', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),

  -- Telecom
  ('Dialog Axiata', 'dialog.lk', 'Telecom', 'https://www.dialog.lk', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),
  ('SLT-Mobitel', 'slt.lk', 'Telecom', 'https://www.slt.lk', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),

  -- Government (in addition to CERT and Police already seeded)
  ('Department of Inland Revenue', 'ird.gov.lk', 'Government', 'https://www.ird.gov.lk', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),

  -- Education
  ('University of Moratuwa', 'uom.lk', 'Education', 'https://www.uom.lk', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),

  -- Job platforms
  ('topjobs.lk', 'topjobs.lk', 'Recruitment', 'https://www.topjobs.lk', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE'),

  -- Demo employer: the fake-job scenario impersonates this real company while
  -- linking to an unrelated domain, so the directory has a genuine entry to
  -- compare against once mismatch detection (Stage 5.2) is built.
  ('Virtusa', 'virtusa.com', 'Employer', 'https://www.virtusa.com', now(), 'Isuru Adikaram', (now() + interval '90 days')::date, 'ACTIVE')
on conflict (official_domain) do nothing;
