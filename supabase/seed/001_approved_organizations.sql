insert into public.approved_organizations (name, official_domain, category, source_url, verified_at)
values
  ('Sri Lanka CERT', 'cert.gov.lk', 'Cybersecurity', 'https://www.cert.gov.lk', now()),
  ('Sri Lanka Police', 'police.lk', 'Law enforcement', 'https://www.police.lk', now())
on conflict (official_domain) do nothing;
