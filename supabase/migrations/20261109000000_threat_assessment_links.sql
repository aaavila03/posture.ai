-- Outside input for threat risk assessments. An analyst creates a link so someone without an
-- account can complete the asset profile and controls. Each assessment has at most one live
-- link; a new link replaces the old one. Only a SHA-256 hash of the token is stored, and a link
-- expires after 30 days. Answers are held apart from the assessment until an analyst applies
-- them. Both tables reference the assessment's row, because display IDs can be reused.

create table public.threat_assessment_links (
  assessment_id uuid primary key references public.threat_assessments (id) on delete cascade,
  org_id uuid not null references public.organizations (id) on delete cascade,
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '30 days'
);

create table public.threat_assessment_responses (
  assessment_id uuid primary key references public.threat_assessments (id) on delete cascade,
  org_id uuid not null references public.organizations (id) on delete cascade,
  response jsonb not null check (jsonb_typeof(response) = 'object' and pg_column_size(response) <= 524288),
  status text not null check (status in ('draft', 'submitted')),
  updated_at timestamptz not null default now(),
  submitted_at timestamptz
);

-- No policies and no privileges for API roles: everything goes through the functions below.
alter table public.threat_assessment_links enable row level security;
alter table public.threat_assessment_responses enable row level security;
revoke all on public.threat_assessment_links, public.threat_assessment_responses from anon, authenticated;

-- ---------- for analysts ----------
create or replace function private.threat_assessment_id(org uuid, ref text)
returns uuid language plpgsql stable security definer set search_path = '' as $$
declare found_id uuid := (select t.id from public.threat_assessments t where t.org_id = org and t.display_id = ref);
begin
  if found_id is null then raise exception 'assessment not found'; end if;
  return found_id;
end $$;

-- Creates or replaces an assessment's link and returns the token (shown only once).
create or replace function public.create_tra_link(org uuid, ref text)
returns text language plpgsql security definer set search_path = '' as $$
declare
  token text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
  target uuid;
begin
  perform private.require_role(org, 'analyst');
  target := private.threat_assessment_id(org, ref);
  insert into public.threat_assessment_links (assessment_id, org_id, token_hash)
  values (target, org, encode(sha256(convert_to(token, 'UTF8')), 'hex'))
  on conflict (assessment_id) do update set token_hash = excluded.token_hash, created_by = auth.uid(), created_at = now(), expires_at = now() + interval '30 days';
  perform private.write_audit(org, 'insert', 'threat_assessment_links', ref, null);
  return token;
end $$;

create or replace function public.revoke_tra_link(org uuid, ref text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.require_role(org, 'analyst');
  delete from public.threat_assessment_links l where l.assessment_id = private.threat_assessment_id(org, ref);
  perform private.write_audit(org, 'delete', 'threat_assessment_links', ref, null);
end $$;

-- The link's expiry and any response, for the assessment's editor.
create or replace function public.get_tra_outside(org uuid, ref text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare target uuid;
begin
  perform private.require_role(org, 'analyst');
  target := private.threat_assessment_id(org, ref);
  return jsonb_build_object(
    'expiresAt', (select l.expires_at from public.threat_assessment_links l where l.assessment_id = target and l.expires_at > now()),
    'response', (select r.response from public.threat_assessment_responses r where r.assessment_id = target),
    'status', (select r.status from public.threat_assessment_responses r where r.assessment_id = target),
    'updatedAt', (select r.updated_at from public.threat_assessment_responses r where r.assessment_id = target),
    'submittedAt', (select r.submitted_at from public.threat_assessment_responses r where r.assessment_id = target));
end $$;

-- ---------- for the person with the link, who has no account ----------
-- The assessment a token opens. Completed assessments no longer take outside input.
create or replace function private.tra_link_target(token text)
returns public.threat_assessments language plpgsql stable security definer set search_path = '' as $$
declare found public.threat_assessments;
begin
  if token is null or token !~ '^[0-9a-f]{64}$' then raise exception 'This link has expired or is no longer available.'; end if;
  select t.* into found from public.threat_assessment_links l join public.threat_assessments t on t.id = l.assessment_id
  where l.token_hash = encode(sha256(convert_to(token, 'UTF8')), 'hex') and l.expires_at > now();
  if found.id is null then raise exception 'This link has expired or is no longer available.'; end if;
  if found.data ->> 'status' = 'Completed' then raise exception 'This assessment has been completed, so it no longer takes answers.'; end if;
  return found;
end $$;

-- Returns only what steps 1 and 2 need. Impact ratings, gaps, scores, owners and notes stay private.
create or replace function public.tra_outside_load(token text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
  target public.threat_assessments := private.tra_link_target(token);
  saved public.threat_assessment_responses;
  org public.organizations;
begin
  select r.* into saved from public.threat_assessment_responses r where r.assessment_id = target.id;
  select o.* into org from public.organizations o where o.id = target.org_id;
  return jsonb_build_object(
    'requester', org.name, 'logo', org.logo, 'assetName', target.data ->> 'assetName',
    'seed', jsonb_build_object('description', target.data -> 'description', 'department', target.data -> 'department',
      'profile', target.data -> 'profile', 'answers', target.data -> 'answers'),
    'response', saved.response, 'status', saved.status, 'updatedAt', saved.updated_at, 'submittedAt', saved.submitted_at);
end $$;

-- Saves the response, keeping only the expected parts.
create or replace function public.tra_outside_save(token text, response jsonb, submit boolean default false)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  target public.threat_assessments := private.tra_link_target(token);
  kept jsonb;
  saved public.threat_assessment_responses;
begin
  if jsonb_typeof(response) is distinct from 'object' then raise exception 'Invalid response'; end if;
  kept := jsonb_strip_nulls(jsonb_build_object(
    'contributor', case when jsonb_typeof(response -> 'contributor') = 'object' then response -> 'contributor' end,
    'description', case when jsonb_typeof(response -> 'description') = 'string' then response -> 'description' end,
    'department', case when jsonb_typeof(response -> 'department') = 'string' then response -> 'department' end,
    'profile', case when jsonb_typeof(response -> 'profile') = 'object' then response -> 'profile' end,
    'answers', case when jsonb_typeof(response -> 'answers') = 'object' then response -> 'answers' end));
  if pg_column_size(kept) > 524288 then raise exception 'These answers are too long to save.'; end if;
  if submit and coalesce(btrim(kept #>> '{contributor,name}'), '') = '' then raise exception 'Add your name before submitting.'; end if;
  insert into public.threat_assessment_responses as r (assessment_id, org_id, response, status, updated_at, submitted_at)
  values (target.id, target.org_id, kept, case when submit then 'submitted' else 'draft' end, now(), case when submit then now() end)
  on conflict (assessment_id) do update set response = excluded.response, updated_at = now(),
    status = case when submit then 'submitted' else r.status end,
    submitted_at = case when submit then now() else r.submitted_at end
  returning r.* into saved;
  if submit then
    insert into public.audit_log (org_id, actor, actor_email, action, entity, entity_id)
    values (target.org_id, null, left(kept #>> '{contributor,email}', 254), 'submit', 'threat_assessment_responses', target.display_id);
  end if;
  return jsonb_build_object('status', saved.status, 'updatedAt', saved.updated_at, 'submittedAt', saved.submitted_at);
end $$;

revoke all on function private.threat_assessment_id(uuid, text), private.tra_link_target(text),
  public.create_tra_link(uuid, text), public.revoke_tra_link(uuid, text), public.get_tra_outside(uuid, text),
  public.tra_outside_load(text), public.tra_outside_save(text, jsonb, boolean) from public, anon, authenticated;
grant execute on function public.create_tra_link(uuid, text), public.revoke_tra_link(uuid, text), public.get_tra_outside(uuid, text) to authenticated;
grant execute on function public.tra_outside_load(text), public.tra_outside_save(text, jsonb, boolean) to anon, authenticated;
