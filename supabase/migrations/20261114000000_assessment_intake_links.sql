-- Intake questionnaire for ad-hoc risk assessments. An analyst creates a link so someone in
-- the business, without an account, can answer the intake questions for a request. It follows
-- the threat risk assessment links: each assessment has at most one live link and a new link
-- replaces the old one; only a SHA-256 hash of the token is stored; a link lasts 14 days and
-- ends when its answers are submitted; answers are held apart from the assessment until an
-- analyst adds them. Both tables reference the assessment's row, because display IDs can be reused.

create table public.assessment_intake_links (
  assessment_id uuid primary key references public.assessments (id) on delete cascade,
  org_id uuid not null references public.organizations (id) on delete cascade,
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '14 days'
);

-- Each link has its own response, so a new link can't see or overwrite earlier answers.
create table public.assessment_intake_responses (
  id uuid primary key default gen_random_uuid(),
  assessment_id uuid not null references public.assessments (id) on delete cascade,
  org_id uuid not null references public.organizations (id) on delete cascade,
  token_hash text not null unique check (token_hash ~ '^[0-9a-f]{64}$'),
  response jsonb not null check (jsonb_typeof(response) = 'object' and pg_column_size(response) <= 524288),
  status text not null check (status in ('draft', 'submitted')),
  updated_at timestamptz not null default now(),
  submitted_at timestamptz
);
create index assessment_intake_responses_assessment_idx on public.assessment_intake_responses (assessment_id);

-- No policies and no privileges for API roles: everything goes through the functions below.
alter table public.assessment_intake_links enable row level security;
alter table public.assessment_intake_responses enable row level security;
revoke all on public.assessment_intake_links, public.assessment_intake_responses from anon, authenticated;

-- ---------- for analysts ----------
create or replace function private.assessment_row_id(org uuid, ref text)
returns uuid language plpgsql stable security definer set search_path = '' as $$
declare found_id uuid := (select a.id from public.assessments a where a.org_id = org and a.display_id = ref);
begin
  if found_id is null then raise exception 'assessment not found'; end if;
  return found_id;
end $$;

-- Creates or replaces an assessment's link and returns the token (shown only once). Answers
-- saved through an earlier link but never submitted are discarded.
create or replace function public.create_assessment_intake_link(org uuid, ref text)
returns text language plpgsql security definer set search_path = '' as $$
declare
  token text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
  target uuid;
begin
  perform private.require_role(org, 'analyst');
  target := private.assessment_row_id(org, ref);
  delete from public.assessment_intake_responses r where r.assessment_id = target and r.status = 'draft';
  insert into public.assessment_intake_links (assessment_id, org_id, token_hash)
  values (target, org, encode(sha256(convert_to(token, 'UTF8')), 'hex'))
  on conflict (assessment_id) do update set token_hash = excluded.token_hash, created_by = auth.uid(), created_at = now(), expires_at = now() + interval '14 days';
  perform private.write_audit(org, 'insert', 'assessment_intake_links', ref, null);
  return token;
end $$;

create or replace function public.revoke_assessment_intake_link(org uuid, ref text)
returns void language plpgsql security definer set search_path = '' as $$
declare target uuid;
begin
  perform private.require_role(org, 'analyst');
  target := private.assessment_row_id(org, ref);
  delete from public.assessment_intake_links l where l.assessment_id = target;
  delete from public.assessment_intake_responses r where r.assessment_id = target and r.status = 'draft';
  perform private.write_audit(org, 'delete', 'assessment_intake_links', ref, null);
end $$;

-- The link's state, the latest submitted answers and any draft in progress, for the editor.
create or replace function public.get_assessment_intake(org uuid, ref text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
  target uuid;
  link public.assessment_intake_links;
  sent public.assessment_intake_responses;
  draft public.assessment_intake_responses;
begin
  perform private.require_role(org, 'analyst');
  target := private.assessment_row_id(org, ref);
  select l.* into link from public.assessment_intake_links l where l.assessment_id = target and l.expires_at > now();
  select r.* into sent from public.assessment_intake_responses r where r.assessment_id = target and r.status = 'submitted' order by r.submitted_at desc limit 1;
  select r.* into draft from public.assessment_intake_responses r where r.assessment_id = target and r.status = 'draft' order by r.updated_at desc limit 1;
  return jsonb_build_object('expiresAt', link.expires_at, 'response', sent.response, 'submittedAt', sent.submitted_at,
    'draftBy', draft.response #>> '{contributor,name}', 'draftUpdatedAt', draft.updated_at);
end $$;

-- ---------- for the person with the link, who has no account ----------
-- The assessment a token opens. A final report no longer takes intake answers.
create or replace function private.assessment_intake_target(token text)
returns public.assessments language plpgsql stable security definer set search_path = '' as $$
declare found public.assessments;
begin
  if token is null or token !~ '^[0-9a-f]{64}$' then raise exception 'This link has expired or is no longer available.'; end if;
  select a.* into found from public.assessment_intake_links l join public.assessments a on a.id = l.assessment_id
  where l.token_hash = encode(sha256(convert_to(token, 'UTF8')), 'hex') and l.expires_at > now();
  if found.id is null then raise exception 'This link has expired or is no longer available.'; end if;
  if found.data ->> 'status' = 'Final' then raise exception 'This assessment has been finalized, so it no longer takes answers.'; end if;
  return found;
end $$;

-- Returns only what the questionnaire needs: who is asking, the request's name and which
-- question sets the analyst chose. Nothing else from the assessment, and no contact details.
create or replace function public.assessment_intake_load(token text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
  target public.assessments := private.assessment_intake_target(token);
  hash text := encode(sha256(convert_to(token, 'UTF8')), 'hex');
  saved public.assessment_intake_responses;
  org public.organizations;
begin
  select r.* into saved from public.assessment_intake_responses r where r.token_hash = hash and r.status = 'draft';
  select o.* into org from public.organizations o where o.id = target.org_id;
  return jsonb_build_object(
    'requester', org.name, 'logo', org.logo, 'requestName', target.data ->> 'solution',
    'types', case when jsonb_typeof(target.data -> 'intakeTypes') = 'array' then target.data -> 'intakeTypes' else '[]'::jsonb end,
    'response', saved.response - 'contributor', 'updatedAt', saved.updated_at);
end $$;

-- Saves this link's response, keeping only the expected parts. Submitting ends the link.
create or replace function public.assessment_intake_save(token text, response jsonb, submit boolean default false)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  target public.assessments := private.assessment_intake_target(token);
  hash text := encode(sha256(convert_to(token, 'UTF8')), 'hex');
  kept jsonb;
  saved public.assessment_intake_responses;
begin
  if jsonb_typeof(response) is distinct from 'object' then raise exception 'Invalid response'; end if;
  kept := jsonb_strip_nulls(jsonb_build_object(
    'contributor', case when jsonb_typeof(response -> 'contributor') = 'object' then jsonb_strip_nulls(jsonb_build_object(
        'name', left(response #>> '{contributor,name}', 200), 'email', left(response #>> '{contributor,email}', 254))) end,
    'answers', case when jsonb_typeof(response -> 'answers') = 'object' then response -> 'answers' end));
  if pg_column_size(kept) > 524288 then raise exception 'These answers are too long to save.'; end if;
  if submit and coalesce(btrim(kept #>> '{contributor,name}'), '') = '' then raise exception 'Add your name before submitting.'; end if;
  insert into public.assessment_intake_responses as r (assessment_id, org_id, token_hash, response, status, updated_at, submitted_at)
  values (target.id, target.org_id, hash, kept, case when submit then 'submitted' else 'draft' end, now(), case when submit then now() end)
  on conflict (token_hash) do update set response = excluded.response, status = excluded.status, updated_at = now(), submitted_at = excluded.submitted_at
  returning r.* into saved;
  if submit then
    delete from public.assessment_intake_links l where l.token_hash = hash;
    insert into public.audit_log (org_id, actor, actor_email, action, entity, entity_id, details)
    values (target.org_id, null, 'outside link', 'submit', 'assessment_intake_responses', target.display_id,
      jsonb_build_object('entered_name', kept #>> '{contributor,name}', 'entered_email', kept #>> '{contributor,email}'));
  end if;
  return jsonb_build_object('status', saved.status, 'updatedAt', saved.updated_at);
end $$;

revoke all on function private.assessment_row_id(uuid, text), private.assessment_intake_target(text),
  public.create_assessment_intake_link(uuid, text), public.revoke_assessment_intake_link(uuid, text), public.get_assessment_intake(uuid, text),
  public.assessment_intake_load(text), public.assessment_intake_save(text, jsonb, boolean) from public, anon, authenticated;
grant execute on function public.create_assessment_intake_link(uuid, text), public.revoke_assessment_intake_link(uuid, text), public.get_assessment_intake(uuid, text) to authenticated;
grant execute on function public.assessment_intake_load(text), public.assessment_intake_save(text, jsonb, boolean) to anon, authenticated;
