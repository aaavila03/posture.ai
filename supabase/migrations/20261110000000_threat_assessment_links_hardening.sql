-- Limits what a leaked threat risk assessment link can do. The form starts blank unless the
-- analyst chooses to share existing answers. A link lasts 14 days and ends when its answers are
-- submitted, so it allows one submission and can't be used afterwards. A person's contact details
-- aren't sent back to the form. Audit entries are marked as coming from a link, so a typed
-- email can't pass for a member's. Each link has its own response, so a new link can't see or
-- overwrite earlier answers.

alter table public.threat_assessment_links add column share_existing boolean not null default false;
update public.threat_assessment_links set expires_at = least(expires_at, now() + interval '14 days');
alter table public.threat_assessment_links alter column expires_at set default now() + interval '14 days';

alter table public.threat_assessment_responses drop constraint threat_assessment_responses_pkey;
alter table public.threat_assessment_responses add column id uuid primary key default gen_random_uuid();
alter table public.threat_assessment_responses add column token_hash text unique check (token_hash ~ '^[0-9a-f]{64}$');
update public.threat_assessment_responses r set token_hash = l.token_hash
  from public.threat_assessment_links l where l.assessment_id = r.assessment_id;
create index threat_assessment_responses_assessment_idx on public.threat_assessment_responses (assessment_id);

drop function public.create_tra_link(uuid, text);

-- Creates or replaces an assessment's link and returns the token (shown only once). Answers
-- saved through an earlier link but never submitted are discarded.
create or replace function public.create_tra_link(org uuid, ref text, share boolean default false)
returns text language plpgsql security definer set search_path = '' as $$
declare
  token text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
  target uuid;
begin
  perform private.require_role(org, 'analyst');
  target := private.threat_assessment_id(org, ref);
  delete from public.threat_assessment_responses r where r.assessment_id = target and r.status = 'draft';
  insert into public.threat_assessment_links (assessment_id, org_id, token_hash, share_existing)
  values (target, org, encode(sha256(convert_to(token, 'UTF8')), 'hex'), coalesce(share, false))
  on conflict (assessment_id) do update set token_hash = excluded.token_hash, share_existing = excluded.share_existing,
    created_by = auth.uid(), created_at = now(), expires_at = now() + interval '14 days';
  perform private.write_audit(org, 'insert', 'threat_assessment_links', ref, jsonb_build_object('share_existing', coalesce(share, false)));
  return token;
end $$;

create or replace function public.revoke_tra_link(org uuid, ref text)
returns void language plpgsql security definer set search_path = '' as $$
declare target uuid;
begin
  perform private.require_role(org, 'analyst');
  target := private.threat_assessment_id(org, ref);
  delete from public.threat_assessment_links l where l.assessment_id = target;
  delete from public.threat_assessment_responses r where r.assessment_id = target and r.status = 'draft';
  perform private.write_audit(org, 'delete', 'threat_assessment_links', ref, null);
end $$;

-- The link's state, the latest submitted answers and any draft in progress, for the editor.
create or replace function public.get_tra_outside(org uuid, ref text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
  target uuid;
  link public.threat_assessment_links;
  sent public.threat_assessment_responses;
  draft public.threat_assessment_responses;
begin
  perform private.require_role(org, 'analyst');
  target := private.threat_assessment_id(org, ref);
  select l.* into link from public.threat_assessment_links l where l.assessment_id = target and l.expires_at > now();
  select r.* into sent from public.threat_assessment_responses r where r.assessment_id = target and r.status = 'submitted' order by r.submitted_at desc limit 1;
  select r.* into draft from public.threat_assessment_responses r where r.assessment_id = target and r.status = 'draft' order by r.updated_at desc limit 1;
  return jsonb_build_object('expiresAt', link.expires_at, 'shareExisting', link.share_existing,
    'response', sent.response, 'submittedAt', sent.submitted_at,
    'draftBy', draft.response #>> '{contributor,name}', 'draftUpdatedAt', draft.updated_at);
end $$;

-- Returns only what steps 1 and 2 need, without anyone's contact details. Existing answers are
-- included only if the analyst chose to share them.
create or replace function public.tra_outside_load(token text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
  target public.threat_assessments := private.tra_link_target(token);
  hash text := encode(sha256(convert_to(token, 'UTF8')), 'hex');
  shared boolean := (select l.share_existing from public.threat_assessment_links l where l.token_hash = hash);
  saved public.threat_assessment_responses;
  org public.organizations;
begin
  select r.* into saved from public.threat_assessment_responses r where r.token_hash = hash and r.status = 'draft';
  select o.* into org from public.organizations o where o.id = target.org_id;
  return jsonb_build_object(
    'requester', org.name, 'logo', org.logo, 'assetName', target.data ->> 'assetName',
    'seed', case when shared then jsonb_build_object('description', target.data -> 'description', 'department', target.data -> 'department',
      'profile', target.data -> 'profile', 'answers', target.data -> 'answers') end,
    'response', saved.response - 'contributor', 'updatedAt', saved.updated_at);
end $$;

-- Saves this link's response, keeping only the expected parts. Submitting ends the link.
create or replace function public.tra_outside_save(token text, response jsonb, submit boolean default false)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  target public.threat_assessments := private.tra_link_target(token);
  hash text := encode(sha256(convert_to(token, 'UTF8')), 'hex');
  kept jsonb;
  saved public.threat_assessment_responses;
begin
  if jsonb_typeof(response) is distinct from 'object' then raise exception 'Invalid response'; end if;
  kept := jsonb_strip_nulls(jsonb_build_object(
    'contributor', case when jsonb_typeof(response -> 'contributor') = 'object' then jsonb_strip_nulls(jsonb_build_object(
        'name', left(response #>> '{contributor,name}', 200), 'email', left(response #>> '{contributor,email}', 254))) end,
    'description', case when jsonb_typeof(response -> 'description') = 'string' then response -> 'description' end,
    'department', case when jsonb_typeof(response -> 'department') = 'string' then response -> 'department' end,
    'profile', case when jsonb_typeof(response -> 'profile') = 'object' then response -> 'profile' end,
    'answers', case when jsonb_typeof(response -> 'answers') = 'object' then response -> 'answers' end));
  if pg_column_size(kept) > 524288 then raise exception 'These answers are too long to save.'; end if;
  if submit and coalesce(btrim(kept #>> '{contributor,name}'), '') = '' then raise exception 'Add your name before submitting.'; end if;
  insert into public.threat_assessment_responses as r (assessment_id, org_id, token_hash, response, status, updated_at, submitted_at)
  values (target.id, target.org_id, hash, kept, case when submit then 'submitted' else 'draft' end, now(), case when submit then now() end)
  on conflict (token_hash) do update set response = excluded.response, status = excluded.status, updated_at = now(), submitted_at = excluded.submitted_at
  returning r.* into saved;
  if submit then
    delete from public.threat_assessment_links l where l.token_hash = hash;
    insert into public.audit_log (org_id, actor, actor_email, action, entity, entity_id, details)
    values (target.org_id, null, 'outside link', 'submit', 'threat_assessment_responses', target.display_id,
      jsonb_build_object('entered_name', kept #>> '{contributor,name}', 'entered_email', kept #>> '{contributor,email}'));
  end if;
  return jsonb_build_object('status', saved.status, 'updatedAt', saved.updated_at);
end $$;

revoke all on function public.create_tra_link(uuid, text, boolean) from public, anon, authenticated;
grant execute on function public.create_tra_link(uuid, text, boolean) to authenticated;
