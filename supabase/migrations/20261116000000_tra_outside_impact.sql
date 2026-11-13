-- The threat risk assessment link now asks for the worst-case business impact as well as the
-- asset profile and controls. The impact ratings a link sends are kept with its response, and
-- an analyst applies them with the rest of the answers (the analyst's Review changes step). The
-- analyst's own impact ratings are never sent to a link, even when it shares existing answers.
-- Owners, status, gaps and scores still can't be set from a link.

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
    'answers', case when jsonb_typeof(response -> 'answers') = 'object' then response -> 'answers' end,
    'impact', case when jsonb_typeof(response -> 'impact') = 'object' then response -> 'impact' end));
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

create or replace function public.tra_outside_load(token text)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare
  target public.threat_assessments := private.tra_link_target(token);
  hash text := encode(sha256(convert_to(token, 'UTF8')), 'hex');
  shared boolean := (select l.share_existing from public.threat_assessment_links l where l.token_hash = hash);
  saved public.threat_assessment_responses;
  org public.organizations;
  profile jsonb := case when jsonb_typeof(target.data -> 'profile') = 'object' then target.data -> 'profile' else '{}'::jsonb end;
begin
  select r.* into saved from public.threat_assessment_responses r where r.token_hash = hash and r.status = 'draft';
  select o.* into org from public.organizations o where o.id = target.org_id;
  return jsonb_build_object(
    'requester', org.name, 'logo', org.logo, 'framework', org.tra_framework, 'assetName', target.data ->> 'assetName',
    'scope', (select coalesce(jsonb_object_agg(p.key, p.value), '{}'::jsonb) from jsonb_each(profile) p
      where p.key in ('assetTypes', 'auth') or p.value in ('"Yes"'::jsonb, '"No"'::jsonb)),
    'seed', case when shared then jsonb_build_object('description', target.data -> 'description', 'department', target.data -> 'department',
      'profile', target.data -> 'profile', 'answers', target.data -> 'answers') end,
    'response', saved.response - 'contributor', 'updatedAt', saved.updated_at);
end $$;
