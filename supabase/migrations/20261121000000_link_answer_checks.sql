-- Shape checks for the answers sent through a link. Answers from the app and the links are
-- kept in the database, so the database refuses anything outside the expected form. Text that is
-- only too long is cut to its limit rather than refused.

create or replace function private.valid_intake_answers(answers jsonb)
returns boolean language sql immutable as $$
  select jsonb_typeof(answers) = 'object' and (select count(*) from jsonb_each(answers)) <= 300
    and not exists (
      select 1 from jsonb_each(answers) e
      where e.key !~ '^[A-Z]{2,3}[0-9]{1,3}$' or jsonb_typeof(e.value) <> 'object'
        or exists (select 1 from jsonb_each(e.value) v
          where v.key not in ('a', 't') or jsonb_typeof(v.value) <> 'string'
            or char_length(v.value #>> '{}') > (case when v.key = 'a' then 80 else 4000 end)));
$$;

create or replace function private.valid_control_answers(answers jsonb)
returns boolean language sql immutable as $$
  select jsonb_typeof(answers) = 'object' and (select count(*) from jsonb_each(answers)) <= 200
    and not exists (
      select 1 from jsonb_each(answers) e
      where e.key !~ '^[A-Z]{2,3}-[0-9]{2,3}$' or jsonb_typeof(e.value) <> 'object'
        or exists (select 1 from jsonb_each(e.value) v
          where v.key not in ('status', 'evidence', 'compensating')
            or (v.key = 'status' and (jsonb_typeof(v.value) <> 'string' or v.value #>> '{}' not in ('Yes', 'No', 'Partially', 'Not applicable')))
            or (v.key <> 'status' and (jsonb_typeof(v.value) <> 'string' or char_length(v.value #>> '{}') > 2000))));
$$;

create or replace function private.valid_impact(impact jsonb)
returns boolean language sql immutable as $$
  select jsonb_typeof(impact) = 'object' and (select count(*) from jsonb_each(impact)) <= 60
    and not exists (
      select 1 from jsonb_each(impact) e
      where e.key !~ '^[A-Z]{1,2}[0-9]{1,2}$' or jsonb_typeof(e.value) <> 'object'
        or exists (select 1 from jsonb_each(e.value) v
          where v.key not in ('c', 'i', 'a') or jsonb_typeof(v.value) <> 'string' or v.value #>> '{}' not in ('A', 'B', 'C', 'D', 'E', 'NA')));
$$;

revoke all on function private.valid_intake_answers(jsonb), private.valid_control_answers(jsonb), private.valid_impact(jsonb) from public, anon, authenticated;

create or replace function public.tra_outside_save(token text, response jsonb, submit boolean default false)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  target public.threat_assessments := private.tra_link_target(token);
  hash text := encode(sha256(convert_to(token, 'UTF8')), 'hex');
  kept jsonb;
  saved public.threat_assessment_responses;
begin
  if jsonb_typeof(response) is distinct from 'object' then raise exception 'Invalid response'; end if;
  if response ? 'answers' and not private.valid_control_answers(response -> 'answers') then raise exception 'Some answers are not in the expected form.'; end if;
  if response ? 'impact' and not private.valid_impact(response -> 'impact') then raise exception 'Some impact ratings are not in the expected form.'; end if;
  if response ? 'profile' and jsonb_typeof(response -> 'profile') is distinct from 'object' then raise exception 'The profile is not in the expected form.'; end if;
  kept := jsonb_strip_nulls(jsonb_build_object(
    'contributor', case when jsonb_typeof(response -> 'contributor') = 'object' then jsonb_strip_nulls(jsonb_build_object(
        'name', left(response #>> '{contributor,name}', 200), 'email', left(response #>> '{contributor,email}', 254))) end,
    'description', case when jsonb_typeof(response -> 'description') = 'string' then to_jsonb(left(response #>> '{description}', 5000)) end,
    'department', case when jsonb_typeof(response -> 'department') = 'string' then to_jsonb(left(response #>> '{department}', 500)) end,
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

create or replace function public.assessment_intake_save(token text, response jsonb, submit boolean default false)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  target public.assessments := private.assessment_intake_target(token);
  hash text := encode(sha256(convert_to(token, 'UTF8')), 'hex');
  kept jsonb;
  saved public.assessment_intake_responses;
begin
  if jsonb_typeof(response) is distinct from 'object' then raise exception 'Invalid response'; end if;
  if response ? 'answers' and not private.valid_intake_answers(response -> 'answers') then raise exception 'Some answers are not in the expected form.'; end if;
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

