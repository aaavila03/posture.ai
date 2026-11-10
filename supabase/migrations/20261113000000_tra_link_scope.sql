-- A link's form lists the same controls as the assessment it came from. The controls follow
-- from step 1's choices (asset types, sign-in methods and the Yes/No questions), so the link
-- now always returns those as its starting point. Descriptions, free-text details, control
-- answers and evidence are still returned only if the analyst chose to share them.
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
